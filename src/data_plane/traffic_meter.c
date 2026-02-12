/*
 * traffic_meter -- XDP data plane
 *
 * For each incoming packet, parse the IP header (v4 or v6), look up the
 * source and destination addresses in the corresponding LPM rule map.
 * If a match is found, increment the per-CPU statistics (packets, bytes)
 * for that rule.  Always return XDP_PASS so the packet continues to the
 * normal networking stack.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "traffic_meter_common.h"

/* ------------------------------------------------------------------ */
/*  BPF Maps                                                           */
/* ------------------------------------------------------------------ */

/*
 * IPv4 rule map -- LPM trie.
 * Key:   struct lpm_v4_key { prefixlen, addr[4] }
 * Value: __u32 -- the rule's prefix length (so XDP can reconstruct
 *        the rule key for the stats map after an LPM lookup).
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v4_key);
    __type(value, __u32);
    __uint(max_entries, MAX_RULES_V4);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} rules_v4 SEC(".maps");

/*
 * IPv6 rule map -- LPM trie.
 * Value: __u32 -- the rule's prefix length.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v6_key);
    __type(value, __u32);
    __uint(max_entries, MAX_RULES_V6);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} rules_v6 SEC(".maps");

/*
 * IPv4 per-CPU statistics map.
 * Key:   struct lpm_v4_key -- the *rule* key (prefixlen + network addr),
 *        NOT the host key.  Userspace pre-creates entries in do_add;
 *        XDP updates existing entries in-place.
 * Value: struct traffic_stats { packets, bytes }
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct lpm_v4_key);
    __type(value, struct traffic_stats);
    __uint(max_entries, MAX_RULES_V4);
} stats_v4 SEC(".maps");

/*
 * IPv6 per-CPU statistics map.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct lpm_v6_key);
    __type(value, struct traffic_stats);
    __uint(max_entries, MAX_RULES_V6);
} stats_v6 SEC(".maps");
 
/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

/*
 * Build the rule-level stats key from a host address and the matched
 * rule's prefix length.  We copy the host address, set the prefixlen,
 * and zero out host bits beyond the prefix so the key matches what
 * userspace stored in the stats map via do_add.
 *
 * IMPORTANT: We must only use constant array indices (the unrolled loop
 * variable `i`) for addr[] accesses.  Using a variable index like
 * addr[prefix/8] causes a "variable-offset stack read" that the BPF
 * verifier rejects.
 */
static __always_inline void
build_rule_key_v4(struct lpm_v4_key *rule_key,
                  const __u8 *host_addr, __u32 prefix)
{
    rule_key->prefixlen = prefix;
    __builtin_memcpy(rule_key->addr, host_addr, 4);

    /*
     * For each byte position (constant index i after unroll):
     *  - If prefix covers the entire byte: keep as-is.
     *  - If prefix falls within this byte: mask the low bits.
     *  - If prefix is before this byte: zero it.
     *
     * byte_bit_start = i * 8 is the first bit of byte i.
     */
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        __u32 bstart = (__u32)i * 8;
        if (prefix <= bstart) {
            rule_key->addr[i] = 0;
        } else if (prefix < bstart + 8) {
            rule_key->addr[i] &= (__u8)(0xFF << (8 - (prefix - bstart)));
        }
    }
}

static __always_inline void
build_rule_key_v6(struct lpm_v6_key *rule_key,
                  const __u8 *host_addr, __u32 prefix)
{
    rule_key->prefixlen = prefix;
    __builtin_memcpy(rule_key->addr, host_addr, 16);

    #pragma unroll
    for (int i = 0; i < 16; i++) {
        __u32 bstart = (__u32)i * 8;
        if (prefix <= bstart) {
            rule_key->addr[i] = 0;
        } else if (prefix < bstart + 8) {
            rule_key->addr[i] &= (__u8)(0xFF << (8 - (prefix - bstart)));
        }
    }
}

/*
 * Update per-CPU stats for a matched rule.
 * The stats entry is pre-created by userspace (do_add), so we only
 * need lookup + update, never insert.
 */
static __always_inline void
account_v4(struct lpm_v4_key *rule_key, __u64 pkt_len)
{
    struct traffic_stats *st;

    st = bpf_map_lookup_elem(&stats_v4, rule_key);
    if (st) {
        st->packets += 1;
        st->bytes   += pkt_len;
    }
    /* If entry missing (shouldn't happen), silently skip. */
}

static __always_inline void
account_v6(struct lpm_v6_key *rule_key, __u64 pkt_len)
{
    struct traffic_stats *st;

    st = bpf_map_lookup_elem(&stats_v6, rule_key);
    if (st) {
        st->packets += 1;
        st->bytes   += pkt_len;
    }
}

 /* ------------------------------------------------------------------ */
 /*  IPv4 processing                                                    */
 /* ------------------------------------------------------------------ */
 
static __always_inline int
process_ipv4(void *data, void *data_end, __u64 pkt_len)
{
    struct iphdr *iph = data + sizeof(struct ethhdr);

    /* bounds check: ethernet + minimum IPv4 header */
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    /* Build LPM lookup key with prefixlen=32 (exact host) */
    struct lpm_v4_key lookup = { .prefixlen = 32 };
    struct lpm_v4_key rule_key;
    __u32 *matched_prefix;

    /* Source IP lookup */
    __builtin_memcpy(lookup.addr, &iph->saddr, 4);
    matched_prefix = bpf_map_lookup_elem(&rules_v4, &lookup);
    if (matched_prefix) {
        build_rule_key_v4(&rule_key, lookup.addr, *matched_prefix);
        account_v4(&rule_key, pkt_len);
    }

    /* Destination IP lookup */
    __builtin_memcpy(lookup.addr, &iph->daddr, 4);
    matched_prefix = bpf_map_lookup_elem(&rules_v4, &lookup);
    if (matched_prefix) {
        build_rule_key_v4(&rule_key, lookup.addr, *matched_prefix);
        account_v4(&rule_key, pkt_len);
    }

    return XDP_PASS;
}
 
/* ------------------------------------------------------------------ */
/*  IPv6 processing                                                    */
/* ------------------------------------------------------------------ */

static __always_inline int
process_ipv6(void *data, void *data_end, __u64 pkt_len)
{
    struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);

    /* bounds check: ethernet + IPv6 header */
    if ((void *)(ip6h + 1) > data_end)
        return XDP_PASS;

    struct lpm_v6_key lookup = { .prefixlen = 128 };
    struct lpm_v6_key rule_key;
    __u32 *matched_prefix;

    /* Source IP lookup */
    __builtin_memcpy(lookup.addr, &ip6h->saddr, 16);
    matched_prefix = bpf_map_lookup_elem(&rules_v6, &lookup);
    if (matched_prefix) {
        build_rule_key_v6(&rule_key, lookup.addr, *matched_prefix);
        account_v6(&rule_key, pkt_len);
    }

    /* Destination IP lookup */
    __builtin_memcpy(lookup.addr, &ip6h->daddr, 16);
    matched_prefix = bpf_map_lookup_elem(&rules_v6, &lookup);
    if (matched_prefix) {
        build_rule_key_v6(&rule_key, lookup.addr, *matched_prefix);
        account_v6(&rule_key, pkt_len);
    }

    return XDP_PASS;
}

/* ------------------------------------------------------------------ */
/*  XDP entry point                                                    */
/* ------------------------------------------------------------------ */

SEC("xdp")
int traffic_meter_xdp(struct xdp_md *ctx)
{
    void *data     = (void *)(unsigned long)ctx->data;
    void *data_end = (void *)(unsigned long)ctx->data_end;
    __u64 pkt_len  = (__u64)(data_end - data);

    /* Need at least an Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);

    /* Handle VLAN tagged frames (single tag only) */
    if (eth_proto == ETH_P_8021Q || eth_proto == ETH_P_8021AD) {
        struct vlan_hdr {
            __u16 h_vlan_TCI;
            __u16 h_vlan_encapsulated_proto;
        } *vhdr = (void *)(eth + 1);

        if ((void *)(vhdr + 1) > data_end)
            return XDP_PASS;

        eth_proto = bpf_ntohs(vhdr->h_vlan_encapsulated_proto);
    }

    switch (eth_proto) {
    case ETH_P_IP:
        return process_ipv4(data, data_end, pkt_len);
    case ETH_P_IPV6:
        return process_ipv6(data, data_end, pkt_len);
    default:
        return XDP_PASS;
    }
}

char _license[] SEC("license") = "GPL";
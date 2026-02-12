/*
 * traffic_meter -- XDP data plane
 *
 * For each incoming packet:
 *   1. Parse IP header, extract src/dst IP and L4 ports.
 *   2. Query the flow table (flow_table.h) to determine whether this
 *      packet is in the "original" or "reply" direction of its flow.
 *   3. Look up src and dst IP in the LPM rules map.  For each matched
 *      rule, reconstruct the rule-level stats key and update the
 *      per-CPU statistics:
 *        original direction → tx (traffic FROM this address/prefix)
 *        reply    direction → rx (traffic TO   this address/prefix)
 *   4. Return XDP_PASS so the packet continues to the normal stack.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "traffic_meter_common.h"
#include "flow_table.h"

/* ------------------------------------------------------------------ */
/*  BPF Maps -- rules & statistics                                     */
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
 * Key:   struct lpm_v4_key (rule key: prefixlen + network addr)
 * Value: struct traffic_stats { rx_packets, rx_bytes, tx_packets, tx_bytes }
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
/*  Helpers: rule key reconstruction                                   */
/* ------------------------------------------------------------------ */

/*
 * Build the rule-level stats key from a host address and the matched
 * rule's prefix length.  Uses constant indices only (pragma unroll)
 * to satisfy the BPF verifier.
 */
static __always_inline void
build_rule_key_v4(struct lpm_v4_key *rule_key,
                  const __u8 *host_addr, __u32 prefix)
{
    rule_key->prefixlen = prefix;
    __builtin_memcpy(rule_key->addr, host_addr, 4);

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

/* ------------------------------------------------------------------ */
/*  Helpers: per-rule accounting with direction                        */
/* ------------------------------------------------------------------ */

static __always_inline void
account_v4(struct lpm_v4_key *rule_key, __u64 pkt_len, int direction)
{
    struct traffic_stats *st = bpf_map_lookup_elem(&stats_v4, rule_key);
    if (!st)
        return;

    if (direction == DIR_ORIGINAL) {
        st->tx_packets += 1;
        st->tx_bytes   += pkt_len;
    } else {
        st->rx_packets += 1;
        st->rx_bytes   += pkt_len;
    }
}

static __always_inline void
account_v6(struct lpm_v6_key *rule_key, __u64 pkt_len, int direction)
{
    struct traffic_stats *st = bpf_map_lookup_elem(&stats_v6, rule_key);
    if (!st)
        return;

    if (direction == DIR_ORIGINAL) {
        st->tx_packets += 1;
        st->tx_bytes   += pkt_len;
    } else {
        st->rx_packets += 1;
        st->rx_bytes   += pkt_len;
    }
}

/* ------------------------------------------------------------------ */
/*  Helpers: extract L4 ports for flow key construction                */
/* ------------------------------------------------------------------ */

/*
 * Extract L4 identifiers for flow key construction.
 *
 *   TCP / UDP : source and destination ports (5-tuple flow key).
 *   ICMP echo : ICMP ID field (shared between request and reply)
 *               placed into sport; dport stays 0.
 *   Other     : ports stay 0 (flow keyed by IP 2-tuple + protocol).
 */
static __always_inline void
extract_ports_v4(void *data, void *data_end,
                 struct iphdr *iph,
                 __u16 *sport, __u16 *dport)
{
    __u8 proto = iph->protocol;
    __u32 ihl = (__u32)iph->ihl * 4;
    void *l4 = (void *)iph + ihl;

    *sport = 0;
    *dport = 0;

    switch (proto) {
    case IPPROTO_TCP: {
        struct tcphdr *th = l4;
        if ((void *)(th + 1) <= data_end) {
            *sport = th->source;
            *dport = th->dest;
        }
        break;
    }
    case IPPROTO_UDP: {
        struct udphdr *uh = l4;
        if ((void *)(uh + 1) <= data_end) {
            *sport = uh->source;
            *dport = uh->dest;
        }
        break;
    }
    case IPPROTO_ICMP: {
        struct icmphdr *ih = l4;
        if ((void *)(ih + 1) <= data_end) {
            __u8 type = ih->type;
            if (type == ICMP_ECHO || type == ICMP_ECHOREPLY)
                *sport = ih->un.echo.id;
            /* non-echo ICMP: ports stay 0 */
        }
        break;
    }
    default:
        break;
    }
}

static __always_inline void
extract_ports_v6(void *data, void *data_end,
                 struct ipv6hdr *ip6h,
                 __u16 *sport, __u16 *dport)
{
    __u8 proto = ip6h->nexthdr;
    void *l4 = (void *)(ip6h + 1);

    *sport = 0;
    *dport = 0;

    switch (proto) {
    case IPPROTO_TCP: {
        struct tcphdr *th = l4;
        if ((void *)(th + 1) <= data_end) {
            *sport = th->source;
            *dport = th->dest;
        }
        break;
    }
    case IPPROTO_UDP: {
        struct udphdr *uh = l4;
        if ((void *)(uh + 1) <= data_end) {
            *sport = uh->source;
            *dport = uh->dest;
        }
        break;
    }
    case IPPROTO_ICMPV6: {
        struct icmp6hdr *ih6 = l4;
        if ((void *)(ih6 + 1) <= data_end) {
            __u8 type = ih6->icmp6_type;
            if (type == ICMPV6_ECHO_REQUEST ||
                type == ICMPV6_ECHO_REPLY)
                *sport = ih6->icmp6_dataun.u_echo.identifier;
            /* non-echo ICMPv6: ports stay 0 */
        }
        break;
    }
    default:
        break;
    }
}

/* ------------------------------------------------------------------ */
/*  Helpers: TCP SYN detection                                         */
/* ------------------------------------------------------------------ */

/*
 * Check whether a TCP packet carries the SYN flag (SYN or SYN-ACK).
 * These indicate a new or restarted connection and should trigger a
 * flow table overwrite so orig_src tracks the current initiator.
 *
 * @l4:       pointer to the start of the TCP header
 * @data_end: packet boundary for bounds checking
 *
 * Returns 1 if SYN is set, 0 otherwise (including non-parseable).
 */
static __always_inline int
is_tcp_syn(void *l4, void *data_end)
{
    struct tcphdr *th = l4;
    if ((void *)(th + 1) > data_end)
        return 0;
    return th->syn;
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

    __u32 src_ip = iph->saddr;
    __u32 dst_ip = iph->daddr;

    /* Extract L4 ports (TCP/UDP) or ICMP ID */
    __u16 sport, dport;
    extract_ports_v4(data, data_end, iph, &sport, &dport);

    /* TCP SYN / SYN-ACK → force flow table overwrite */
    int force_new = 0;
    if (iph->protocol == IPPROTO_TCP)
        force_new = is_tcp_syn((void *)iph + (__u32)iph->ihl * 4, data_end);

    /* Determine flow direction via flow table */
    int direction = flow_lookup_v4(src_ip, dst_ip,
                                   sport, dport, iph->protocol,
                                   force_new);

    /* Build LPM lookup key with prefixlen=32 (exact host) */
    struct lpm_v4_key lookup = { .prefixlen = 32 };
    struct lpm_v4_key rule_key;
    __u32 *matched_prefix;

    /* Source IP lookup */
    __builtin_memcpy(lookup.addr, &src_ip, 4);
    matched_prefix = bpf_map_lookup_elem(&rules_v4, &lookup);
    if (matched_prefix) {
        build_rule_key_v4(&rule_key, lookup.addr, *matched_prefix);
        account_v4(&rule_key, pkt_len, direction);
    }

    /* Destination IP lookup */
    __builtin_memcpy(lookup.addr, &dst_ip, 4);
    matched_prefix = bpf_map_lookup_elem(&rules_v4, &lookup);
    if (matched_prefix) {
        build_rule_key_v4(&rule_key, lookup.addr, *matched_prefix);
        account_v4(&rule_key, pkt_len, direction);
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

    /* Extract L4 ports */
    __u16 sport, dport;
    extract_ports_v6(data, data_end, ip6h, &sport, &dport);

    /* TCP SYN / SYN-ACK → force flow table overwrite */
    int force_new = 0;
    if (ip6h->nexthdr == IPPROTO_TCP)
        force_new = is_tcp_syn((void *)(ip6h + 1), data_end);

    /* Determine flow direction via flow table */
    int direction = flow_lookup_v6((__u8 *)&ip6h->saddr,
                                   (__u8 *)&ip6h->daddr,
                                   sport, dport, ip6h->nexthdr,
                                   force_new);

    struct lpm_v6_key lookup = { .prefixlen = 128 };
    struct lpm_v6_key rule_key;
    __u32 *matched_prefix;

    /* Source IP lookup */
    __builtin_memcpy(lookup.addr, &ip6h->saddr, 16);
    matched_prefix = bpf_map_lookup_elem(&rules_v6, &lookup);
    if (matched_prefix) {
        build_rule_key_v6(&rule_key, lookup.addr, *matched_prefix);
        account_v6(&rule_key, pkt_len, direction);
    }

    /* Destination IP lookup */
    __builtin_memcpy(lookup.addr, &ip6h->daddr, 16);
    matched_prefix = bpf_map_lookup_elem(&rules_v6, &lookup);
    if (matched_prefix) {
        build_rule_key_v6(&rule_key, lookup.addr, *matched_prefix);
        account_v6(&rule_key, pkt_len, direction);
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

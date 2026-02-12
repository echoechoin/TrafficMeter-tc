/*
 * traffic_meter -- TC BPF data plane (ingress + egress)
 *
 * Attached to both the ingress and egress paths of a network interface
 * via the clsact qdisc, so it sees packets in both directions.
 *
 * For each packet:
 *   1. Parse IP header, extract src/dst IP and L4 ports.
 *   2. Query the flow table (flow_table.h) to determine whether this
 *      packet is in the "original" or "reply" direction of its flow.
 *   3. Look up src and dst IP in the LPM rules map.  For each matched
 *      rule, update per-CPU byte statistics:
 *        original direction → tx_bytes
 *        reply    direction → rx_bytes
 *   4. Return TC_ACT_OK so the packet continues normally.
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
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

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v4_key);
    __type(value, __u32);
    __uint(max_entries, MAX_RULES_V4);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} rules_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_v6_key);
    __type(value, __u32);
    __uint(max_entries, MAX_RULES_V6);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} rules_v6 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct lpm_v4_key);
    __type(value, struct traffic_stats);
    __uint(max_entries, MAX_RULES_V4);
} stats_v4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct lpm_v6_key);
    __type(value, struct traffic_stats);
    __uint(max_entries, MAX_RULES_V6);
} stats_v6 SEC(".maps");

/* ------------------------------------------------------------------ */
/*  Helpers: rule key reconstruction                                   */
/* ------------------------------------------------------------------ */

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
/*  Helpers: per-rule accounting with direction (bytes only)            */
/* ------------------------------------------------------------------ */

static __always_inline void
account_v4(struct lpm_v4_key *rule_key, __u64 pkt_len, int direction)
{
    struct traffic_stats *st = bpf_map_lookup_elem(&stats_v4, rule_key);
    if (!st)
        return;

    if (direction == DIR_ORIGINAL)
        st->tx_bytes += pkt_len;
    else
        st->rx_bytes += pkt_len;
}

static __always_inline void
account_v6(struct lpm_v6_key *rule_key, __u64 pkt_len, int direction)
{
    struct traffic_stats *st = bpf_map_lookup_elem(&stats_v6, rule_key);
    if (!st)
        return;

    if (direction == DIR_ORIGINAL)
        st->tx_bytes += pkt_len;
    else
        st->rx_bytes += pkt_len;
}

/* ------------------------------------------------------------------ */
/*  Helpers: extract L4 ports for flow key construction                */
/* ------------------------------------------------------------------ */

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

    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    __u32 src_ip = iph->saddr;
    __u32 dst_ip = iph->daddr;

    __u16 sport, dport;
    extract_ports_v4(data, data_end, iph, &sport, &dport);

    /* TCP SYN / SYN-ACK → force flow table overwrite */
    int force_new = 0;
    if (iph->protocol == IPPROTO_TCP)
        force_new = is_tcp_syn((void *)iph + (__u32)iph->ihl * 4, data_end);

    int direction = flow_lookup_v4(src_ip, dst_ip,
                                   sport, dport, iph->protocol,
                                   force_new);

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

    return TC_ACT_OK;
}

/* ------------------------------------------------------------------ */
/*  IPv6 processing                                                    */
/* ------------------------------------------------------------------ */

static __always_inline int
process_ipv6(void *data, void *data_end, __u64 pkt_len)
{
    struct ipv6hdr *ip6h = data + sizeof(struct ethhdr);

    if ((void *)(ip6h + 1) > data_end)
        return TC_ACT_OK;

    __u16 sport, dport;
    extract_ports_v6(data, data_end, ip6h, &sport, &dport);

    int force_new = 0;
    if (ip6h->nexthdr == IPPROTO_TCP)
        force_new = is_tcp_syn((void *)(ip6h + 1), data_end);

    int direction = flow_lookup_v6((__u8 *)&ip6h->saddr,
                                   (__u8 *)&ip6h->daddr,
                                   sport, dport, ip6h->nexthdr,
                                   force_new);

    struct lpm_v6_key lookup = { .prefixlen = 128 };
    struct lpm_v6_key rule_key;
    __u32 *matched_prefix;

    __builtin_memcpy(lookup.addr, &ip6h->saddr, 16);
    matched_prefix = bpf_map_lookup_elem(&rules_v6, &lookup);
    if (matched_prefix) {
        build_rule_key_v6(&rule_key, lookup.addr, *matched_prefix);
        account_v6(&rule_key, pkt_len, direction);
    }

    __builtin_memcpy(lookup.addr, &ip6h->daddr, 16);
    matched_prefix = bpf_map_lookup_elem(&rules_v6, &lookup);
    if (matched_prefix) {
        build_rule_key_v6(&rule_key, lookup.addr, *matched_prefix);
        account_v6(&rule_key, pkt_len, direction);
    }

    return TC_ACT_OK;
}

/* ------------------------------------------------------------------ */
/*  Shared packet processing logic                                     */
/* ------------------------------------------------------------------ */

static __always_inline int
traffic_meter_process(struct __sk_buff *skb)
{
    void *data     = (void *)(unsigned long)skb->data;
    void *data_end = (void *)(unsigned long)skb->data_end;
    __u64 pkt_len  = (__u64)skb->len;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    __u16 eth_proto = bpf_ntohs(eth->h_proto);

    /* Handle VLAN tagged frames (single tag only) */
    if (eth_proto == ETH_P_8021Q || eth_proto == ETH_P_8021AD) {
        struct vlan_hdr {
            __u16 h_vlan_TCI;
            __u16 h_vlan_encapsulated_proto;
        } *vhdr = (void *)(eth + 1);

        if ((void *)(vhdr + 1) > data_end)
            return TC_ACT_OK;

        eth_proto = bpf_ntohs(vhdr->h_vlan_encapsulated_proto);
    }

    switch (eth_proto) {
    case ETH_P_IP:
        return process_ipv4(data, data_end, pkt_len);
    case ETH_P_IPV6:
        return process_ipv6(data, data_end, pkt_len);
    default:
        return TC_ACT_OK;
    }
}

/* ------------------------------------------------------------------ */
/*  TC BPF entry points                                                */
/* ------------------------------------------------------------------ */

SEC("tc")
int traffic_meter_ingress(struct __sk_buff *skb)
{
    return traffic_meter_process(skb);
}

SEC("tc")
int traffic_meter_egress(struct __sk_buff *skb)
{
    /*
     * Skip bridge-forwarded packets to avoid double counting.
     * If ingress_ifindex is set and differs from the current ifindex,
     * this packet entered from another interface and is being forwarded
     * through a bridge -- it was already counted on the ingress side.
     */
    if (skb->ingress_ifindex != 0 &&
        skb->ingress_ifindex != skb->ifindex)
        return TC_ACT_OK;

    return traffic_meter_process(skb);
}

char _license[] SEC("license") = "GPL";

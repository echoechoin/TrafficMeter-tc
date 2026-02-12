/*
 * flow_table.h -- BPF flow table for direction detection
 *
 * Maintains an LRU hash map of active flows (IPv4 and IPv6).
 * The first packet of each flow is recorded as the "original" direction;
 * subsequent packets are classified as original or reply by comparing
 * the current source IP against the stored orig_src.
 *
 * Flow keys are *normalized*: ip_lo <= ip_hi, ports follow their IPs.
 * This ensures both directions of the same flow map to the same entry.
 *
 * Protocol-specific key construction:
 *   TCP / UDP : 5-tuple (ip_lo, ip_hi, port_lo, port_hi, protocol)
 *   ICMP / other : 2-tuple + protocol (ip_lo, ip_hi, 0, 0, protocol)
 *
 * This file is included by the main BPF .c file.  All functions are
 * static __always_inline so the BPF verifier can trace them.
 */

#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "traffic_meter_common.h"

/* ------------------------------------------------------------------ */
/*  Direction constants                                                */
/* ------------------------------------------------------------------ */

#define DIR_ORIGINAL 0
#define DIR_REPLY    1

/* ------------------------------------------------------------------ */
/*  BPF Maps -- flow tables                                            */
/* ------------------------------------------------------------------ */

/*
 * IPv4 flow table -- LRU hash, auto-evicts least recently used entries.
 * Key:   struct flow_key_v4 (normalized 5-tuple / 2-tuple)
 * Value: struct flow_info_v4 { orig_src }
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key_v4);
    __type(value, struct flow_info_v4);
    __uint(max_entries, MAX_FLOWS_V4);
} flow_table_v4 SEC(".maps");

/*
 * IPv6 flow table -- LRU hash.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key_v6);
    __type(value, struct flow_info_v6);
    __uint(max_entries, MAX_FLOWS_V6);
} flow_table_v6 SEC(".maps");

/* ------------------------------------------------------------------ */
/*  IPv6 address comparison helpers                                    */
/* ------------------------------------------------------------------ */

/*
 * Compare two 16-byte IPv6 addresses (memcmp-style).
 * Returns <0, 0, or >0.
 */
static __always_inline int
cmp_ipv6(const __u8 *a, const __u8 *b)
{
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if (a[i] < b[i])
            return -1;
        if (a[i] > b[i])
            return 1;
    }
    return 0;
}

static __always_inline int
ipv6_eq(const __u8 *a, const __u8 *b)
{
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if (a[i] != b[i])
            return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/*  IPv4 flow lookup                                                   */
/* ------------------------------------------------------------------ */

/*
 * Build a normalized IPv4 flow key, look it up in the flow table,
 * and return the direction of the current packet.
 *
 * Normalization: ip_lo <= ip_hi (unsigned compare of network-order
 * 32-bit values).  Ports follow their respective IPs.
 *
 * @force_new: if true (TCP SYN / SYN-ACK detected), force-overwrite
 *             the flow entry with the current src_ip as orig_src.
 *             This handles TCP reconnection on the same 5-tuple.
 *
 * Returns DIR_ORIGINAL (first packet or same direction) or DIR_REPLY.
 */
static __always_inline int
flow_lookup_v4(__u32 src_ip, __u32 dst_ip,
               __u16 sport, __u16 dport, __u8 protocol,
               int force_new)
{
    struct flow_key_v4 fkey = {};

    /*
     * Normalize: compare IPs as unsigned 32-bit in network byte order.
     * The comparison only needs a consistent ordering so both
     * directions of the same flow hash to the same key.
     */
    if (src_ip <= dst_ip) {
        fkey.ip_lo   = src_ip;
        fkey.ip_hi   = dst_ip;
        fkey.port_lo = sport;
        fkey.port_hi = dport;
    } else {
        fkey.ip_lo   = dst_ip;
        fkey.ip_hi   = src_ip;
        fkey.port_lo = dport;
        fkey.port_hi = sport;
    }
    fkey.protocol = protocol;

    /*
     * If this is a TCP SYN or SYN-ACK, the connection is being
     * (re-)established.  Force-overwrite the flow entry so that
     * orig_src reflects the new initiator.
     */
    if (force_new) {
        struct flow_info_v4 new_fi = { .orig_src = src_ip };
        bpf_map_update_elem(&flow_table_v4, &fkey, &new_fi, BPF_ANY);
        return DIR_ORIGINAL;
    }

    /* Lookup existing flow entry */
    struct flow_info_v4 *fi = bpf_map_lookup_elem(&flow_table_v4, &fkey);
    if (fi)
        return (src_ip == fi->orig_src) ? DIR_ORIGINAL : DIR_REPLY;

    /* First packet of this flow -- insert with BPF_NOEXIST */
    struct flow_info_v4 new_fi = { .orig_src = src_ip };
    int ret = bpf_map_update_elem(&flow_table_v4, &fkey, &new_fi, BPF_NOEXIST);
    if (ret == 0)
        return DIR_ORIGINAL;

    /*
     * BPF_NOEXIST failed (-EEXIST): another CPU beat us.
     * Re-lookup to get the winner's entry.
     */
    fi = bpf_map_lookup_elem(&flow_table_v4, &fkey);
    if (fi)
        return (src_ip == fi->orig_src) ? DIR_ORIGINAL : DIR_REPLY;

    /* Shouldn't happen; default to original */
    return DIR_ORIGINAL;
}

/* ------------------------------------------------------------------ */
/*  IPv6 flow lookup                                                   */
/* ------------------------------------------------------------------ */

static __always_inline int
flow_lookup_v6(const __u8 *src_ip, const __u8 *dst_ip,
               __u16 sport, __u16 dport, __u8 protocol,
               int force_new)
{
    struct flow_key_v6 fkey = {};
    int cmp = cmp_ipv6(src_ip, dst_ip);

    if (cmp <= 0) {
        __builtin_memcpy(fkey.ip_lo, src_ip, 16);
        __builtin_memcpy(fkey.ip_hi, dst_ip, 16);
        fkey.port_lo = sport;
        fkey.port_hi = dport;
    } else {
        __builtin_memcpy(fkey.ip_lo, dst_ip, 16);
        __builtin_memcpy(fkey.ip_hi, src_ip, 16);
        fkey.port_lo = dport;
        fkey.port_hi = sport;
    }
    fkey.protocol = protocol;

    /* TCP SYN / SYN-ACK: force-overwrite */
    if (force_new) {
        struct flow_info_v6 new_fi = {};
        __builtin_memcpy(new_fi.orig_src, src_ip, 16);
        bpf_map_update_elem(&flow_table_v6, &fkey, &new_fi, BPF_ANY);
        return DIR_ORIGINAL;
    }

    /* Lookup existing flow entry */
    struct flow_info_v6 *fi = bpf_map_lookup_elem(&flow_table_v6, &fkey);
    if (fi)
        return ipv6_eq(src_ip, fi->orig_src) ? DIR_ORIGINAL : DIR_REPLY;

    /* First packet -- insert */
    struct flow_info_v6 new_fi = {};
    __builtin_memcpy(new_fi.orig_src, src_ip, 16);

    int ret = bpf_map_update_elem(&flow_table_v6, &fkey, &new_fi, BPF_NOEXIST);
    if (ret == 0)
        return DIR_ORIGINAL;

    /* Race: re-lookup */
    fi = bpf_map_lookup_elem(&flow_table_v6, &fkey);
    if (fi)
        return ipv6_eq(src_ip, fi->orig_src) ? DIR_ORIGINAL : DIR_REPLY;

    return DIR_ORIGINAL;
}

#endif /* FLOW_TABLE_H */

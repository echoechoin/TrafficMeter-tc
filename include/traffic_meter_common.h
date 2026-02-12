/*
 * traffic_meter_common.h -- data structures shared between
 * kernel BPF data plane and userspace control plane.
 *
 * This header is included by both BPF (clang) and userspace (gcc/clang)
 * code, so it must be self-contained and use only fixed-width types.
 */
#ifndef TRAFFIC_METER_COMMON_H
#define TRAFFIC_METER_COMMON_H

/*
 * Pull fixed-width kernel types (__u8, __u32, __u64).
 * <linux/types.h> works in both BPF and userspace contexts and avoids
 * typedef conflicts when userspace also includes kernel headers.
 */
#include <linux/types.h>

/* ------------------------------------------------------------------ */
/*  LPM trie keys for rule maps                                        */
/* ------------------------------------------------------------------ */

/*
 * IPv4 LPM key: prefixlen (0-32) + 4 bytes address.
 * Used as key for rules_v4 map.
 */
struct lpm_v4_key {
	__u32	prefixlen;
	__u8	addr[4];
};

/*
 * IPv6 LPM key: prefixlen (0-128) + 16 bytes address.
 * Used as key for rules_v6 map.
 */
struct lpm_v6_key {
	__u32	prefixlen;
	__u8	addr[16];
};

/* ------------------------------------------------------------------ */
/*  Flow table keys and values                                         */
/* ------------------------------------------------------------------ */

/*
 * IPv4 flow key -- normalized so both directions of the same flow
 * hash to the same entry.  ip_lo <= ip_hi; ports follow their IP.
 *
 * TCP/UDP: 5-tuple  (ip_lo, ip_hi, port_lo, port_hi, protocol)
 * ICMP:    2-tuple  (ip_lo, ip_hi, id, 0, IPPROTO_ICMP)
 * Other:   2-tuple  (ip_lo, ip_hi, 0, 0, protocol)
 */
struct flow_key_v4 {
	__u32	ip_lo;		/* min(src_ip, dst_ip) in network order */
	__u32	ip_hi;		/* max(src_ip, dst_ip) in network order */
	__u16	port_lo;	/* port associated with ip_lo */
	__u16	port_hi;	/* port associated with ip_hi */
	__u8	protocol;	/* L4 protocol number */
	__u8	pad[3];
};

/*
 * IPv6 flow key -- same normalization logic, larger addresses.
 */
struct flow_key_v6 {
	__u8	ip_lo[16];
	__u8	ip_hi[16];
	__u16	port_lo;
	__u16	port_hi;
	__u8	protocol;
	__u8	pad[3];
};

/*
 * Flow info -- stored in the flow table (LRU hash map).
 * Records the source IP of the first packet (the "original" direction).
 */
struct flow_info_v4 {
	__u32	orig_src;	/* src IP of the first packet (net order) */
};

struct flow_info_v6 {
	__u8	orig_src[16];	/* src IPv6 of the first packet */
};

/* ------------------------------------------------------------------ */
/*  Statistics value (per-CPU)                                         */
/* ------------------------------------------------------------------ */

/*
 * Per-rule traffic counters (bytes only, no packet count).
 *
 * Direction is determined by the flow table:
 *   - The first packet of a flow establishes the "original" direction.
 *   - original direction → tx_bytes, reply direction → rx_bytes.
 *
 * In the kernel per-CPU map each CPU has its own copy; userspace sums
 * across all CPUs when querying.
 */
struct traffic_stats {
	__u64	rx_bytes;
	__u64	tx_bytes;
};

/* ------------------------------------------------------------------ */
/*  Map capacity defaults                                              */
/* ------------------------------------------------------------------ */

#define MAX_RULES_V4	10240
#define MAX_RULES_V6	10240
#define MAX_FLOWS_V4	65536
#define MAX_FLOWS_V6	65536

#endif /* TRAFFIC_METER_COMMON_H */

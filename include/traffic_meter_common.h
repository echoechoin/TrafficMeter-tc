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
/*  Statistics value (per-CPU)                                         */
/* ------------------------------------------------------------------ */

/*
 * Per-rule traffic counters.  In the kernel per-CPU map each CPU
 * has its own copy; userspace sums across all CPUs when querying.
 */
struct traffic_stats {
	__u64	packets;
	__u64	bytes;
};

/* ------------------------------------------------------------------ */
/*  Map capacity defaults                                              */
/* ------------------------------------------------------------------ */

#define MAX_RULES_V4	10240
#define MAX_RULES_V6	10240

#endif /* TRAFFIC_METER_COMMON_H */

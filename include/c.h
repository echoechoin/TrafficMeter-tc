/*
 * Fundamental C definitions.
 * Adapted from util-linux (public domain).
 *
 * IMPORTANT: This header must be included FIRST (before any system headers)
 * so that _GNU_SOURCE takes effect for program_invocation_short_name etc.
 */
#ifndef TRAFFIC_METER_C_H
#define TRAFFIC_METER_C_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <err.h>

#ifdef __GNUC__
# define __must_be_array(a) \
	__extension__ (sizeof(struct { int:-!!__builtin_types_compatible_p(__typeof__(a), __typeof__(&a[0])); }))
#else
# define __must_be_array(a) 0
#endif

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + __must_be_array(arr))
#endif

#ifndef PATH_MAX
# define PATH_MAX 4096
#endif

/*
 * Constant strings for usage() functions.
 * Following the util-linux convention.
 */
#define USAGE_HEADER		"\nUsage:\n"
#define USAGE_OPTIONS		"\nOptions:\n"
#define USAGE_COMMANDS		"\nCommands:\n"
#define USAGE_SEPARATOR		"\n"

#define USAGE_HELP_OPTIONS(marg_dsc) \
		"%-" #marg_dsc "s%s\n" \
		"%-" #marg_dsc "s%s\n" \
		, " -h, --help",    "display this help" \
		, " -V, --version", "display version"

#define PROGRAM_VERSION		"0.1.0"

static inline void __attribute__((__noreturn__))
print_version(int eval)
{
	printf("%s version %s\n", program_invocation_short_name, PROGRAM_VERSION);
	exit(eval);
}

/*
 * errtryhelp -- print "Try ... --help" and exit
 */
#define errtryhelp(eval) do { \
	fprintf(stderr, "Try '%s --help' for more information.\n", \
			program_invocation_short_name); \
	exit(eval); \
} while (0)

#endif /* TRAFFIC_METER_C_H */

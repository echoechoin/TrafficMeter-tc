/*
 * Memory allocation wrappers.
 * Adapted from util-linux (public domain).
 */
#ifndef TRAFFIC_METER_XALLOC_H
#define TRAFFIC_METER_XALLOC_H

#include <stdlib.h>
#include <string.h>
#include <err.h>

static inline void *xmalloc(size_t size)
{
	void *ret = malloc(size);
	if (!ret && size)
		err(EXIT_FAILURE, "cannot allocate %zu bytes", size);
	return ret;
}

static inline void *xcalloc(size_t nelems, size_t size)
{
	void *ret = calloc(nelems, size);
	if (!ret && size && nelems)
		err(EXIT_FAILURE, "cannot allocate %zu bytes", nelems * size);
	return ret;
}

static inline void *xrealloc(void *ptr, size_t size)
{
	void *ret = realloc(ptr, size);
	if (!ret && size)
		err(EXIT_FAILURE, "cannot allocate %zu bytes", size);
	return ret;
}

static inline char *xstrdup(const char *str)
{
	char *ret;
	if (!str)
		return NULL;
	ret = strdup(str);
	if (!ret)
		err(EXIT_FAILURE, "cannot duplicate string");
	return ret;
}

#endif /* TRAFFIC_METER_XALLOC_H */

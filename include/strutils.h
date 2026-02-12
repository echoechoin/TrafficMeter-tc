/*
 * String utility functions.
 * Adapted from util-linux (public domain).
 */
#ifndef TRAFFIC_METER_STRUTILS_H
#define TRAFFIC_METER_STRUTILS_H

#include <string.h>
#include <ctype.h>
#include <stdbool.h>

/*
 * Match string beginning.
 */
static inline const char *startswith(const char *s, const char *prefix)
{
	size_t sz = prefix ? strlen(prefix) : 0;

	if (s && sz && strncmp(s, prefix, sz) == 0)
		return s + sz;
	return NULL;
}

/*
 * Case insensitive match string beginning.
 */
static inline const char *startswith_no_case(const char *s, const char *prefix)
{
	size_t sz = prefix ? strlen(prefix) : 0;

	if (s && sz && strncasecmp(s, prefix, sz) == 0)
		return s + sz;
	return NULL;
}

/*
 * Skip leading white space.
 */
static inline const char *skip_space(const char *p)
{
	while (isspace((unsigned char)*p))
		++p;
	return p;
}

/*
 * Removes whitespace from the right-hand side of a string.
 * Returns size of the new string (without \0).
 */
static inline size_t rtrim_whitespace(char *str)
{
	size_t i;

	if (!str)
		return 0;
	i = strlen(str);
	while (i) {
		i--;
		if (!isspace((unsigned char)str[i])) {
			i++;
			break;
		}
	}
	str[i] = '\0';
	return i;
}

/*
 * Removes whitespace from the left-hand side of a string.
 * Returns size of the new string (without \0).
 */
static inline size_t ltrim_whitespace(char *str)
{
	size_t len;
	char *p;

	if (!str)
		return 0;
	for (p = str; *p && isspace((unsigned char)*p); p++)
		;

	len = strlen(p);
	if (p > str)
		memmove(str, p, len + 1);

	return len;
}

/*
 * Safe strncpy that always null-terminates.
 * Caller guarantees n > 0.
 */
static inline int xstrncpy(char *dest, const char *src, size_t n)
{
	size_t len = src ? strlen(src) : 0;

	if (!len)
		return 0;
	if (len >= n)
		len = n - 1;
	memcpy(dest, src, len);
	dest[len] = '\0';
	return (int)len;
}

/*
 * Check if string is empty or NULL.
 */
static inline bool str_is_empty(const char *s)
{
	return !s || !*s;
}

#endif /* TRAFFIC_METER_STRUTILS_H */

/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "str.h"

size_t strlcpy(char *dest, const char *src, size_t size)
{
	size_t ret = strlen(src);

	if (size) {
		size_t len = (ret >= size) ? size - 1 : ret;

		memcpy(dest, src, len);
		dest[len] = '\0';
	}

	return ret;
}

static inline int vslprintf(char *dst, size_t size, const char *fmt, va_list ap)
{
	int ret;

	ret = vsnprintf(dst, size, fmt, ap);
	dst[size - 1] = '\0';

	return ret;
}

int slprintf(char *dst, size_t size, const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vslprintf(dst, size, fmt, ap);
	va_end(ap);

	return ret;
}

int slprintf_nocheck(char *dst, size_t size, const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vslprintf(dst, size, fmt, ap);
	va_end(ap);

	return ret;
}

noinline void *xmemset(void *s, int c, size_t n)
{
	size_t i;
	uint8_t *ptr = s;

	for (i = 0; i < n; ++i)
		ptr[i] = (uint8_t) c;

	return ptr;
}

char *strtrim_right(char *p, char c)
{
	char *end;
	size_t len;

	len = strlen(p);
	while (*p && len) {
		end = p + len - 1;
		if (c == *end)
			*end = 0;
		else
			break;
		len = strlen(p);
	}

	return p;
}

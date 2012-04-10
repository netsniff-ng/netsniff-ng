/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010, 2011, 2012 Daniel Borkmann.
 * Copyright 2009, 2010, 2011, 2012 Emmanuel Roullit.
 * strlcpy, Copyright 1991, 1992  Linus Torvalds.
 * Subject to the GPL, version 2.
 */

#define _BSD_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <stdint.h>

#include "xstring.h"
#include "built_in.h"

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

int slprintf(char *dst, size_t size, const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);

	ret = vsnprintf(dst, size, fmt, ap);
	dst[size - 1] = '\0';

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

char *getuint(char *in, uint32_t *out)
{
	char *pt = in, tmp;
	char *endptr = NULL;

	while (*in && (isdigit(*in) || isxdigit(*in) || *in == 'x'))
		in++;
	if (!*in)
		panic("Syntax error!\n");
	errno = 0;
	tmp = *in;
	*in = 0;
	*out = strtoul(pt, &endptr, 0);
	if ((endptr != NULL && *endptr != '\0') || errno != 0) {
		panic("Syntax error!\n");
	}
	*in = tmp;

	return in;
}

char *strtrim_right(register char *p, register char c)
{
	register char *end;
	register int len;

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

char *strtrim_left(register char *p, register char c)
{
	register int len;

	len = strlen(p);
	while (*p && len--) {
		if (c == *p)
			p++;
		else
			break;
	}

	return p;
}

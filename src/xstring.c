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

#include "xstring.h"

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

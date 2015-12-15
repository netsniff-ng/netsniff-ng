/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "str.h"
#include "die.h"
#include "xmalloc.h"

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

char *argv2str(int startind, int argc, char **argv)
{
	off_t offset = 0;
	char *str = NULL;
	int ret, i;

	for (i = startind; i < argc; ++i) {
		size_t alen = strlen(argv[i]) + 2;
		size_t slen = str ? strlen(str) : 0;

		str = xrealloc(str, slen + alen);
		ret = slprintf(str + offset, strlen(argv[i]) + 2, "%s ", argv[i]);
		if (ret < 0)
			panic("Cannot concatenate string!\n");
		else
			offset += ret;
	}

	return str;
}

char **argv_insert(char **argv, size_t *count, const char *str)
{
	argv = xrealloc(argv, (*count + 2) * sizeof(char *));
	argv[*count] = str ? xstrdup(str) : xstrdup("");
	argv[*count + 1] = NULL;

	*count += 1;
	return argv;
}

void argv_free(char **argv)
{
	char **tmp = argv;

	for (; argv && *argv; argv++)
		free(*argv);

	free(tmp);
}

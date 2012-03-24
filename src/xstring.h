/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010, 2011, 2012 Daniel Borkmann.
 * Copyright 2009, 2010, 2011, 2012 Emmanuel Roullit.
 * Subject to the GPL, version 2.
 */

#ifndef XSTRING_H
#define XSTRING_H

#include <stdint.h>

#include "die.h"
#include "built_in.h"

extern size_t strlcpy(char *dest, const char *src, size_t size);
extern int slprintf(char *dst, size_t size, const char *fmt, ...);
extern noinline void *xmemset(void *s, int c, size_t n);
extern char *getuint(char *in, uint32_t *out);
extern char *strtrim_right(register char *p, register char c);
extern char *strtrim_left(register char *p, register char c);

static inline char *skips(char *p)
{
	return strtrim_left(p, ' ');
}

static inline char *skipt(char *p)
{
	return strtrim_left(p, '\t');
}

static inline char *skipchar(char *in, char c)
{
	if (*in != c)
		panic("Syntax error!\n");
	return ++in;
}

static inline char *skipchar_s(char *in, char c)
{
	in = skips(in);
	if (*in == '\n')
		return in;
	in = skipchar(in, c);
	in = skips(in);
	return in;
}

#endif /* XSTRING_H */

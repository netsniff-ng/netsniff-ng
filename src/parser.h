/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef PARSER_H
#define PARSER_H

#include "die.h"

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

#endif /* PARSER_H */

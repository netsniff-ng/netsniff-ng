/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef STRLCPY_H
#define STRLCPY_H

extern size_t strlcpy(char *dest, const char *src, size_t size);
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

#endif /* STRLCPY_H */

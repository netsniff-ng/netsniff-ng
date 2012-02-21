/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010, 2011, 2012 Daniel Borkmann.
 * Copyright 2009, 2010, 2011, 2012 Emmanuel Roullit.
 * Subject to the GPL, version 2.
 */

#ifndef XSTRING_H
#define XSTRING_H

extern size_t strlcpy(char *dest, const char *src, size_t size);
extern int slprintf(char *dst, size_t size, const char *fmt, ...);

#endif /* XSTRING_H */

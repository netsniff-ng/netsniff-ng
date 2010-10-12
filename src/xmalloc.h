/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef XMALLOC_H
#define XMALLOC_H

extern void *xmalloc(size_t size);
extern void *xzmalloc(size_t size);
extern void *xcalloc(size_t nmemb, size_t size);
extern void *xrealloc(void *ptr, size_t nmemb, size_t size);
extern void xfree(void *ptr);
extern char *xstrdup(const char *str);
extern char *xstrndup(const char *str, size_t size);

#endif /* XMALLOC_H */

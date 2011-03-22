/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef XMALLOC_H
#define XMALLOC_H

extern void muntrace_handler(int signal);
extern void stacktrace(void);

extern void *xmalloc(size_t size);
extern void *xzmalloc(size_t size);
extern void *xmallocz(size_t size);
extern void *xvalloc(size_t size);
extern void *xmalloc_aligned(size_t size, size_t alignment);
extern void *xmemdupz(const void *data, size_t len);
extern void *xcalloc(size_t nmemb, size_t size);
extern void *xrealloc(void *ptr, size_t nmemb, size_t size);
extern void xfree(void *ptr);
extern char *xstrdup(const char *str);
extern char *xstrndup(const char *str, size_t size);
extern int xdup(int fd);

#endif /* XMALLOC_H */

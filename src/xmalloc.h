/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef XMALLOC_H
#define XMALLOC_H

#include <stdlib.h>

#include "built_in.h"
#include "die.h"

extern __hidden void *xmalloc(size_t size);
extern __hidden void *xzmalloc(size_t size);
extern __hidden void *xmallocz(size_t size);
extern __hidden void *xmalloc_aligned(size_t size, size_t alignment);
extern __hidden void *xzmalloc_aligned(size_t size, size_t alignment);
extern __hidden void *xmemdupz(const void *data, size_t len);
extern __hidden void *xrealloc(void *ptr, size_t nmemb, size_t size);
extern __hidden void xfree_func(void *ptr);
extern __hidden char *xstrdup(const char *str);
extern __hidden char *xstrndup(const char *str, size_t size);
extern __hidden int xdup(int fd);

#define xfree(ptr)							\
do {									\
        if (unlikely((ptr) == NULL))					\
                panic("xfree: NULL pointer given as argument\n");	\
        free((ptr));							\
	(ptr) = NULL;							\
} while (0)

#endif /* XMALLOC_H */

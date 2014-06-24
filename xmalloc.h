#ifndef XMALLOC_H
#define XMALLOC_H

#include <stdlib.h>

#include "built_in.h"
#include "die.h"

extern void *xmalloc(size_t size) __hidden;
extern void *xcalloc(size_t nmemb, size_t size) __hidden;
extern void *xzmalloc(size_t size) __hidden;
extern void *xmallocz(size_t size) __hidden;
extern void *xmalloc_aligned(size_t size, size_t alignment) __hidden;
extern void *xzmalloc_aligned(size_t size, size_t alignment) __hidden;
extern void *xmemdupz(const void *data, size_t len) __hidden;
extern void *xrealloc(void *ptr, size_t nmemb, size_t size) __hidden;
extern void xfree_func(void *ptr) __hidden;
extern char *xstrdup(const char *str) __hidden;
extern char *xstrndup(const char *str, size_t size) __hidden;

static inline void __xfree(void *ptr)
{
        if (unlikely((ptr) == NULL))
                panic("xfree: NULL pointer given as argument\n");
        free(ptr);
}

#define xzfree(ptr, size)	\
do {				\
	xmemset(ptr, 0, size);	\
	xfree(ptr);		\
} while (0)

#define xfree(ptr)	\
do {			\
	__xfree(ptr);	\
	(ptr) = NULL;	\
} while (0)

#endif /* XMALLOC_H */

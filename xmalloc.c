/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010, 2011, 2012 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <sys/types.h>

#include "xmalloc.h"
#include "xutils.h"
#include "built_in.h"
#include "die.h"

__hidden void *xmalloc(size_t size)
{
	void *ptr;

	if (unlikely(size == 0))
		panic("xmalloc: zero size\n");

	ptr = malloc(size);
	if (unlikely(ptr == NULL))
		panic("xmalloc: out of memory (allocating %zu bytes)\n",
		      size);

	return ptr;
}

__hidden void *xzmalloc(size_t size)
{
	void *ptr = xmalloc(size);
	memset(ptr, 0, size);
	return ptr;
}

__hidden void *xmalloc_aligned(size_t size, size_t alignment)
{
	int ret;
	void *ptr;

	if (unlikely(size == 0))
		panic("xmalloc_aligned: zero size\n");

	ret = posix_memalign(&ptr, alignment, size);
	if (unlikely(ret != 0))
		panic("xmalloc_aligned: out of memory (allocating %zu "
		      "bytes)\n", size);

	return ptr;
}

__hidden void *xzmalloc_aligned(size_t size, size_t alignment)
{
	void *ptr = xmalloc_aligned(size, alignment);
	memset(ptr, 0, size);
	return ptr;
}

__hidden void *xmallocz(size_t size)
{
	void *ptr;

	if (unlikely(size + 1 < size))
		panic("xmallocz: data too large to fit into virtual "
		      "memory space\n");

	ptr = xmalloc(size + 1);
	((char*) ptr)[size] = 0;

	return ptr;
}

__hidden void *xmemdupz(const void *data, size_t len)
{
	return memcpy(xmallocz(len), data, len);
}

__hidden void *xrealloc(void *ptr, size_t nmemb, size_t size)
{
	void *new_ptr;
	size_t new_size = nmemb * size;

	if (unlikely(new_size == 0))
		panic("xrealloc: zero size\n");
	if (unlikely(((size_t) ~0) / nmemb < size))
		panic("xrealloc: nmemb * size > SIZE_T_MAX\n");

	if (ptr == NULL)
		new_ptr = malloc(new_size);
	else
		new_ptr = realloc(ptr, new_size);

	if (unlikely(new_ptr == NULL))
		panic("xrealloc: out of memory (new_size %zu bytes)\n",
		      new_size);

	return new_ptr;
}

__hidden void xfree_func(void *ptr)
{
	if (unlikely(ptr == NULL))
		panic("xfree: NULL pointer given as argument\n");

	free(ptr);
}

__hidden char *xstrdup(const char *str)
{
	size_t len;
	char *cp;

	len = strlen(str) + 1;
	cp = xmalloc(len);

	strlcpy(cp, str, len);

	return cp;
}

__hidden char *xstrndup(const char *str, size_t size)
{
	size_t len;
	char *cp;

	len = strlen(str) + 1;
	if (size < len)
		len = size;

	cp = xmalloc(len);

	strlcpy(cp, str, len);

	return cp;
}

__hidden int xdup(int fd)
{
	int ret = dup(fd);
	if (unlikely(ret < 0))
		panic("xdup: dup failed\n");
	return ret;
}

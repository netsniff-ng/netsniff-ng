/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010, 2011 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mcheck.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <sys/types.h>

#ifndef SIZE_T_MAX
# define SIZE_T_MAX  ((size_t) ~0)
#endif

#include "xmalloc.h"
#include "compiler.h"
#include "strlcpy.h"
#include "tty.h"
#include "die.h"

#if 0
static void maybe_exit_by_vomit(enum mcheck_status stat, void *p)
{
	switch (stat) {
	case MCHECK_HEAD:
		panic("Memory underrun at %s%p\n", !p ? "??? " : "", p);
	case MCHECK_TAIL:
		panic("Memory overrun at %s%p\n", !p ? "??? " : "", p);
	case MCHECK_FREE:
		panic("Double free %s%p\n", !p ? "??? " : "", p);
	default:
		break;
	}
}
#endif

static void checkmem(void *p)
{
	return;
#if 0
	if (p) {
		enum mcheck_status stat = mprobe(p);
		maybe_exit_by_vomit(stat, p);
	}
#endif
}

#if 0
void mcheck_abort(enum mcheck_status stat)
{
	maybe_exit_by_vomit(stat, NULL);
}

static void xmalloc_mcheck_init(void)
{
	int ret = mcheck_pedantic(mcheck_abort);
	if (ret < 0)
		panic("xmalloc: cannot init mcheck! bug\n");
	mtrace();
}

static void xmalloc_init_hook(void)
{
	xmalloc_mcheck_init();
}
#endif

//void (*__malloc_initialize_hook)(void) = xmalloc_init_hook;

__hidden void *xmalloc(size_t size)
{
	void *ptr;

	if (size == 0)
		panic("xmalloc: zero size\n");

	ptr = malloc(size);
	if (ptr == NULL)
		panic("xmalloc: out of memory (allocating %lu bytes)\n",
		      (u_long) size);
	checkmem(ptr);

	debug_blue("%p: %zu", ptr, size);
	return ptr;
}

__hidden void *xzmalloc(size_t size)
{
	void *ptr;

	if (size == 0)
		panic("xzmalloc: zero size\n");

	ptr = malloc(size);
	if (ptr == NULL)
		panic("xzmalloc: out of memory (allocating %lu bytes)\n",
		      (u_long) size);
	checkmem(ptr);

	memset(ptr, 0, size);

	debug_blue("%p: %zu", ptr, size);
	return ptr;
}

__hidden void *xmalloc_aligned(size_t size, size_t alignment)
{
	int ret;
	void *ptr;

	if (size == 0)
		panic("xmalloc_aligned: zero size\n");

	ret = posix_memalign(&ptr, alignment, size);
	if (ret != 0)
		panic("xmalloc_aligned: out of memory (allocating %lu "
		      "bytes)\n", (u_long) size);
	checkmem(ptr);

	debug_blue("%p: %zu", ptr, size);
	return ptr;
}

__hidden void *xvalloc(size_t size)
{
	void *ptr;

	if (size == 0)
		panic("xvalloc: zero size\n");

	ptr = valloc(size);
	if (ptr == NULL)
		panic("xvalloc: out of memory (allocating %lu bytes)\n",
		      (u_long) size);
	checkmem(ptr);

	debug_blue("%p: %zu", ptr, size);
	return ptr;
}

__hidden void *xmallocz(size_t size)
{
	void *ptr;

	if (size + 1 < size)
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

__hidden void *xcalloc(size_t nmemb, size_t size)
{
	void *ptr;

	if (size == 0 || nmemb == 0)
		panic("xcalloc: zero size\n");
	if (SIZE_T_MAX / nmemb < size)
		panic("xcalloc: nmemb * size > SIZE_T_MAX\n");

	ptr = calloc(nmemb, size);
	if (ptr == NULL)
		panic("xcalloc: out of memory (allocating %lu bytes)\n",
		      (u_long) (size * nmemb));
	checkmem(ptr);

	debug_blue("%p: %zu", ptr, size);
	return ptr;
}

__hidden void *xrealloc(void *ptr, size_t nmemb, size_t size)
{
	void *new_ptr;
	size_t new_size = nmemb * size;

	if (new_size == 0)
		panic("xrealloc: zero size\n");
	if (SIZE_T_MAX / nmemb < size)
		panic("xrealloc: nmemb * size > SIZE_T_MAX\n");

	if (ptr == NULL)
		new_ptr = malloc(new_size);
	else
		new_ptr = realloc(ptr, new_size);

	if (new_ptr == NULL)
		panic("xrealloc: out of memory (new_size %lu bytes)\n",
		      (u_long) new_size);
	checkmem(ptr);

	debug_blue("%p: %zu => %p: %zu", ptr, size, new_ptr, new_size);
	return new_ptr;
}

__hidden void xfree_func(void *ptr)
{
	if (ptr == NULL)
		panic("xfree: NULL pointer given as argument\n");
	checkmem(ptr);

	debug_blue("%p => 0", ptr);

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
	if (ret < 0)
		panic("xdup: dup failed\n");

	return ret;
}


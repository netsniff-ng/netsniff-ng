/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

/*
 * Copyright (C) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland, 
 *                    All rights reserved
 * Copyright (C) 2010 Daniel Borkmann <daniel@netsniff-ng.org>,
 *                    Ported from SSH and added several other functions and
 *                    heap consistency checks
 *
 * Versions of malloc and friends that check their results, and never return
 * failure (they call fatal if they encounter an error).
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mcheck.h>
#include <unistd.h>

#ifndef SIZE_T_MAX
# define SIZE_T_MAX  ((size_t) ~0)
#endif

#include "xmalloc.h"
#include "compiler.h"
#include "strlcpy.h"
#include "tty.h"
#include "error_and_die.h"

static int mcheck_init = 1;

void mcheck_abort(enum mcheck_status stat)
{
	if (stat != MCHECK_OK)
		error_and_die(EXIT_FAILURE, "mcheck: mem inconsistency "
			      "detected: %d\n", stat);
}

void muntrace_handler(int signal)
{
	muntrace();
	abort();
}

void *xmalloc(size_t size)
{
	void *ptr;
	enum mcheck_status stat;

	if (size == 0)
		error_and_die(EXIT_FAILURE, "xmalloc: zero size\n");

	if (unlikely(mcheck_init)) {
		int ret = mcheck_pedantic(mcheck_abort);
		if (ret < 0)
			error_and_die(EXIT_FAILURE, "xmalloc: cannot init "
				      "mcheck! bug\n");
		mtrace();
		mcheck_init = 0;
	}

	ptr = malloc(size);
	if (ptr == NULL)
		error_and_die(EXIT_FAILURE, "xmalloc: out of memory "
			      "(allocating %lu bytes)\n", (u_long) size);
	stat = mprobe(ptr);
	if (stat != MCHECK_OK)
		error_and_die(EXIT_FAILURE, "xmalloc: mem inconsistency "
			      "detected: %d\n", stat);

	debug_blue("%p: %zu", ptr, size);
	return ptr;
}

void *xzmalloc(size_t size)
{
	void *ptr;
	enum mcheck_status stat;

	if (size == 0)
		error_and_die(EXIT_FAILURE, "xzmalloc: zero size\n");

	if (unlikely(mcheck_init)) {
		int ret = mcheck_pedantic(mcheck_abort);
		if (ret < 0)
			error_and_die(EXIT_FAILURE, "xmalloc: cannot init "
				      "mcheck! bug\n");
		mtrace();
		mcheck_init = 0;
	}

	ptr = malloc(size);
	if (ptr == NULL)
		error_and_die(EXIT_FAILURE, "xzmalloc: out of memory "
			      "(allocating %lu bytes)\n", (u_long) size);

	stat = mprobe(ptr);
	if (stat != MCHECK_OK)
		error_and_die(EXIT_FAILURE, "xzmalloc: mem inconsistency "
			      "detected: %d\n", stat);

	memset(ptr, 0, size);

	debug_blue("%p: %zu", ptr, size);
	return ptr;
}

void *xmalloc_aligned(size_t size, size_t alignment)
{
	int ret;
	void *ptr;
	enum mcheck_status stat;

	if (size == 0)
		error_and_die(EXIT_FAILURE, "xmalloc_aligned: zero size\n");

	if (unlikely(mcheck_init)) {
		int ret = mcheck_pedantic(mcheck_abort);
		if (ret < 0)
			error_and_die(EXIT_FAILURE, "xmalloc_aligned: cannot "
				      "init mcheck! bug\n");
		mtrace();
		mcheck_init = 0;
	}

	ret = posix_memalign(&ptr, alignment, size);
	if (ret != 0)
		error_and_die(EXIT_FAILURE, "xmalloc_aligned: out of memory "
			      "(allocating %lu bytes)\n", (u_long) size);
	stat = mprobe(ptr);
	if (stat != MCHECK_OK)
		error_and_die(EXIT_FAILURE, "xmalloc_aligned: mem "
			      "inconsistency detected: %d\n", stat);

	debug_blue("%p: %zu", ptr, size);
	return ptr;
}

void *xmallocz(size_t size)
{
	void *ptr;

	if (size + 1 < size)
		error_and_die(EXIT_FAILURE, "xmallocz: data too large to fit "
			      "into virtual memory space\n");

	ptr = xmalloc(size + 1);
	((char*) ptr)[size] = 0;

	return ptr;
}

void *xmemdupz(const void *data, size_t len)
{
	return memcpy(xmallocz(len), data, len);
}

void *xcalloc(size_t nmemb, size_t size)
{
	void *ptr;
	enum mcheck_status stat;

	if (size == 0 || nmemb == 0)
		error_and_die(EXIT_FAILURE, "xcalloc: zero size\n");
	if (SIZE_T_MAX / nmemb < size)
		error_and_die(EXIT_FAILURE, "xcalloc: nmemb * size > "
			      "SIZE_T_MAX\n");

	if (unlikely(mcheck_init)) {
		int ret = mcheck_pedantic(mcheck_abort);
		if (ret < 0)
			error_and_die(EXIT_FAILURE, "xmalloc: cannot init "
				      "mcheck! bug\n");
		mtrace();
		mcheck_init = 0;
	}

	ptr = calloc(nmemb, size);
	if (ptr == NULL)
		error_and_die(EXIT_FAILURE, "xcalloc: out of memory "
			      "(allocating %lu bytes)\n",
			      (u_long) (size * nmemb));

	stat = mprobe(ptr);
	if (stat != MCHECK_OK)
		error_and_die(EXIT_FAILURE, "xcalloc: mem inconsistency "
			      "detected: %d\n", stat);

	debug_blue("%p: %zu", ptr, size);
	return ptr;
}

void *xrealloc(void *ptr, size_t nmemb, size_t size)
{
	void *new_ptr;
	size_t new_size = nmemb * size;
	enum mcheck_status stat;

	if (new_size == 0)
		error_and_die(EXIT_FAILURE, "xrealloc: zero size\n");
	if (SIZE_T_MAX / nmemb < size)
		error_and_die(EXIT_FAILURE, "xrealloc: nmemb * size > "
			      "SIZE_T_MAX\n");

	if (unlikely(mcheck_init)) {
		int ret = mcheck_pedantic(mcheck_abort);
		if (ret < 0)
			error_and_die(EXIT_FAILURE, "xmalloc: cannot init "
				      "mcheck! bug\n");
		mtrace();
		mcheck_init = 0;
	}

	if (ptr == NULL)
		new_ptr = malloc(new_size);
	else
		new_ptr = realloc(ptr, new_size);

	if (new_ptr == NULL)
		error_and_die(EXIT_FAILURE, "xrealloc: out of memory "
			      "(new_size %lu bytes)\n", (u_long) new_size);

	stat = mprobe(ptr);
	if (stat != MCHECK_OK)
		error_and_die(EXIT_FAILURE, "xrealloc: mem inconsistency "
			      "detected: %d\n", stat);

	debug_blue("%p: %zu => %p: %zu", ptr, size, new_ptr, new_size);
	return new_ptr;
}

void xfree(void *ptr)
{
	enum mcheck_status stat;

	if (ptr == NULL)
		error_and_die(EXIT_FAILURE, "xfree: NULL pointer given as "
			      "argument\n");

	if (unlikely(mcheck_init)) {
		int ret = mcheck_pedantic(mcheck_abort);
		if (ret < 0)
			error_and_die(EXIT_FAILURE, "xmalloc: cannot init "
				      "mcheck! bug\n");
		mtrace();
		mcheck_init = 0;
	}

	stat = mprobe(ptr);
	if (stat != MCHECK_OK)
		error_and_die(EXIT_FAILURE, "xfree: mem inconsistency "
			      "detected: %d\n", stat);

	debug_blue("%p => 0", ptr);

	free(ptr);
}

char *xstrdup(const char *str)
{
	size_t len;
	char *cp;

	len = strlen(str) + 1;
	cp = xmalloc(len);
	strlcpy(cp, str, len);

	return cp;
}

char *xstrndup(const char *str, size_t size)
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

int xdup(int fd)
{
	int ret = dup(fd);
	if (ret < 0)
		error_and_die(EXIT_FAILURE, "xdup: dup failed\n");

	return ret;
}


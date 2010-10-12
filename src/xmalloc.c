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
 *                    Ported from SSH and added several other stuff
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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef SIZE_T_MAX
# define SIZE_T_MAX  ((size_t) ~0)
#endif

#include "xmalloc.h"
#include "strlcpy.h"
#include "tty.h"
#include "error_and_die.h"

void *xmalloc(size_t size)
{
	void *ptr;

	if (size == 0)
		error_and_die(EXIT_FAILURE, "xmalloc: zero size\n");

	ptr = malloc(size);
	if (ptr == NULL)
		error_and_die(EXIT_FAILURE, "xmalloc: out of memory "
			      "(allocating %lu bytes)\n", (u_long) size);
	debug_blue("%p: %zu", ptr, size);

	return ptr;
}

void *xzmalloc(size_t size)
{
	void *ptr;

	if (size == 0)
		error_and_die(EXIT_FAILURE, "xzmalloc: zero size\n");

	ptr = malloc(size);
	if (ptr == NULL)
		error_and_die(EXIT_FAILURE, "xzmalloc: out of memory "
			      "(allocating %lu bytes)\n", (u_long) size);
	memset(ptr, 0, size);
	debug_blue("%p: %zu", ptr, size);

	return ptr;
}

void *xcalloc(size_t nmemb, size_t size)
{
	void *ptr;

	if (size == 0 || nmemb == 0)
		error_and_die(EXIT_FAILURE, "xcalloc: zero size\n");
	if (SIZE_T_MAX / nmemb < size)
		error_and_die(EXIT_FAILURE, "xcalloc: nmemb * size > "
			      "SIZE_T_MAX\n");

	ptr = calloc(nmemb, size);
	if (ptr == NULL)
		error_and_die(EXIT_FAILURE, "xcalloc: out of memory "
			      "(allocating %lu bytes)\n",
			      (u_long) (size * nmemb));
	debug_blue("%p: %zu", ptr, size);

	return ptr;
}

void *xrealloc(void *ptr, size_t nmemb, size_t size)
{
	void *new_ptr;
	size_t new_size = nmemb * size;

	if (new_size == 0)
		error_and_die(EXIT_FAILURE, "xrealloc: zero size\n");
	if (SIZE_T_MAX / nmemb < size)
		error_and_die(EXIT_FAILURE, "xrealloc: nmemb * size > "
			      "SIZE_T_MAX\n");

	if (ptr == NULL)
		new_ptr = malloc(new_size);
	else
		new_ptr = realloc(ptr, new_size);

	if (new_ptr == NULL)
		error_and_die(EXIT_FAILURE, "xrealloc: out of memory "
			      "(new_size %lu bytes)\n", (u_long) new_size);
	debug_blue("%p: %zu => %p: %zu", ptr, size, new_ptr, new_size);

	return new_ptr;
}

void xfree(void *ptr)
{
	if (ptr == NULL)
		error_and_die(EXIT_FAILURE, "xfree: NULL pointer given as "
			      "argument\n");
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


/*
 * Copyright (C) 2009, 2010  Daniel Borkmann <daniel@netsniff-ng.org> and 
 *                           Emmanuel Roullit <emmanuel@netsniff-ng.org>
 *
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation; either version 2 of the License, or (at 
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License 
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
 */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Versions of malloc and friends that check their results, and never return
 * failure (they call fatal if they encounter an error).
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

/* xmalloc.c taken from OpenSSH and adapted */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#ifndef SIZE_T_MAX
#define SIZE_T_MAX  UINT_MAX
#endif

#include "macros.h"
#include "xmalloc.h"
#include "strlcpy.h"

void *xmalloc(size_t size)
{
	void *ptr;

	if (size == 0) {
		err("xmalloc: zero size");
		exit(EXIT_FAILURE);
	}
	
	ptr = malloc(size);
	if (ptr == NULL) {
		err("xmalloc: out of memory (allocating %lu bytes)", 
		    (u_long) size);
		exit(EXIT_FAILURE);
	}
	
	return ptr;
}

void *xzmalloc(size_t size)
{
	void *ptr;

	if (size == 0) {
		err("xmalloc: zero size");
		exit(EXIT_FAILURE);
	}

	ptr = malloc(size);
	if (ptr == NULL) {
		err("xmalloc: out of memory (allocating %lu bytes)", 
		    (u_long) size);
		exit(EXIT_FAILURE);
	}

	memset(ptr, 0, size);
	return ptr;
}

void *xcalloc(size_t nmemb, size_t size)
{
	void *ptr;

	if (size == 0 || nmemb == 0) {
		err("xcalloc: zero size");
		exit(EXIT_FAILURE);
	}

	if (SIZE_T_MAX / nmemb < size) {
		err("xcalloc: nmemb * size > SIZE_T_MAX");
		exit(EXIT_FAILURE);
	}

	ptr = calloc(nmemb, size);
	if (ptr == NULL) {
		err("xcalloc: out of memory (allocating %lu bytes)",
		    (u_long)(size * nmemb));
		exit(EXIT_FAILURE);
	}

	return ptr;
}

void *xrealloc(void *ptr, size_t nmemb, size_t size)
{
	void *new_ptr;
	size_t new_size = nmemb * size;

	if (new_size == 0) {
		err("xrealloc: zero size");
		exit(EXIT_FAILURE);
	}

	if (SIZE_T_MAX / nmemb < size) {
		err("xrealloc: nmemb * size > SIZE_T_MAX");
		exit(EXIT_FAILURE);
	}

	if (ptr == NULL) {
		new_ptr = malloc(new_size);
	} else {
		new_ptr = realloc(ptr, new_size);
	}

	if (new_ptr == NULL) {
		err("xrealloc: out of memory (new_size %lu bytes)",
		    (u_long) new_size);
		exit(EXIT_FAILURE);
	}

	return new_ptr;
}

void xfree(void *ptr)
{
	if (ptr == NULL) {
		err("xfree: NULL pointer given as argument");
		exit(EXIT_FAILURE);
	}

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


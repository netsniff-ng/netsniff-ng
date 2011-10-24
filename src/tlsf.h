/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

/*
 * Two Levels Segregate Fit memory allocator (TLSF), Version 2.4.6
 * Written by Miguel Masmano Tello <mimastel@doctor.upv.es>
 * Thanks to Ismael Ripoll for his suggestions and reviews
 * Copyright (C) 2008, 2007, 2006, 2005, 2004
 * This code is released using a dual license strategy: GPL/LGPL
 * You can choose the licence that better fits your requirements.
 * Released under the terms of the GNU General Public License Version 2.0
 * Released under the terms of the GNU Lesser General Public License Version 2.1
 */

#ifndef TLSF_H
#define TLSF_H

#include <sys/types.h>
#include <string.h>

#include "die.h"
#include "compiler.h"
#include "strlcpy.h"

extern size_t init_memory_pool(size_t, void *);
extern size_t get_used_size(void *);
extern size_t get_max_size(void *);
extern void destroy_memory_pool(void *);
extern size_t add_new_area(void *, size_t, void *);
extern void *malloc_ex(size_t, void *);
extern void free_ex(void *, void *);
extern void *realloc_ex(void *, size_t, void *);
extern void *calloc_ex(size_t, size_t, void *);

extern void *tlsf_malloc(size_t size);
extern void tlsf_free(void *ptr);
extern void *tlsf_realloc(void *ptr, size_t size);
extern void *tlsf_calloc(size_t nelem, size_t elem_size);

static inline void *xtlsf_malloc(size_t size)
{
	void *ptr;
	if (unlikely(size == 0))
		panic("xtlsf_malloc: zero size!\n");
	ptr = tlsf_malloc(size);
	if (unlikely(!ptr))
		panic("xtlsf_malloc: out of mem!\n");
	return ptr;
}

static inline void xtlsf_free(void *ptr)
{
	if (unlikely(!ptr))
		panic("xtlsf_free: freeing NULL ptr!\n");
	tlsf_free(ptr);
}

static inline char *xtlsf_strdup(const char *str)
{
	size_t len;
	char *cp;
	len = strlen(str) + 1;
	cp = xtlsf_malloc(len);
	strlcpy(cp, str, len);
	return cp;
}

#endif /* TLSF_H */


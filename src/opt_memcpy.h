/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef OPT_MEMCPY_H
#define OPT_MEMCPY_H

/* This one checks CPU flags and sets right variant! */
extern void set_memcpy(void);
extern void *(*____memcpy)(void *dest, const void *src, size_t n);

static inline void *__memcpy(void *dest, const void *src, size_t n)
{
	return ____memcpy(dest, src, n);
}

extern void *__sse_memcpy_32(void *dest, const void *src, size_t n);
extern void *__sse_memcpy_64(void *dest, const void *src, size_t n);
extern void *__mmx_memcpy_32(void *dest, const void *src, size_t n);
extern void *__mmx_memcpy_64(void *dest, const void *src, size_t n);

#endif /* OPT_MEMCPY_H */

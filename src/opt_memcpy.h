/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef OPT_MEMCPY_H
#define OPT_MEMCPY_H

#define small_memcpy(dest, src, n)                                       \
	do {                                                             \
		register unsigned long int dummy;                        \
		asm volatile ("rep; movsb\n\t"                           \
			      : "=&D" (dest), "=&S" (src), "=&c" (dummy) \
			      : "0" (dest), "1" (src), "2" (n)           \
			      : "memory");                               \
	} while(0)

/* From the Linux kernel. */
static inline void *___memcpy(void *__restrict__ dest,
			      const void *__restrict__ src, size_t n)
{
	int d0, d1, d2;

	if (n == 4)
		small_memcpy(dest, src, n);
	else
		asm volatile("rep ; movsl\n\t"
			     "testb $2,%b4\n\t"
			     "je 1f\n\t"
			     "movsw\n"
			     "1:\ttestb $1,%b4\n\t"
			     "je 2f\n\t"
			     "movsb\n"
			     "2:"
			     : "=&c" (d0), "=&D" (d1), "=&S" (d2)
			     : "0" (n / 4), "q" (n), "1" ((long)dest), "2" ((long)src)
			     : "memory");
	return (dest);
}

/* This one checks CPU flags and sets right variant! */
extern void set_memcpy(void);
extern void *(*____memcpy)(void *__restrict__ dest, const void *__restrict__ src,
			   size_t n);

static inline void *__memcpy(void *__restrict__ dest, const void *__restrict__ src,
			     size_t n)
{
	return ____memcpy(dest, src, n);
}

extern void *__sse_memcpy(void *__restrict__ dest, const void *__restrict__ src, size_t n);
extern void *__sse2_memcpy(void *__restrict__ dest, const void *__restrict__ src, size_t n);
extern void *__mmx_memcpy(void *__restrict__ dest, const void *__restrict__ src, size_t n);
extern void *__mmx2_memcpy(void *__restrict__ dest, const void *__restrict__ src, size_t n);

#endif /* OPT_MEMCPY_H */

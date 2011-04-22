/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

#include <string.h>
#include <signal.h>
#include <stdint.h>

#include "die.h"
#include "compiler.h"
#include "opt_memcpy.h"

/* TODO: SSSE3? */

#define CPU_FLAG_NONE   0
#define CPU_FLAG_NOPT   1
#define CPU_FLAG_MMX    5
#define CPU_FLAG_SSE    6
#define CPU_FLAG_SSE2   7

/*
 * memcpy(3) provided by glibc does obviously not exploit all the
 * CPU features, i.e. did testing with SSE2 memcpy vs. glibc memcpy
 * and the former was about 4 times as fast!
 */

static sig_atomic_t checked = 0;
void *(*____memcpy)(void *dest, const void *src, size_t n) = memcpy;

struct cpuid_regs {
	unsigned int eax;
	unsigned int ebx;
	unsigned int ecx;
	unsigned int edx;
};

static int check_cpu_flags(void)
{
	struct cpuid_regs regs;

#define CPUID ".byte 0x0f, 0xa2; "
	asm (CPUID : "=a" (regs.eax),
		     "=b" (regs.ebx),
		     "=c" (regs.ecx),
		     "=d" (regs.edx) : "0" (1));

	if (regs.edx & 0x4000000)
		return CPU_FLAG_SSE2;
	if (regs.edx & 0x2000000)
		return CPU_FLAG_SSE;
	if (regs.edx & 0x800000)
		return CPU_FLAG_MMX;
	return CPU_FLAG_NONE;
}

#define small_memcpy(dest, src, n)                                       \
	do {                                                             \
		register unsigned long int dummy;                        \
		asm volatile ("rep; movsb\n\t"                           \
			      : "=&D" (dest), "=&S" (src), "=&c" (dummy) \
			      : "0" (dest), "1" (src), "2" (n)           \
			      : "memory");                               \
	} while(0)

/* From the Linux kernel. */
static inline void *___memcpy(void *dest, const void *src, size_t n)
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

#define MIN_LEN        0x40
#define SSE_MMREG_SIZE 16
#define MMX_MMREG_SIZE  8

void *__sse_memcpy_32(void *dest, const void *src, size_t n)
{
	uint8_t *to = dest;
	const uint8_t *from = src;
	void *const save = to;

	__asm__ __volatile__ ("prefetchnta (%0)\n"
			      "prefetchnta 32(%0)\n"
			      "prefetchnta 64(%0)\n"
			      "prefetchnta 96(%0)\n"
			      "prefetchnta 128(%0)\n"
			      "prefetchnta 160(%0)\n"
			      "prefetchnta 192(%0)\n"
			      "prefetchnta 224(%0)\n"
			      "prefetchnta 256(%0)\n"
			      "prefetchnta 288(%0)\n"::"r" (from));

	if (n >= MIN_LEN) {
		register int i;
		register int j;
		register unsigned long delta;

		delta = ((unsigned long) to) & (SSE_MMREG_SIZE - 1);
		if (delta) {
			delta = SSE_MMREG_SIZE - delta;
			n -= delta;
			small_memcpy(to, from, delta);
		}

		j = n >> 6;
		n &= 63;
		for (i = 0; i < j; i++)	{
			__asm__ __volatile__ ("prefetchnta 320(%0)\n"
					      "prefetchnta 352(%0)\n"
					      "movups (%0), %%xmm0\n"
					      "movups 16(%0), %%xmm1\n"
					      "movups 32(%0), %%xmm2\n"
					      "movups 48(%0), %%xmm3\n"
					      "movntps %%xmm0, (%1)\n"
					      "movntps %%xmm1, 16(%1)\n"
					      "movntps %%xmm2, 32(%1)\n"
					      "movntps %%xmm3, 48(%1)\n"::"r" (from),
					      "r" (to):"memory");
			from += 64;
			to += 64;
		}

		__asm__ __volatile__ ("sfence":::"memory");
	}
	if (n != 0)
		___memcpy(to, from, n);
	return save;
}

void *__sse_memcpy_64(void *dest, const void *src, size_t n)
{
	uint8_t *to = dest;
	const uint8_t *from = src;
	void *const save = to;

	__asm__ __volatile__ ("prefetchnta (%0)\n"
			      "prefetchnta 64(%0)\n"
			      "prefetchnta 128(%0)\n"
			      "prefetchnta 192(%0)\n"
			      "prefetchnta 256(%0)\n"::"r" (from));

	if (n >= MIN_LEN) {
		register int i;
		register int j;
		register unsigned long delta;

		delta = ((unsigned long) to) & (SSE_MMREG_SIZE - 1);
		if (delta) {
			delta = SSE_MMREG_SIZE - delta;
			n -= delta;
			small_memcpy(to, from, delta);
		}

		j = n >> 6;
		n &= 63;
		for (i = 0; i < j; i++)	{
			__asm__ __volatile__ ("prefetchnta 320(%0)\n"
					      "movups (%0), %%xmm0\n"
					      "movups 16(%0), %%xmm1\n"
					      "movups 32(%0), %%xmm2\n"
					      "movups 48(%0), %%xmm3\n"
					      "movntps %%xmm0, (%1)\n"
					      "movntps %%xmm1, 16(%1)\n"
					      "movntps %%xmm2, 32(%1)\n"
					      "movntps %%xmm3, 48(%1)\n"::"r" (from),
					      "r" (to):"memory");
			from += 64;
			to += 64;
		}

		__asm__ __volatile__ ("sfence":::"memory");
	}

	if (n != 0)
		___memcpy (to, from, n);
	return save;
}

void *__mmx_memcpy_32(void *dest, const void *src, size_t n)
{
	uint8_t *to = dest;
	const uint8_t *from = src;
	void *const save = to;
	register int i;
	register int j;

	__asm__ __volatile__ ("prefetchnta (%0)\n"
			      "prefetchnta 32(%0)\n"
			      "prefetchnta 64(%0)\n"
			      "prefetchnta 96(%0)\n"
			      "prefetchnta 128(%0)\n"
			      "prefetchnta 160(%0)\n"
			      "prefetchnta 192(%0)\n"
			      "prefetchnta 224(%0)\n"
			      "prefetchnta 256(%0)\n"
			      "prefetchnta 288(%0)\n"::"r" (from));
	j = n >> 6;
	n &= 63;
	for (i = 0; i < j; i++) {
		__asm__ __volatile__ ("prefetchnta 320(%0)\n"
				      "prefetchnta 352(%0)\n"
				      "movq (%0), %%mm0\n"
				      "movq 8(%0), %%mm1\n"
				      "movq 16(%0), %%mm2\n"
				      "movq 24(%0), %%mm3\n"
				      "movq 32(%0), %%mm4\n"
				      "movq 40(%0), %%mm5\n"
				      "movq 48(%0), %%mm6\n"
				      "movq 56(%0), %%mm7\n"
				      "movq %%mm0, (%1)\n"
				      "movq %%mm1, 8(%1)\n"
				      "movq %%mm2, 16(%1)\n"
				      "movq %%mm3, 24(%1)\n"
				      "movq %%mm4, 32(%1)\n"
				      "movq %%mm5, 40(%1)\n"
				      "movq %%mm6, 48(%1)\n"
				      "movq %%mm7, 56(%1)\n"::"r" (from),
				      "r" (to):"memory");
		from += 64;
		to += 64;
	}

	__asm__ __volatile__ ("sfence":::"memory");
	__asm__ __volatile__ ("emms":::"memory");

	if (n != 0)
		___memcpy (to, from, n);
	return save;
}

void *__mmx_memcpy_64(void *dest, const void *src, size_t n)
{
	uint8_t *to = dest;
	const uint8_t *from = src;
	void *const save = to;
	register int i;
	register int j;

	__asm__ __volatile__ ("prefetchnta (%0)\n"
			      "prefetchnta 64(%0)\n"
			      "prefetchnta 128(%0)\n"
			      "prefetchnta 192(%0)\n"
			      "prefetchnta 256(%0)\n"::"r" (from));
	j = n >> 6;
	n &= 63;
	for (i = 0; i < j; i++) {
		__asm__ __volatile__ ("prefetchnta 320(%0)\n"
				      "movq (%0), %%mm0\n"
				      "movq 8(%0), %%mm1\n"
				      "movq 16(%0), %%mm2\n"
				      "movq 24(%0), %%mm3\n"
				      "movq 32(%0), %%mm4\n"
				      "movq 40(%0), %%mm5\n"
				      "movq 48(%0), %%mm6\n"
				      "movq 56(%0), %%mm7\n"
				      "movq %%mm0, (%1)\n"
				      "movq %%mm1, 8(%1)\n"
				      "movq %%mm2, 16(%1)\n"
				      "movq %%mm3, 24(%1)\n"
				      "movq %%mm4, 32(%1)\n"
				      "movq %%mm5, 40(%1)\n"
				      "movq %%mm6, 48(%1)\n"
				      "movq %%mm7, 56(%1)\n"::"r" (from),
				      "r" (to):"memory");
		from += 64;
		to += 64;
	}

	__asm__ __volatile__ ("sfence":::"memory");
	__asm__ __volatile__ ("emms":::"memory");

	if (n != 0)
		___memcpy(to, from, n);
	return save;
}

/* Will be extended in future! */
void set_memcpy(void)
{
	int cpu_flag;

	if (likely(checked))
		return;
	cpu_flag = check_cpu_flags();
	if (cpu_flag == CPU_FLAG_SSE2) {
		____memcpy = __sse_memcpy_64;
		info("Using __sse_memcpy_64!\n");
	} else if (cpu_flag == CPU_FLAG_SSE) {
		____memcpy = __sse_memcpy_32;
		info("Using __sse_memcpy_32!\n");
	} else if (cpu_flag == CPU_FLAG_MMX) {
		____memcpy = __mmx_memcpy_64;
		info("Using __sse_memcpy_64!\n");
	} else
		____memcpy = memcpy;
	checked = 1;
}

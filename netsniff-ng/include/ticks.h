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
 * Copyright (c) 2003, 2007-8 Matteo Frigo
 * Copyright (c) 2003, 2007-8 Massachusetts Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef _NET_TICKS_H_
#define _NET_TICKS_H_

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

/*
 * The following API for netsniff-ng will be provided (e.g. for benchmarking 
 * purpose, debugging or high-pres (but arch dependent!) time):
 *   ticks_t getticks(void);
 *   double elapsed(ticks_t t1, ticks_t t0);
 */

/* Intel Pentium / AMD Time Stamp Counter register */
#if (defined(__GNUC__) || defined(__ICC)) && defined(__i386__) && \
    !defined(HAVE_TICK_COUNTER)
typedef unsigned long long ticks_t;

static __inline__ ticks_t getticks(void)
{
	ticks_t ret;
	__asm__ __volatile__("rdtsc":"=A"(ret));
	return ret;
}

static __inline__ double elapsed(ticks_t t1, ticks_t t0)
{
	return (double)t1 - (double)t0;
}

# define HAVE_TICK_COUNTER
# define TIME_MIN 5000.0	/* Unreliable Pentium IV cycle counter */
#endif				/* Intel Pentium / AMD Time Stamp Counter register */

/* PowerPC */
#if ((((defined(__GNUC__) && (defined(__powerpc__) || defined(__ppc__))) || \
       (defined(__MWERKS__) && defined(macintosh)))) || \
     (defined(__IBM_GCC_ASM) && (defined(__powerpc__) || \
      defined(__ppc__)))) && \
    !defined(HAVE_TICK_COUNTER)
typedef unsigned long long ticks_t;

static __inline__ ticks_t getticks(void)
{
	unsigned int tbl, tbu0, tbu1;

	do {
		__asm__ __volatile__("mftbu %0":"=r"(tbu0));
		__asm__ __volatile__("mftb %0":"=r"(tbl));
		__asm__ __volatile__("mftbu %0":"=r"(tbu1));
	} while (tbu0 != tbu1);

	return (((unsigned long long)tbu0) << 32) | tbl;
}

static __inline__ double elapsed(ticks_t t1, ticks_t t0)
{
	return (double)t1 - (double)t0;
}

# define HAVE_TICK_COUNTER
#endif				/* PowerPC */

/* Intel Pentium / AMD, 64 Bit Time Stamp Counter register */
#if (defined(__GNUC__) || defined(__ICC) || defined(__SUNPRO_C)) && \
    defined(__x86_64__)  && !defined(HAVE_TICK_COUNTER)
typedef unsigned long long ticks_t;

static __inline__ ticks_t getticks(void)
{
	unsigned a, d;
	__asm__ __volatile__("rdtsc":"=a"(a), "=d"(d));
	return ((ticks_t) a) | (((ticks_t) d) << 32);
}

static __inline__ double elapsed(ticks_t t1, ticks_t t0)
{
	return (double)t1 - (double)t0;
}

# define HAVE_TICK_COUNTER
#endif				/* Intel Pentium / AMD, 64 Bit Time Stamp Counter register */

/* IA64 cycle counter, gcc version */
#if defined(__GNUC__) && defined(__ia64__) && !defined(HAVE_TICK_COUNTER)
typedef unsigned long ticks_t;

static __inline__ ticks_t getticks(void)
{
	ticks_t ret;
	__asm__ __volatile__("mov %0=ar.itc":"=r"(ret));
	return ret;
}

static __inline__ double elapsed(ticks_t t1, ticks_t t0)
{
	return (double)t1 - (double)t0;
}

# define HAVE_TICK_COUNTER
#endif				/* IA64 cycle counter, gcc version */

/* SPARC */
#if defined(__GNUC__) && defined(__sparc_v9__) && !defined(HAVE_TICK_COUNTER)
typedef unsigned long ticks_t;

static __inline__ ticks_t getticks(void)
{
	ticks_t ret;
	__asm__ __volatile__("rd %%tick, %0":"=r"(ret));
	return ret;
}

static __inline__ double elapsed(ticks_t t1, ticks_t t0)
{
	return (double)t1 - (double)t0;
}

# define HAVE_TICK_COUNTER
#endif				/* SPARC */

#endif				/* _NET_TICKS_H_ */

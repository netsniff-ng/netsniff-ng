/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef ATOMIC_H
#define ATOMIC_H

#ifndef COMPILER_H
# error "Never include <atomic.h> directly; use <compiler.h> instead."
#endif

static inline unsigned short atomic_preincrement_ushort(unsigned short x)
{
	return __sync_add_and_fetch(&x, 1);
}

static inline unsigned int atomic_preincrement_uint(unsigned int x)
{
	return __sync_add_and_fetch(&x, 1);
}

static inline unsigned short atomic_predecrement_ushort(unsigned short x)
{
	return __sync_sub_and_fetch(&x, 1);
}

static inline unsigned int atomic_predecrement_uint(unsigned int x)
{
	return __sync_sub_and_fetch(&x, 1);
}

#endif /* ATOMIC_H */

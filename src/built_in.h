/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef BUILT_IN_H
#define BUILT_IN_H

#ifndef __aligned_16
# define __aligned_16		__attribute__((aligned(16)))
#endif

#ifndef likely
# define likely(x)		__builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
# define unlikely(x)		__builtin_expect(!!(x), 0)
#endif

#ifndef __deprecated
# define __deprecated		/* unimplemented */
#endif

#ifndef unreachable
# define unreachable()		do { } while (1)
#endif

#ifndef __read_mostly
# define __read_mostly		__attribute__((__section__(".data.read_mostly")))
#endif

#ifndef noinline
# define noinline		__attribute__((noinline))
#endif

#ifndef __always_inline
# define __always_inline	inline
#endif

#ifndef __hidden
# define __hidden		__attribute__((visibility("hidden")))
#endif

#ifndef __pure
# define __pure			__attribute__ ((pure))
#endif

#ifndef max
# define max(a, b)                         \
	({                                 \
		typeof (a) _a = (a);       \
		typeof (b) _b = (b);       \
		_a > _b ? _a : _b;         \
	})
#endif /* max */

#ifndef min
# define min(a, b)                         \
	({                                 \
		typeof (a) _a = (a);       \
		typeof (b) _b = (b);       \
		_a < _b ? _a : _b;         \
	})
#endif /* min */

/* from the Linux kernel, GPLv2 */
#ifndef offsetof
# define offsetof(type, member)	((size_t) &((type *) 0)->member)
#endif

#ifndef container_of
# define container_of(ptr, type, member)                             \
	({                                                           \
		const typeof(((type *) 0)->member) * __mptr = (ptr); \
		(type *) ((char *) __mptr - offsetof(type, member)); \
	})
#endif

#endif /* BUILT_IN_H */

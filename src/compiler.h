/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef COMPILER_H
#define COMPILER_H

#define L1_CACHE_BYTES 64 /* Assumption! Fix this eventually! */
#define CACHE_ALIGN_BYTES L1_CACHE_BYTES

#ifndef __cacheline_aligned
#define __cacheline_aligned                             \
	__attribute__((__aligned__(CACHE_ALIGN_BYTES))) \
	__page_aligned_data
#endif

#ifndef likely
# define likely(x)          __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
# define unlikely(x)        __builtin_expect(!!(x), 0)
#endif

#ifndef __deprecated
# define __deprecated       /* unimplemented */
#endif

#ifndef unreachable
# define unreachable()      do { } while (1)
#endif

#define barrier()           __asm__ __volatile__("": : :"memory")
#define mb()                asm volatile("mfence":::"memory")
#define rmb()               asm volatile("lfence":::"memory")
#define wmb()               asm volatile("sfence"::: "memory")
#define smp_mb()            mb()
#define smp_rmb()           rmb()
#define smp_wmb()           wmb()

#ifndef bug
# define build_bug_on(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#endif

#ifndef bug
# define build_bug_on_zero(e) (sizeof(char[1 - 2 * !!(e)]) - 1)
#endif

#ifndef mark_unreachable
# define mark_unreachable() __builtin_unreachable()
#endif

#ifndef is_type
# define is_type(x, type)   __builtin_types_compatible_p(typeof(x), (type))
#endif

#ifndef same_type
# define same_type(x, y)    __builtin_types_compatible_p(typeof(x), typeof(y))
#endif

#ifndef __read_mostly
# define __read_mostly      __attribute__((__section__(".data.read_mostly")))
#endif

#ifndef __must_check
# define __must_check       /* unimplemented */
#endif

#ifndef __used
# define __used             /* unimplemented */
#endif

#ifndef __maybe_unused
# define __maybe_unused     /* unimplemented */
#endif

#ifndef __always_unused
# define __always_unused    /* unimplemented */
#endif

#ifndef noinline
#define noinline            __attribute__((noinline))
#endif

#ifndef __always_inline
# define __always_inline    inline
#endif

#ifndef offsetof
# define offsetof(type, member) ((size_t) &((type *) 0)->member)
#endif

#ifndef container_of
# define container_of(ptr, type, member)                             \
	({                                                           \
		const typeof(((type *) 0)->member) * __mptr = (ptr); \
		(type *) ((char *) __mptr - offsetof(type, member)); \
	})
#endif

static inline void rep_nop(void)
{
	asm volatile("rep; nop" ::: "memory");
}

static inline void cpu_relax(void)
{
	rep_nop();
}

#endif /* COMPILER_H */

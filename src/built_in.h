/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009-2012 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef BUILT_IN_H
#define BUILT_IN_H

#include <linux/if_packet.h>
#include <assert.h>
#include <endian.h>
#include <byteswap.h>
#include <stdint.h>

typedef uint64_t	u64;
typedef uint32_t	u32;
typedef uint16_t	u16;
typedef uint8_t		u8;

/* /sys/devices/system/cpu/cpuX/cache/indexX/coherency_line_size */

#if defined(__amd64__) || defined(__x86_64__) || defined(__AMD64__) || \
    defined(_M_X64) || defined(__amd64)
# define CO_IN_CACHE_SHIFT		7
#elif defined(__i386__) || defined(__x86__) || defined(__X86__) || \
      defined(_M_IX86) || defined(__i386)
# define CO_IN_CACHE_SHIFT		7
#elif defined(__ia64__) || defined(__IA64__) || defined(__M_IA64)
# define CO_IN_CACHE_SHIFT		6
#elif defined(__SPU__)
# define CO_IN_CACHE_SHIFT		7
#elif defined(__powerpc64__) || defined(__ppc64__) || defined(__PPC64__) || \
      defined(_ARCH_PPC64)
# define CO_IN_CACHE_SHIFT		8
#elif defined(__powerpc__) || defined(__ppc__) || defined(__PPC__) || \
      defined(_ARCH_PPC)
# define CO_IN_CACHE_SHIFT		7
#elif defined(__sparcv9__) || defined(__sparcv9)
# define CO_IN_CACHE_SHIFT		6
#elif defined(__sparc_v8__)
# define CO_IN_CACHE_SHIFT		5
#elif defined(__sparc__) || defined(__sparc)
# define CO_IN_CACHE_SHIFT		5
#elif defined(__ARM_EABI__)
# define CO_IN_CACHE_SHIFT		5
#elif defined(__arm__)
# define CO_IN_CACHE_SHIFT		5
#elif defined(__mips__) || defined(__mips) || defined(__MIPS__)
# if defined(_ABIO32)
# define CO_IN_CACHE_SHIFT		5
# elif defined(_ABIN32)
# define CO_IN_CACHE_SHIFT		5
# else
# define CO_IN_CACHE_SHIFT		6
# endif
#else
# define CO_IN_CACHE_SHIFT		5
#endif

#ifndef CO_CACHE_LINE_SIZE
# define CO_CACHE_LINE_SIZE	(1 << CO_IN_CACHE_SHIFT)
#endif

#ifndef __aligned_16
# define __aligned_16		__attribute__((aligned(16)))
#endif

#ifndef __cacheline_aligned
# define __cacheline_aligned	__attribute__((aligned(CO_CACHE_LINE_SIZE)))
#endif

#ifndef __aligned_tpacket
# define __aligned_tpacket	__attribute__((aligned(TPACKET_ALIGNMENT)))
#endif

#ifndef __packed
# define __packed		__attribute__((packed))
#endif

#ifndef round_up
# define round_up(x, alignment)	(((x) + (alignment) - 1) & ~((alignment) - 1))
#endif

#ifndef round_up_cacheline
# define round_up_cacheline(x)	round_up((x), CO_CACHE_LINE_SIZE)
#endif

#ifndef likely
# define likely(x)		__builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
# define unlikely(x)		__builtin_expect(!!(x), 0)
#endif

#ifndef prefetch_rd_hi
# define prefetch_rd_hi(addr)	__builtin_prefetch(addr, 0, 3)
#endif

#ifndef prefetch_rd_lo
# define prefetch_rd_lo(addr)	__builtin_prefetch(addr, 0, 0)
#endif

#ifndef prefetch_wr_hi
# define prefetch_wr_hi(addr)	__builtin_prefetch(addr, 1, 3)
#endif

#ifndef prefetch_wr_lo
# define prefetch_wr_lo(addr)	__builtin_prefetch(addr, 1, 0)
#endif

#ifndef fmemset
# define fmemset		__builtin_memset
#endif

#ifndef fmemcpy
# define fmemcpy		__builtin_memcpy
#endif

#ifndef atomic_cmp_swp
# define atomic_cmp_swp		__sync_val_compare_and_swap
#endif

#ifndef __deprecated
# define __deprecated		/* unimplemented */
#endif

#ifndef EXPORT_SYMBOL
# define EXPORT_SYMBOL(x)	/* empty, just for readability */
#endif

#ifndef unreachable
# define unreachable()		do { } while (1)
#endif

#ifndef __read_mostly
# define __read_mostly		__attribute__((__section__(".data.read_mostly")))
#endif

#ifndef __unused
# define __unused		 __attribute__ ((__unused__))
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

#ifndef force_cast
# define force_cast(type, arg)	((type) (arg))
#endif

#ifndef access_once
# define access_once(x)		(*(volatile typeof(x) *) &(x))
#endif

#ifndef max
# define max(a, b)							\
	({								\
		typeof (a) _a = (a);					\
		typeof (b) _b = (b);					\
		_a > _b ? _a : _b;					\
	})
#endif /* max */

#ifndef min
# define min(a, b)							\
	({								\
		typeof (a) _a = (a);					\
		typeof (b) _b = (b);					\
		_a < _b ? _a : _b;					\
	})
#endif /* min */

#ifndef ispow2
# define ispow2(x)		({ !!((x) && !((x) & ((x) - 1))); })
#endif

#ifndef offsetof
# define offsetof(type, member)	((size_t) &((type *) 0)->member)
#endif

#ifndef container_of
# define container_of(ptr, type, member)				\
	({								\
		const typeof(((type *) 0)->member) * __mptr = (ptr);	\
		(type *) ((char *) __mptr - offsetof(type, member));	\
	})
#endif

#ifndef array_size
# define array_size(x)	(sizeof(x) / sizeof((x)[0]) + __must_be_array(x))
#endif

#ifndef __must_be_array
# define __must_be_array(x)						\
	build_bug_on_zero(__builtin_types_compatible_p(typeof(x),	\
						       typeof(&x[0])))
#endif

#ifndef build_bug_on_zero
# define build_bug_on_zero(e)	(sizeof(char[1 - 2 * !!(e)]) - 1)
#endif

#ifndef bug_on
# define bug_on(cond)		assert(!(cond))
#endif

#ifndef bug
# define bug			assert(0)
#endif

#define PAGE_SIZE		(getpagesize())
#define PAGE_MASK		(~(PAGE_SIZE - 1))
#define PAGE_ALIGN(addr)	(((addr) + PAGE_SIZE - 1) & PAGE_MASK)

#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t htonll(uint64_t x)
{
	return bswap_64(x);
}

static inline uint64_t ntohll(uint64_t x)
{
	return bswap_64(x);
}
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline uint64_t htonll(uint64_t x)
{
	return x;
}

static inline uint64_t ntohll(uint64_t x)
{
	return x;
}
#else
# error __BYTE_ORDER is neither __LITTLE_ENDIAN nor __BIG_ENDIAN
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline u16 cpu_to_be16(u16 val)
{
	return bswap_16(val);
}

static inline u32 cpu_to_be32(u32 val)
{
	return bswap_32(val);
}

static inline u64 cpu_to_be64(u64 val)
{
	return bswap_64(val);
}

static inline u16 cpu_to_le16(u16 val)
{
	return val;
}

static inline u32 cpu_to_le32(u32 val)
{
	return val;
}

static inline u64 cpu_to_le64(u64 val)
{
	return val;
}
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline u16 cpu_to_be16(u16 val)
{
	return val;
}

static inline u32 cpu_to_be32(u32 val)
{
	return val;
}

static inline u64 cpu_to_be64(u64 val)
{
	return val;
}

static inline u16 cpu_to_le16(u16 val)
{
	return bswap_16(val);
}

static inline u32 cpu_to_le32(u32 val)
{
	return bswap_32(val);
}

static inline u64 cpu_to_le64(u64 val)
{
	return bswap_64(val);
}
#else
# error __BYTE_ORDER is neither __LITTLE_ENDIAN nor __BIG_ENDIAN
#endif

#define le64_to_cpu	cpu_to_le64
#define le32_to_cpu	cpu_to_le32
#define le16_to_cpu	cpu_to_le16
#define be64_to_cpu	cpu_to_be64
#define be32_to_cpu	cpu_to_be32
#define be16_to_cpu	cpu_to_be16

#undef memset
#undef memcpy

#define memset		fmemset
#define memcpy		fmemcpy

#endif /* BUILT_IN_H */

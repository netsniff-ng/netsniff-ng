#ifndef BUILT_IN_H
#define BUILT_IN_H

/* Parts taken from the Linux kernel, GPL, version 2. */

#include <linux/if_packet.h>
#include <assert.h>
#include <endian.h>
#include <byteswap.h>
#include <asm/byteorder.h>
#include <stdint.h>

typedef uint64_t	u64;
typedef uint32_t	u32;
typedef uint16_t	u16;
typedef uint8_t		u8;

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

#ifndef __align_tpacket
# define __align_tpacket(x)	__attribute__((aligned(TPACKET_ALIGN(x))))
#endif

#ifndef __check_format_printf
# define __check_format_printf(pos_fmtstr, pos_fmtargs)		\
		__attribute__ ((format (printf, (pos_fmtstr), (pos_fmtargs))))
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

#ifndef constant
# define constant(x)		__builtin_constant_p(x)
#endif

#ifndef fmemset
# define fmemset		__builtin_memset
#endif

#ifndef fmemcpy
# define fmemcpy		__builtin_memcpy
#endif

#ifndef __maybe_unused
# define __maybe_unused		__attribute__ ((__unused__))
#endif

#ifndef noinline
# define noinline		__attribute__((noinline))
#endif

#ifndef __noreturn
# define __noreturn		__attribute__((noreturn))
#endif

#ifndef __hidden
# define __hidden		__attribute__((visibility("hidden")))
#endif

#ifndef __pure
# define __pure			__attribute__ ((pure))
#endif

#ifndef __force
# define __force		/* unimplemented */
#endif

/* see config_enabled et al. in linux/kconfig.h for details. */
#define __ARG_PLACEHOLDER_1 			0,
#define is_defined(cfg)				_is_defined(cfg)
#define _is_defined(value)			__is_defined(__ARG_PLACEHOLDER_##value)
#define __is_defined(arg1_or_junk)		___is_defined(arg1_or_junk 1, 0)
#define ___is_defined(__ignored, val, ...)	val

#ifndef max
# define max(a, b)							\
	({								\
		typeof (a) _a = (a);					\
		typeof (b) _b = (b);					\
		_a > _b ? _a : _b;					\
	})
#endif /* max */

#ifndef max_t
# define max_t(type, a, b)						\
	({								\
		type ___max1 = (a);					\
		type ___max2 = (b);					\
		___max1 > ___max2 ? ___max1 : ___max2;			\
	})
#endif /* max_t */

#ifndef min
# define min(a, b)							\
	({								\
		typeof (a) _a = (a);					\
		typeof (b) _b = (b);					\
		_a < _b ? _a : _b;					\
	})
#endif /* min */

#ifndef min_t
# define min_t(type, a, b)						\
	({								\
		type ___min1 = (a);					\
		type ___min2 = (b);					\
		___min1 < ___min2 ? ___min1 : ___min2;			\
	})
#endif /* min_t */

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

#ifndef build_bug_on
# define build_bug_on(e)	((void)sizeof(char[1 - 2*!!(e)]))
#endif

#ifndef bug_on
# define bug_on(cond)		assert(!(cond))
#endif

#ifndef bug
# define bug()			assert(0)
#endif

#define RUNTIME_PAGE_SIZE	(sysconf(_SC_PAGE_SIZE))
#define PAGE_MASK		(~(RUNTIME_PAGE_SIZE - 1))
#define PAGE_ALIGN(addr)	(((addr) + RUNTIME_PAGE_SIZE - 1) & PAGE_MASK)

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
#ifndef ___constant_swab16
# define ___constant_swab16(x) ((__u16)(			\
	(((__u16)(x) & (__u16)0x00ffU) << 8) |			\
	(((__u16)(x) & (__u16)0xff00U) >> 8)))
#endif
#ifndef ___constant_swab32
# define ___constant_swab32(x) ((__u32)(			\
	(((__u32)(x) & (__u32)0x000000ffUL) << 24) |		\
	(((__u32)(x) & (__u32)0x0000ff00UL) <<  8) |		\
	(((__u32)(x) & (__u32)0x00ff0000UL) >>  8) |		\
	(((__u32)(x) & (__u32)0xff000000UL) >> 24)))
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

# ifndef __constant_htonl
#  define __constant_htonl(x) ((__force __be32)___constant_swab32((x)))
# endif
# ifndef __constant_ntohl
#  define __constant_ntohl(x) ___constant_swab32((__force __be32)(x))
# endif
# ifndef __constant_htons
#  define __constant_htons(x) ((__force __be16)___constant_swab16((x)))
# endif
# ifndef __constant_ntohs
#  define __constant_ntohs(x) ___constant_swab16((__force __be16)(x))
# endif
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

# ifndef __constant_htonl
#  define __constant_htonl(x) ((__force __be32)(__u32)(x))
# endif
# ifndef __constant_ntohl
#  define __constant_ntohl(x) ((__force __u32)(__be32)(x))
# endif
# ifndef __constant_htons
#  define __constant_htons(x) ((__force __be16)(__u16)(x))
# endif
# ifndef __constant_ntohs
#  define __constant_ntohs(x) ((__force __u16)(__be16)(x))
# endif
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

#ifndef TP_STATUS_TS_SOFTWARE
# define TP_STATUS_TS_SOFTWARE		(1 << 29)
#endif

#ifndef TP_STATUS_TS_SYS_HARDWARE
# define TP_STATUS_TS_SYS_HARDWARE	(1 << 30)
#endif

#ifndef TP_STATUS_TS_RAW_HARDWARE
# define TP_STATUS_TS_RAW_HARDWARE	(1 << 31)
#endif

#ifndef PACKET_QDISC_BYPASS
# define PACKET_QDISC_BYPASS 20
#endif

#ifndef ARPHRD_IEEE802154_MONITOR
# define ARPHRD_IEEE802154_MONITOR	805
#endif

#ifndef ARPHRD_IP6GRE
# define ARPHRD_IP6GRE			823
#endif

#ifndef ARPHRD_NETLINK
# define ARPHRD_NETLINK			824
#endif

#ifndef PACKET_USER
# define PACKET_USER			6
#endif

#ifndef PACKET_KERNEL
# define PACKET_KERNEL			7
#endif

#ifndef DEFFILEMODE
# define DEFFILEMODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH) /* 0666 */
#endif

#endif /* BUILT_IN_H */

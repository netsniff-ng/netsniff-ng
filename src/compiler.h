/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef COMPILER_H
#define COMPILER_H

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
#ifndef barrier
# define barrier()          __sync_synchronize()
#endif
#ifndef bug
# define bug()              __builtin_trap()
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

#endif /* COMPILER_H */

#ifndef ASM_BYTEORDER_H
#define ASM_BYTEORDER_H

#include <machine/endian.h>
#include <libkern/OSByteOrder.h>

#ifndef bswap_16
# define bswap_16(x) OSSwapInt16(x)
# define bswap_32(x) OSSwapInt32(x)
# define bswap_64(x) OSSwapInt64(x)
#endif

/* arm64 macOS is always little endian */
#define __LITTLE_ENDIAN_BITFIELD
#ifndef __LITTLE_ENDIAN
# define __LITTLE_ENDIAN 1234
#endif
#ifndef __BIG_ENDIAN
# define __BIG_ENDIAN 4321
#endif

#endif /* ASM_BYTEORDER_H */
/* built_in.h checks __BYTE_ORDER */
#ifndef __BYTE_ORDER
# define __BYTE_ORDER    __LITTLE_ENDIAN
#endif

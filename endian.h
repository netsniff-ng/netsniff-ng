#ifndef ENDIAN_H
#define ENDIAN_H
#include <machine/endian.h>
#include <libkern/OSByteOrder.h>
#ifndef bswap_16
# define bswap_16(x) OSSwapInt16(x)
#endif
#ifndef bswap_32
# define bswap_32(x) OSSwapInt32(x)
#endif
#ifndef bswap_64
# define bswap_64(x) OSSwapInt64(x)
#endif
#endif

#ifndef IPV6_H
#define IPV6_H

#include <asm/byteorder.h>

#include "built_in.h"

/*
 * IPv6 fixed header
 *
 * BEWARE, it is incorrect. The first 4 bits of flow_lbl
 * are glued to priority now, forming "class".
 */
struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__extension__ uint8_t priority:4,
			      version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__extension__ uint8_t version:4,
			      priority:4;
#else
# error "Please fix <asm/byteorder.h>"
#endif
	uint8_t flow_lbl[3];
	uint16_t payload_len;
	uint8_t nexthdr;
	uint8_t hop_limit;
	struct in6_addr saddr;
	struct in6_addr daddr;
} __packed;

#endif /* IPV6_H */

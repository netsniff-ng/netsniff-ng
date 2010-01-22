#ifndef	__PROTO_IPV6_H__
#define __PROTO_IPV6_H__

#include <stdint.h>
#include <assert.h>
#include <netinet/in.h>
/*
 *	IPv6 fixed header
 *
 *	BEWARE, it is incorrect. The first 4 bits of flow_lbl
 *	are glued to priority now, forming "class".
 */

struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8			priority:4,
				version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8			version:4,
				priority:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8			flow_lbl[3];

	__be16			payload_len;
	__u8			nexthdr;
	__u8			hop_limit;

	struct	in6_addr	saddr;
	struct	in6_addr	daddr;
};

static inline struct ipv6hdr * get_ipv6hdr(uint8_t ** pkt, uint32_t *pkt_len)
{
	struct ipv6hdr * ipv6_header;

	assert(pkt);
	assert(*pkt);
	assert(*pkt_len > sizeof(*ipv6_header));

	ipv6_header = (struct ipv6hdr *) *pkt;

	*pkt += sizeof(*ipv6_header);
	*pkt_len -= sizeof(*ipv6_header);

	return (ipv6_header);
}

static inline uint16_t get_l4_type_from_ipv6(const struct ipv6hdr * header)
{	
	assert(header);
	return (header->nexthdr);
}

#endif	/* __PROTO_IPV6_H__ */

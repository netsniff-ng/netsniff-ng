#ifndef	__PROTO_UDP_H__
#define	__PROTO_UDP_H__

#include <stdint.h>
#include <assert.h>
#include <linux/udp.h>

static inline struct udphdr * get_udphdr(uint8_t ** pkt, uint32_t * pkt_len)
{
	struct udphdr * udp_header = NULL;

	assert(pkt);
	assert(*pkt);
	assert(*pkt_len >= sizeof(*udp_header));

	udp_header = (struct udphdr *) *pkt;

	*pkt += sizeof(*udp_header);
	*pkt_len -= sizeof(*udp_header);

	return(udp_header);
}

#endif	/* __PROTO_UDP_H__ */

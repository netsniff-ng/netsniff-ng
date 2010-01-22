#ifndef	__PROTO_ETHERNET_H__
#define __PROTO_ETHERNET_H__

#include <stdint.h>
#include <assert.h>
#include <netinet/if_ether.h>

static inline struct ethhdr * get_ethhdr(uint8_t **pkt, uint32_t * pkt_len)
{
	struct ethhdr * header;
	assert(pkt);
	assert(*pkt);
	assert(*pkt_len > ETH_HLEN);

	header = (struct ethhdr * ) *pkt;

	*pkt += ETH_HLEN;
	*pkt_len -= ETH_HLEN;

	return (header);
}

static inline uint16_t get_ethertype(const struct ethhdr *header)
{
	assert(header);
	return(ntohs(header->h_proto));
}

#endif	/* __PROTO_ETHERNET_H__ */

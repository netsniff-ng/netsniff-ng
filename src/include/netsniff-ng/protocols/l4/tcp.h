#ifndef	__PROTO_TCP_H__
#define	__PROTO_TCP_H__

#include <stdint.h>
#include <assert.h>
#include <linux/tcp.h>

static inline struct tcphdr * get_tcphdr(uint8_t ** pkt, uint32_t * pkt_len)
{
	struct tcphdr * tcp_header = NULL;

	assert(pkt);
	assert(*pkt);
	assert(*pkt_len >= sizeof(*tcp_header));

	tcp_header = (struct tcphdr *) *pkt;

	*pkt += sizeof(*tcp_header);
	*pkt_len -= sizeof(*tcp_header);

	return(tcp_header);
}

#endif	/* __PROTO_TCP_H__ */

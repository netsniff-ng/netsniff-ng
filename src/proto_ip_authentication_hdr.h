/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend <markus@netsniff-ng.org>
 * Subject to the GPL, version 2.
 *
 * IP Authentication Header described in RFC4302
 */

#ifndef PROTO_IP_AUTHENTICATION_HDR_H
#define PROTO_IP_AUTHENTICATION_HDR_H

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto_struct.h"
#include "dissector_eth.h"
#include "built_in.h"

struct auth_hdr {
	uint8_t h_next_header;
	uint8_t h_payload_len;
	uint16_t h_reserved;
	uint32_t h_spi;
	uint32_t h_snf;
} __packed;

static inline void auth_hdr(struct pkt_buff *pkt)
{
	uint16_t hdr_len;
	struct auth_hdr *auth_ops;

	auth_ops = (struct auth_hdr *) pkt_pull(pkt, sizeof(*auth_ops));
	hdr_len = (auth_ops->h_payload_len * 4) + 8;
	if (auth_ops == NULL || hdr_len > pkt_len(pkt))
		return;

	tprintf(" [ Authentication Header ");
	tprintf("NextHdr (%u), ", auth_ops->h_next_header);
	tprintf("HdrLen (%u), ", hdr_len);
	tprintf("Reserved (0x%x), ", ntohs(auth_ops->h_reserved));
	/* TODO
	 * Upgrade for Extended (64-bit) Sequence Number
	 * http://tools.ietf.org/html/rfc4302#section-2.5.1
	 */
	tprintf("SPI (0x%x), ", ntohl(auth_ops->h_spi));
	tprintf("SNF (0x%x), ", ntohl(auth_ops->h_snf));
	tprintf("ICV 0x");
	for (size_t i = sizeof(struct auth_hdr); i < hdr_len; i++)
		tprintf("%02x", *pkt_pull(pkt, 1));
	tprintf(" ]\n");

	pkt_set_proto(pkt, &eth_lay3, auth_ops->h_next_header);
}

static inline void auth_hdr_less(struct pkt_buff *pkt)
{
  	uint16_t hdr_len;
	struct auth_hdr *auth_ops;

	auth_ops = (struct auth_hdr *) pkt_pull(pkt, sizeof(*auth_ops));
	hdr_len = (auth_ops->h_payload_len * 4) + 8;
	if (auth_ops == NULL || hdr_len > pkt_len(pkt))
		return;

	tprintf(" AH");

	pkt_pull(pkt, hdr_len - sizeof(*auth_ops));
	pkt_set_proto(pkt, &eth_lay3, auth_ops->h_next_header);
}

struct protocol ip_auth_hdr_ops = {
	.key = 0x33,
	.print_full = auth_hdr,
	.print_less = auth_hdr_less,
};

#endif /* PROTO_IP_AUTHENTICATION_HDR_H */

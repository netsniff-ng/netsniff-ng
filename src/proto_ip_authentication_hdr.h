/*
 * IP Authentication Header described in RFC4302
 * programmed by Markus Amend 2012 as a contribution to
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend.
 * Subject to the GPL, version 2.
 */

#ifndef AUTHENTICATION_HEADER_H
#define AUTHENTICATION_HEADER_H

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto_struct.h"
#include "dissector_eth.h"

struct auth_hdrhdr {
	uint8_t h_next_header;
	uint8_t h_payload_len;
	uint16_t h_reserved;
	uint32_t h_spi;
	uint32_t h_snf;
} __attribute__((packed));

static inline void auth_hdr(uint8_t *packet, size_t len)
{
	uint8_t hdr_payload_len;	
	struct auth_hdrhdr *auth_hdr = (struct auth_hdrhdr *) packet;

	hdr_payload_len = (auth_hdr->h_payload_len * 4) + 8;
	if (len < hdr_payload_len || len < sizeof(struct auth_hdrhdr))
		return;

	tprintf(" [ Authentication Header ");
	tprintf("NextHdr (%u), ", auth_hdr->h_next_header);
	tprintf("HdrLen (%u), ", hdr_payload_len);
	tprintf("Reserved (0x%x), ", ntohs(auth_hdr->h_reserved));
	tprintf("SPI (0x%x), ", ntohl(auth_hdr->h_spi));
	tprintf("SNF (0x%x), ", ntohl(auth_hdr->h_snf));
	tprintf("ICV 0x");
	for (uint8_t i = sizeof(struct auth_hdrhdr); i < hdr_payload_len; i++)
		tprintf("%02x",(uint8_t) packet[i]);
	tprintf(" ]\n");
}

static inline void auth_hdr_less(uint8_t *packet, size_t len)
{
  	uint8_t hdr_payload_len;
	struct auth_hdrhdr *auth_hdr = (struct auth_hdrhdr *) packet;

	hdr_payload_len = (auth_hdr->h_payload_len * 4) + 8;
	if (len < hdr_payload_len || len < sizeof(struct auth_hdrhdr))
		return;

	tprintf(" AH");
}

static inline void auth_hdr_next(uint8_t *packet, size_t len,
				 struct hash_table **table,
				 unsigned int *key, size_t *off)
{
    	uint8_t hdr_payload_len;
	struct auth_hdrhdr *auth_hdr = (struct auth_hdrhdr *) packet;

	hdr_payload_len = (auth_hdr->h_payload_len * 4) + 8;
	if (len < hdr_payload_len || len < sizeof(struct auth_hdrhdr))
		goto invalid;

	(*off) = hdr_payload_len;
	(*key) = auth_hdr->h_next_header;
	(*table) = &eth_lay3;
	return;
invalid:
	(*off) = 0;
	(*key) = 0;
	(*table) = NULL;
}

struct protocol ip_auth_hdr_ops = {
	.key = 0x33,
	.print_full = auth_hdr,
	.print_less = auth_hdr_less,
	.print_pay_ascii = empty,
	.print_pay_hex = empty,
	.print_pay_none = auth_hdr,
	.print_all_cstyle = __hex2,
	.print_all_hex = __hex,
	.proto_next = auth_hdr_next,
};

#endif /* AUTHENTICATION_HEADER_H */

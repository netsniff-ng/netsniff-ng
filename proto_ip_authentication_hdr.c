/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend <markus@netsniff-ng.org>, Deutsche Flugsicherung GmbH
 * Subject to the GPL, version 2.
 *
 * IP Authentication Header described in RFC4302
 */

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto.h"
#include "dissector_eth.h"
#include "built_in.h"
#include "pkt_buff.h"

struct auth_hdr {
	uint8_t h_next_header;
	uint8_t h_payload_len;
	uint16_t h_reserved;
	uint32_t h_spi;
	uint32_t h_snf;
} __packed;

static void auth_hdr(struct pkt_buff *pkt)
{
	size_t i, hdr_len;
	struct auth_hdr *auth_ops;

	auth_ops = (struct auth_hdr *) pkt_pull(pkt, sizeof(*auth_ops));
	if (auth_ops == NULL)
		return;

	hdr_len = (auth_ops->h_payload_len * 4) + 8;

	tprintf(" [ Authentication Header ");
	tprintf("NextHdr (%u), ", auth_ops->h_next_header);
	if (hdr_len > pkt_len(pkt)) {
		tprintf("HdrLen (%u, %zd Bytes %s), ",
		      auth_ops->h_payload_len, hdr_len,
		      colorize_start_full(black, red)
		      "invalid" colorize_end());
		      return;
	}
	tprintf("HdrLen (%u, %zd Bytes), ",auth_ops->h_payload_len, hdr_len);
	tprintf("Reserved (0x%x), ", ntohs(auth_ops->h_reserved));
	/* TODO
	 * Upgrade for Extended (64-bit) Sequence Number
	 * http://tools.ietf.org/html/rfc4302#section-2.5.1
	 */
	tprintf("SPI (0x%x), ", ntohl(auth_ops->h_spi));
	tprintf("SNF (0x%x), ", ntohl(auth_ops->h_snf));
	tprintf("ICV 0x");
	for (i = sizeof(struct auth_hdr); i < hdr_len; i++) {
		uint8_t *data = pkt_pull(pkt, 1);

		if (data == NULL) {
			tprintf("%sinvalid%s", colorize_start_full(black, red),
				colorize_end());
			break;
		}

		tprintf("%02x", *data);
	}
	tprintf(" ]\n");

	pkt_set_proto(pkt, &eth_lay3, auth_ops->h_next_header);
}

static void auth_hdr_less(struct pkt_buff *pkt)
{
  	ssize_t hdr_len;
	struct auth_hdr *auth_ops;

	auth_ops = (struct auth_hdr *) pkt_pull(pkt, sizeof(*auth_ops));
	if (auth_ops == NULL)
		return;

	hdr_len = (auth_ops->h_payload_len * 4) + 8;
	if (hdr_len > pkt_len(pkt) || hdr_len < 0)
		return;

	tprintf(" AH");

	pkt_pull(pkt, hdr_len - sizeof(*auth_ops));
	pkt_set_proto(pkt, &eth_lay3, auth_ops->h_next_header);
}

struct protocol ip_auth_ops = {
	.key = 0x33,
	.print_full = auth_hdr,
	.print_less = auth_hdr_less,
};

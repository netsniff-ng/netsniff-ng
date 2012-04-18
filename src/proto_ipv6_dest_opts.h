/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend <markus@netsniff-ng.org>
 * Subject to the GPL, version 2.
 *
 * IPv6 Destination Options Header described in RFC2460
 */

#ifndef PROTO_IPV6_DEST_OPTS_H
#define PROTO_IPV6_DEST_OPTS_H

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto_struct.h"
#include "dissector_eth.h"
#include "built_in.h"

struct dest_optshdr {
	uint8_t h_next_header;
	uint8_t h_hdr_ext_len;
	uint8_t h_dest_option_type;
} __packed;

static inline void dest_opts(uint8_t *packet, size_t len)
{
	uint8_t hdr_ext_len;
	struct dest_optshdr *dest_opts = (struct dest_optshdr *) packet;

	hdr_ext_len = (dest_opts->h_hdr_ext_len + 1) * 8;
	if (len < hdr_ext_len || len < sizeof(struct dest_optshdr))
		return;

	tprintf("\t [ Destination Options ");
	tprintf("NextHdr (%u), ", dest_opts->h_next_header);
	tprintf("HdrExtLen (%u), ", hdr_ext_len);
	tprintf("Opt (%u), ", dest_opts->h_dest_option_type);
	tprintf("Appendix 0x");
	for (uint8_t i = sizeof(struct dest_optshdr); i < hdr_ext_len; i++)
		tprintf("%02x",(uint8_t) packet[i]);
	tprintf(" ]\n");
}

static inline void dest_opts_less(uint8_t *packet, size_t len)
{
  	uint8_t hdr_ext_len;
	struct dest_optshdr *dest_opts = (struct dest_optshdr *) packet;
	
	hdr_ext_len = (dest_opts->h_hdr_ext_len + 1) * 8;
	if (len < hdr_ext_len || len < sizeof(struct dest_optshdr))
		return;

	tprintf(" Destination Options Opt %u", dest_opts->h_dest_option_type);
}

static inline void dest_opts_next(uint8_t *packet, size_t len,
			     struct hash_table **table,
			     unsigned int *key, size_t *off)
{
    	uint8_t hdr_ext_len;	
	struct dest_optshdr *dest_opts = (struct dest_optshdr *) packet;

	hdr_ext_len = (dest_opts->h_hdr_ext_len + 1) * 8;
	if (len < hdr_ext_len || len < sizeof(struct dest_optshdr))
		return;

	(*off) = hdr_ext_len;
	(*key) = dest_opts->h_next_header;
	(*table) = &eth_lay3;
}

struct protocol ipv6_dest_opts_ops = {
	.key = 0x3C,
	.print_full = dest_opts,
	.print_less = dest_opts_less,
	.proto_next = dest_opts_next,
};

#endif /* PROTO_IPV6_DEST_OPTS_H */

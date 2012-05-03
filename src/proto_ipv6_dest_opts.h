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
	uint8_t hdr_len;
} __packed;


static inline void dissect_opt_dest(struct pkt_buff *pkt, size_t *opt_len)
{
	/* Have to been upgraded.
	 * http://tools.ietf.org/html/rfc2460#section-4.2
	 * Look also for proto_ipv6_hop_by_hop.h, it needs
	 * dissect_opt(), too.
	 */
	if (*opt_len)
		tprintf(", Option(s) recognized ");

	/* If adding dissector reduce opt_len for each using of pkt_pull
	 * to the same size.
	 */
}

static inline void dest_opts(struct pkt_buff *pkt)
{
	uint16_t hdr_ext_len;
	size_t opt_len;
	struct dest_optshdr *dest_ops;

	dest_ops = (struct dest_optshdr *) pkt_pull(pkt, sizeof(*dest_ops));

	/* Total Header Length in Bytes */
	hdr_ext_len = (dest_ops->hdr_len + 1) * 8;
	/* Options length in Bytes */
	opt_len = hdr_ext_len - sizeof(*dest_ops);
	if (dest_ops == NULL || opt_len > pkt_len(pkt))
		return;

	tprintf("\t [ Destination Options ");
	tprintf("NextHdr (%u), ", dest_ops->h_next_header);
	tprintf("HdrExtLen (%u, %u Bytes)", dest_ops->hdr_len,
		hdr_ext_len);

	dissect_opt_dest(pkt, &opt_len);

	tprintf(" ]\n");

	pkt_pull(pkt, opt_len);
	pkt_set_proto(pkt, &eth_lay3, dest_ops->h_next_header);
}

static inline void dest_opts_less(struct pkt_buff *pkt)
{
	uint16_t hdr_ext_len;
	size_t opt_len;
	struct dest_optshdr *dest_ops;

	dest_ops = (struct dest_optshdr *) pkt_pull(pkt, sizeof(*dest_ops));

	/* Total Header Length in Bytes */
	hdr_ext_len = (dest_ops->hdr_len + 1) * 8;
	/* Options length in Bytes */
	opt_len = hdr_ext_len - sizeof(*dest_ops);
	if (dest_ops == NULL || opt_len > pkt_len(pkt))
		return;

	tprintf(" Dest Ops");

	pkt_pull(pkt, opt_len);
	pkt_set_proto(pkt, &eth_lay3, dest_ops->h_next_header);
}

struct protocol ipv6_dest_opts_ops = {
	.key = 0x3C,
	.print_full = dest_opts,
	.print_less = dest_opts_less,
};

#endif /* PROTO_IPV6_DEST_OPTS_H */

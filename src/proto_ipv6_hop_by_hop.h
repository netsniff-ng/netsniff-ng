/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend <markus@netsniff-ng.org>
 * Subject to the GPL, version 2.
 *
 * IPv6 Hop-By-Hop Header described in RFC2460
 */

#ifndef PROTO_IPV6_HOP_BY_HOP_H
#define PROTO_IPV6_HOP_BY_HOP_H

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto_struct.h"
#include "dissector_eth.h"
#include "built_in.h"

struct hop_by_hophdr {
	uint8_t h_next_header;
	uint8_t hdr_len;
} __packed;

static inline void dissect_opt_hop (struct pkt_buff *pkt, size_t *opt_len)
{
	/* Have to been upgraded.
	 * http://tools.ietf.org/html/rfc2460#section-4.2
	 * Look also for proto_ipv6_dest_opts.h, it needs
	 * dissect_opt(), too.
	 */
	if (*opt_len)
		tprintf(", Option(s) recognized ");

	/* If adding dissector reduce opt_len for each using of pkt_pull
	 * to the same size.
	 */
}

static inline void hop_by_hop(struct pkt_buff *pkt)
{
	uint16_t hdr_ext_len;
	size_t opt_len;
	struct hop_by_hophdr *hop_ops;

	hop_ops = (struct hop_by_hophdr *) pkt_pull(pkt, sizeof(*hop_ops));

	/* Total Header Length in Bytes */
	hdr_ext_len = (hop_ops->hdr_len + 1) * 8;
	/* Options length in Bytes */
	opt_len = hdr_ext_len - sizeof(*hop_ops);
	if (hop_ops == NULL || opt_len > pkt_len(pkt))
		return;

	tprintf("\t [ Hop-by-Hop Options ");
	tprintf("NextHdr (%u), ", hop_ops->h_next_header);
	tprintf("HdrExtLen (%u, %u Bytes)", hop_ops->hdr_len,
		hdr_ext_len);

	dissect_opt_hop(pkt, &opt_len);

	tprintf(" ]\n");

	pkt_pull(pkt, opt_len);
	pkt_set_proto(pkt, &eth_lay3, hop_ops->h_next_header);
}

static inline void hop_by_hop_less(struct pkt_buff *pkt)
{
	uint16_t hdr_ext_len;
	size_t opt_len;
	struct hop_by_hophdr *hop_ops;

	hop_ops = (struct hop_by_hophdr *) pkt_pull(pkt, sizeof(*hop_ops));

	/* Total Header Length in Bytes */
	hdr_ext_len = (hop_ops->hdr_len + 1) * 8;
	/* Options length in Bytes */
	opt_len = hdr_ext_len - sizeof(*hop_ops);
	if (hop_ops == NULL || opt_len > pkt_len(pkt))
		return;

	tprintf(" Hop Ops");

	pkt_pull(pkt, opt_len);
	pkt_set_proto(pkt, &eth_lay3, hop_ops->h_next_header);
}

struct protocol ipv6_hop_by_hop_ops = {
	.key = 0x0,
	.print_full = hop_by_hop,
	.print_less = hop_by_hop_less,
};

#endif /* PROTO_IPV6_HOP_BY_HOP_H */

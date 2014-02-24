/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend <markus@netsniff-ng.org>, Deutsche Flugsicherung GmbH
 * Subject to the GPL, version 2.
 *
 * IPv6 Destination Options Header described in RFC2460
 */

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto.h"
#include "dissector_eth.h"
#include "built_in.h"
#include "pkt_buff.h"

struct dest_optshdr {
	uint8_t h_next_header;
	uint8_t hdr_len;
} __packed;


static void dissect_opt_dest(struct pkt_buff *pkt __maybe_unused,
			     ssize_t *opt_len)
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

static void dest_opts(struct pkt_buff *pkt)
{
	uint16_t hdr_ext_len;
	ssize_t opt_len;
	struct dest_optshdr *dest_ops;

	dest_ops = (struct dest_optshdr *) pkt_pull(pkt, sizeof(*dest_ops));
	if (dest_ops == NULL)
		return;

	/* Total Header Length in Bytes */
	hdr_ext_len = (dest_ops->hdr_len + 1) * 8;
	/* Options length in Bytes */
	opt_len = hdr_ext_len - sizeof(*dest_ops);

	tprintf("\t [ Destination Options ");
	tprintf("NextHdr (%u), ", dest_ops->h_next_header);
	if (opt_len > pkt_len(pkt) || opt_len < 0) {
	      tprintf("HdrExtLen (%u, %u Bytes, %s)", dest_ops->hdr_len,
		    hdr_ext_len, colorize_start_full(black, red)
		    "invalid" colorize_end());
		    return;
	}
	tprintf("HdrExtLen (%u, %u Bytes)", dest_ops->hdr_len,
		hdr_ext_len);

	dissect_opt_dest(pkt, &opt_len);

	tprintf(" ]\n");

	pkt_pull(pkt, opt_len);
	pkt_set_proto(pkt, &eth_lay3, dest_ops->h_next_header);
}

static void dest_opts_less(struct pkt_buff *pkt)
{
	uint16_t hdr_ext_len;
	ssize_t opt_len;
	struct dest_optshdr *dest_ops;

	dest_ops = (struct dest_optshdr *) pkt_pull(pkt, sizeof(*dest_ops));
	if (dest_ops == NULL)
		return;

	/* Total Header Length in Bytes */
	hdr_ext_len = (dest_ops->hdr_len + 1) * 8;
	/* Options length in Bytes */
	opt_len = hdr_ext_len - sizeof(*dest_ops);
	if (opt_len > pkt_len(pkt) || opt_len < 0)
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

/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend <markus@netsniff-ng.org>, Deutsche Flugsicherung GmbH
 * Subject to the GPL, version 2.
 *
 * IPv6 No Next Header described in RFC2460
 */

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto.h"
#include "dissector_eth.h"
#include "built_in.h"

static void no_next_header(struct pkt_buff *pkt __maybe_unused)
{
	/*
	 * The value 59 in the Next Header field of an IPv6 header or any
	 * extension header indicates that there is nothing following that
	 * header.  If the Payload Length field of the IPv6 header indicates the
	 * presence of octets past the end of a header whose Next Header field
	 * contains 59, those octets must be ignored, and passed on unchanged if
	 * the packet is forwarded.
	 */
	tprintf(" [ No Next Header");
	tprintf(" ]\n");
}

static void no_next_header_less(struct pkt_buff *pkt __maybe_unused)
{
	tprintf(" No Next Header");
}

struct protocol ipv6_no_next_header_ops = {
	.key = 0x3B,
	.print_full = no_next_header,
	.print_less = no_next_header_less,
};

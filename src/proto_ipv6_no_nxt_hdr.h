/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend <markus@netsniff-ng.org>
 * Subject to the GPL, version 2.
 *
 * IPv6 No Next Header described in RFC2460
 */

#ifndef PROTO_IPV6_NO_NXT_HDR_H
#define PROTO_IPV6_NO_NXT_HDR_H

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto_struct.h"
#include "dissector_eth.h"

static inline void no_next_header(struct pkt_buff *pkt)
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

static inline void no_next_header_less(struct pkt_buff *pkt)
{
	tprintf(" No Next Header");
}

struct protocol ipv6_no_next_header_ops = {
	.key = 0x3B,
	.print_full = no_next_header,
	.print_less = no_next_header_less,
};

#endif /* PROTO_IPV6_NO_NXT_HDR_H */

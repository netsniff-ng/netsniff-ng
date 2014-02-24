/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend <markus@netsniff-ng.org>, Deutsche Flugsicherung GmbH
 * Subject to the GPL, version 2.
 *
 * IPv6 in IPv4 encapsulation described in RFC3056
 */

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto.h"
#include "dissector_eth.h"
#include "built_in.h"

extern void ipv6(struct pkt_buff *pkt);
extern void ipv6_less(struct pkt_buff *pkt);

struct protocol ipv6_in_ipv4_ops = {
	.key = 0x29,
	.print_full = ipv6,
	.print_less = ipv6_less,
};

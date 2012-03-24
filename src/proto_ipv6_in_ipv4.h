/*
 * IPv6 in IPv4 encapsulation described in RFC3056
 * programmed by Markus Amend 2012 as a contribution to
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend.
 * Subject to the GPL, version 2.
 */

#ifndef IP6_IN_IP4_H
#define IP6_IN_IP4_H

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto_struct.h"
#include "dissector_eth.h"

struct protocol ipv6_in_ipv4_ops = {
	.key = 0x29,
	.print_full = ipv6,
	.print_less = ipv6_less,
	.print_pay_ascii = empty,
	.print_pay_hex = empty,
	.print_pay_none = ipv6,
	.print_all_hex = hex,
	.proto_next = ipv6_next,
};

#endif /* IP6_IN_IP4_H */

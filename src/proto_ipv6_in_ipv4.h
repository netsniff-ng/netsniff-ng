/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend <markus@netsniff-ng.org>
 * Subject to the GPL, version 2.
 *
 * IPv6 in IPv4 encapsulation described in RFC3056
 */

#ifndef PROTO_IP6_IN_IP4_H
#define PROTO_IP6_IN_IP4_H

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto_struct.h"
#include "dissector_eth.h"

struct protocol ipv6_in_ipv4_ops = {
	.key = 0x29,
	.print_full = ipv6,
	.print_less = ipv6_less,
};

#endif /* PROTO_IP6_IN_IP4_H */

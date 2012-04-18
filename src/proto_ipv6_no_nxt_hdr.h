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

static inline void no_next_header_next(uint8_t *packet, size_t len,
			     struct hash_table **table,
			     unsigned int *key, size_t *off)
{
	(*off) = 0;
	(*key) = 0;
	(*table) = NULL;
}

struct protocol ipv6_no_next_header_ops = {
	.key = 0x3B,
	.print_full = empty,
	.print_less = empty,
	.proto_next = no_next_header_next,
};

#endif /* PROTO_IPV6_NO_NXT_HDR_H */

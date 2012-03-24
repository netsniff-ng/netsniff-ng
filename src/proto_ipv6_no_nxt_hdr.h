/*
 * IPv6 No Next Header described in RFC2460
 * programmed by Markus Amend 2012 as a contribution to
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend.
 * Subject to the GPL, version 2.
 */

#ifndef NO_NEXT_HEADER_H
#define NO_NEXT_HEADER_H

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
	.print_pay_ascii = empty,
	.print_pay_hex = empty,
	.print_pay_none = empty,
	.print_all_hex = empty,
	.proto_next = no_next_header_next,
};

#endif /* NO_NEXT_HEADER_H */

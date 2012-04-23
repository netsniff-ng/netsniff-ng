/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef PROTO_NONE_H
#define PROTO_NONE_H

#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

#include "proto_struct.h"
#include "dissector_eth.h"
#include "pkt_buff.h"

static inline void none_less(struct pkt_buff *pkt)
{
	tprintf("\n");
}

struct protocol none_ops = {
	.key = 0x01,
	.print_full = hex_ascii,
	.print_less = none_less,
};

#endif /* PROTO_NONE_H */

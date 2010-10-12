/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef HEX_H
#define HEX_H

#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

#include "proto_struct.h"
#include "dissector_ethernet.h"

static inline void hex(uint8_t *packet, size_t len)
{
	size_t plen = len;
	uint8_t *buff;

	tprintf(" [ Payload hex ");
	for (buff = packet; len-- > 0; buff++)
		tprintf("%.2x ", *buff);
	tprintf("]\n");

	tprintf(" [ Payload chr ");
	for (buff = packet; plen-- > 0; buff++)
		tprintf("%c ", isprint(*buff) ? *buff : '.');
	tprintf("]\n");

	tprintf("\n");
}

static inline void hex_less(uint8_t *packet, size_t len)
{
	tprintf("\n");
}

struct protocol hex_ops = {
	.key = 0x01,
	.print_full = hex,
	.print_less = hex_less,
	.proto_next = NULL,
};

#endif /* HEX_H */

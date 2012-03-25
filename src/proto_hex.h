/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef HEX_H
#define HEX_H

#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

#include "proto_struct.h"
#include "dissector_eth.h"

static inline void hex_pay(uint8_t *packet, size_t len)
{
	size_t plen = len;
	uint8_t *buff;

	if (len == 0)
		return;
	tprintf(" [ Payload hex ");
	for (buff = packet, plen = len; plen-- > 0; buff++)
		tprintf("%.2x ", *buff);
	tprintf("]\n");
	tprintf(" [ Payload chr ");
	for (buff = packet, plen = len; plen-- > 0; buff++)
		tprintf("%c ", isprint(*buff) ? *buff : '.');
	tprintf("]\n\n");
}

static inline void hex_none_newline(uint8_t *packet, size_t len)
{
	tprintf("\n");
}

static inline void hex_hex(uint8_t *packet, size_t len)
{
	uint8_t *buff;
	tprintf("   ");
	for (buff = packet; len-- > 0; buff++)
		tprintf("%.2x ", *buff);
	tprintf("\n\n");
}

static inline void hex_all(uint8_t *packet, size_t len)
{
	hex(packet, len);
	tprintf("\n\n");
}

static inline void hex_ascii(uint8_t *packet, size_t len)
{
	uint8_t *buff;
	tprintf("   ");
	for (buff = packet; len-- > 0; buff++)
		tprintf("%c ", isprint(*buff) ? *buff : '.');
	tprintf("\n\n");
}

struct protocol hex_ops = {
	.key = 0x01,
	.offset = 0,
	.print_full = hex_pay,
	.print_less = hex_none_newline,
	.print_pay_ascii = hex_ascii,
	.print_pay_hex = hex_hex,
	.print_pay_none = hex_none_newline,
	.print_all_hex = hex_all,
	.proto_next = NULL,
};

#endif /* HEX_H */

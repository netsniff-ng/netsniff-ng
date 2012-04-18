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
#include "pkt_buff.h"

static inline void hex_pay(struct pkt_buff *pkt)
{
	unsigned int  len    = pkt_len(pkt);
	uint8_t      *packet = pkt_pull(pkt, len);
	size_t plen = len;
	uint8_t *buff;

	if (packet == NULL)
		return;

	tprintf(" [ Payload hex ");
	for (buff = packet, plen = len; plen-- > 0; buff++)
		tprintf("%.2x ", *buff);
	tprintf("]\n");
	tprintf(" [ Payload chr ");
	for (buff = packet, plen = len; plen-- > 0; buff++)
		tprintf("%c  ", isprint(*buff) ? *buff : '.');
	tprintf("]\n\n");
}

static inline void hex_none_newline(struct pkt_buff *pkt)
{
	tprintf("\n");
}

static inline void hex_hex(struct pkt_buff *pkt)
{
	tprintf("   ");
	hex(pkt);
	tprintf("\n\n");
}

static inline void hex_all(struct pkt_buff *pkt)
{
	hex(pkt);
	tprintf("\n\n");
}

static inline void hex_ascii(struct pkt_buff *pkt)
{
	uint8_t *buff;
	unsigned int len = pkt_len(pkt);

	tprintf("   ");
	for (buff = pkt_pull(pkt, len); buff && len-- > 0; buff++)
		tprintf("%c ", isprint(*buff) ? *buff : '.');
	tprintf("\n\n");
}

struct protocol hex_ops = {
	.key = 0x01,
	.print_full = hex_pay,
	.print_less = hex_none_newline,
};

#endif /* HEX_H */

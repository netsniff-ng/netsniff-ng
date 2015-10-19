/*
 * netsniff-ng - the packet sniffing beast
 * Copyright (C) 2009, 2010 Daniel Borkmann
 * Copyright (C) 2012 Christoph Jaeger <christoph@netsniff-ng.org>
 * Subject to the GPL, version 2.
 */

#ifndef PROTO_H
#define PROTO_H

#include <ctype.h>
#include <stdint.h>

#include "tprintf.h"

struct pkt_buff;

struct protocol {
	/* Needs to be filled out by user */
	const unsigned int key;
	void (*print_full)(struct pkt_buff *pkt);
	void (*print_less)(struct pkt_buff *pkt);
	/* Used by program logic */
	struct protocol *next;
	void (*process)   (struct pkt_buff *pkt);
};

extern void empty(struct pkt_buff *pkt);
extern void _hex(uint8_t *ptr, size_t len);
extern void hex(struct pkt_buff *pkt);
extern void _ascii(uint8_t *ptr, size_t len);
extern void ascii(struct pkt_buff *pkt);
extern void hex_ascii(struct pkt_buff *pkt);

#endif /* PROTO_H */

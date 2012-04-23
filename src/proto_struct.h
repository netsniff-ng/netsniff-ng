/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>.
 * Copyright (C) 2009, 2010 Daniel Borkmann
 * Copyright (C) 2012 Christoph Jaeger <christoph@netsniff-ng.org>
 * Subject to the GPL, version 2.
 */

#ifndef PROTO_H
#define PROTO_H

#include <ctype.h>
#include <stdint.h>

#include "hash.h"
#include "tprintf.h"

/* necessary forward declarations */
struct pkt_buff;
static inline unsigned int pkt_len(struct pkt_buff *pkt);
static uint8_t *pkt_pull(struct pkt_buff *pkt, unsigned int len);

struct protocol {
	/* Needs to be filled out by user */
	unsigned int key;
	void (*print_full)(struct pkt_buff *pkt);
	void (*print_less)(struct pkt_buff *pkt);
	/* Used by program logic */
	struct protocol *next;
	void (*process)   (struct pkt_buff *pkt);
};

static inline void empty(struct pkt_buff *pkt) {}

static inline void _hex(uint8_t *ptr, size_t len)
{
	if (!len)
		return;

	tprintf(" [ hex ");
	for (; ptr && len-- > 0; ptr++)
		tprintf(" %.2x", *ptr);
	tprintf(" ]\n");
}

static inline void hex(struct pkt_buff *pkt)
{
	size_t len = pkt_len(pkt);

	if (!len)
		return;

	_hex(pkt_pull(pkt, len), len);
	tprintf("\n");
}

static inline void _ascii(uint8_t *ptr, size_t len)
{
	if (!len)
		return;

	tprintf(" [ chr ");
	for (; ptr && len-- > 0; ptr++)
		tprintf(" %c ", isprint(*ptr) ? *ptr : '.');
	tprintf(" ]\n");
}

static inline void ascii(struct pkt_buff *pkt)
{
	size_t len = pkt_len(pkt);

	if (!len)
		return;

	_ascii(pkt_pull(pkt, len), len);
	tprintf("\n");
}

static inline void hex_ascii(struct pkt_buff *pkt)
{
	size_t   len = pkt_len(pkt);
	uint8_t *ptr = pkt_pull(pkt, len);

	if (!len)
		return;

	_hex(ptr, len);
	_ascii(ptr, len);
	tprintf("\n");
}

#endif /* PROTO_H */

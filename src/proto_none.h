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
#include "pkt_buff.h"

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

	if (len) {
		_hex(ptr, len);
		_ascii(ptr, len);
	}

	tprintf("\n");
}

#ifndef __without_ops
static inline void none_less(struct pkt_buff *pkt)
{
	tprintf("\n");
}

struct protocol none_ops = {
	.key = 0x01,
	.print_full = hex_ascii,
	.print_less = none_less,
};
#endif /* __without_ops */
#endif /* PROTO_NONE_H */

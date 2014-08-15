/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <stdint.h>
#include <ctype.h>

#include "proto.h"
#include "protos.h"
#include "pkt_buff.h"

void empty(struct pkt_buff *pkt __maybe_unused) {}

static void _hex(uint8_t *ptr, size_t len)
{
	if (!len)
		return;

	tprintf(" [ Hex ");
	for (; ptr && len-- > 0; ptr++)
		tprintf(" %.2x", *ptr);
	tprintf(" ]\n");
}

void hex(struct pkt_buff *pkt)
{
	size_t len = pkt_len(pkt);

	if (!len)
		return;

	_hex(pkt_pull(pkt, len), len);
	tprintf("\n");
}

static void _ascii(uint8_t *ptr, size_t len)
{
	if (!len)
		return;

	tprintf(" [ Chr ");
	for (; ptr && len-- > 0; ptr++)
		tprintf("%c", isprint(*ptr) ? *ptr : '.');
	tprintf(" ]\n");
}

void ascii(struct pkt_buff *pkt)
{
	size_t len = pkt_len(pkt);

	if (!len)
		return;

	_ascii(pkt_pull(pkt, len), len);
	tprintf("\n");
}

void hex_ascii(struct pkt_buff *pkt)
{
	size_t   len = pkt_len(pkt);
	uint8_t *ptr = pkt_pull(pkt, len);

	if (len) {
		_ascii(ptr, len);
		_hex(ptr, len);
	}

	tprintf("\n");
}

static void none_less(struct pkt_buff *pkt __maybe_unused)
{
	tprintf("\n");
}

struct protocol none_ops = {
	.key = 0x01,
	.print_full = hex_ascii,
	.print_less = none_less,
};

/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010, 2011, 2012 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "built_in.h"
#include "tprintf.h"
#include "dissector.h"
#include "dissector_eth.h"
#include "proto_struct.h"

int dissector_set_print_type(void *ptr, int type)
{
	struct protocol *proto = (struct protocol *) ptr;
	while (proto != NULL) {
		switch (type) {
		case FNTTYPE_PRINT_NORM:
			proto->process = proto->print_full;
			break;
		case FNTTYPE_PRINT_LESS:
			proto->process = proto->print_less;
			break;
		case FNTTYPE_PRINT_PAY_HEX:
			proto->process = proto->print_pay_hex;
			break;
		case FNTTYPE_PRINT_ALL_HEX:
			proto->process = proto->print_all_hex;
			break;
		case FNTTYPE_PRINT_NO_PAY:
			proto->process = proto->print_pay_none;
			break;
		case FNTTYPE_PRINT_PAY_ASCII:
			proto->process = proto->print_pay_ascii;
			break;
		default:
		case FNTTYPE_PRINT_NONE:
			proto->process = NULL;
			break;
		}
		proto = proto->next;
	}
	return 0;
}

static void dissector_main(uint8_t *packet, size_t len, struct protocol *start,
			   struct protocol *end)
{
	size_t off = 0;
	unsigned int key;
	struct hash_table *table;
	struct protocol *proto = start;
	while (proto != NULL) {
		len -= off;
		packet += off;
		if (unlikely(!proto->process))
			break;
		off = proto->offset;
		if (!off)
			off = len;
		proto->process(packet, off);
		if (unlikely(!proto->proto_next))
			break;
		off = 0;
		key = 0;
		table = NULL;
		proto->proto_next(packet, len, &table, &key, &off);
		if (unlikely(!table))
			break;
		proto = lookup_hash(key, table);
		while (proto && key != proto->key)
			proto = proto->next;
	}
	len -= off;
	packet += off;
	if (end != NULL)
		if (likely(end->process))
			end->process(packet, len);
	tprintf_flush();
}

void dissector_entry_point(uint8_t *packet, size_t len, int linktype)
{
	struct protocol *proto_start = NULL;
	struct protocol *proto_end = NULL;
	switch (linktype) {
	case LINKTYPE_EN10MB:
		proto_start = dissector_get_ethernet_entry_point();
		proto_end = dissector_get_ethernet_exit_point();
		break;
	default:
		return;
	};
	dissector_main(packet, len, proto_start, proto_end);
}

void dissector_init_all(int fnttype)
{
	dissector_init_ethernet(fnttype);
}

void dissector_cleanup_all(void)
{
	dissector_cleanup_ethernet();
}

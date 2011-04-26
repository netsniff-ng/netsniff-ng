/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "compiler.h"
#include "tprintf.h"
#include "dissector.h"
#include "dissector_eth.h"
#include "protos/proto_struct.h"

int dissector_set_print_norm(void *ptr)
{
	struct protocol *proto = (struct protocol *) ptr;
	while (proto != NULL) {
		proto->process = proto->print_full;
		proto = proto->next;
	}
	return 0;
}

int dissector_set_print_less(void *ptr)
{
	struct protocol *proto = (struct protocol *) ptr;
	while (proto != NULL) {
		proto->process = proto->print_less;
		proto = proto->next;
	}
	return 0;
}

int dissector_set_print_none(void *ptr)
{
	struct protocol *proto = (struct protocol *) ptr;
	while (proto != NULL) {
		proto->process = NULL;
		proto = proto->next;
	}
	return 0;
}

int dissector_set_print_payload(void *ptr) { return 0; }
int dissector_set_print_payload_hex(void *ptr) { return 0; }
int dissector_set_print_c_style(void *ptr) { return 0; }
int dissector_set_print_all_hex(void *ptr) { return 0; }
int dissector_set_print_no_payload(void *ptr) { return 0; }

/*
 * The main loop of the dissector. This is designed generic, so it doesn't
 * know the underlying linktype.
 */
static void dissector_main(uint8_t *packet, size_t len,
			   struct protocol *start, struct protocol *end)
{
	size_t off = 0;
	unsigned int key;
	struct hash_table *table;
	struct protocol *proto = start;

	while (proto != NULL) {
		len -= off;
		packet += off;

		if (unlikely(!proto->process))
			break; /* We've reached a silent function */

		proto->process(packet, len);
		if (unlikely(!proto->proto_next))
			break; /* We've reached an endpoint in the graph */

		proto->proto_next(packet, len, &table, &key, &off);
		if (unlikely(!table))
			break; /* Packet seems to be invalid */

		proto = lookup_hash(key, table);

		/*
		 * We traverse the hash tables bucket list in order
		 * to fetch our right proto.
		 */
		while (proto && key != proto->key)
			proto = proto->next;
	}

	/* FIXME: Offset of last proto must be added! */
	if (end != NULL)
		if (likely(end->process))
			end->process(packet, len);

	tprintf_flush();
}

/*
 * This is the entry point for the packet dissector machine. It is 
 * developed for being as generic as possible, so that other linktypes
 * can be implemented, too. Only the direct entry point functions
 * that are linktype specific are called.
 */
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

/*
 * Initialization routines for all linktypes.
 */
void dissector_init_all(int fnttype)
{
	dissector_init_ethernet(fnttype);
}

/*
 * Garbage collection routines for all linktypes.
 */
void dissector_cleanup_all(void)
{
	dissector_cleanup_ethernet();
}

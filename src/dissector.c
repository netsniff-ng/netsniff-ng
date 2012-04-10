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
#include "pkt_buff.h"
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
		default:
		case FNTTYPE_PRINT_NONE:
			proto->process = NULL;
			break;
		}
		proto = proto->next;
	}
	return 0;
}

static void dissector_main(struct pkt_buff *pkt, struct protocol *start,
			   struct protocol *end)
{
	struct protocol *proto;

	for (pkt->proto = start; pkt->proto != NULL;) {
		if (unlikely(!pkt->proto->process))
			break;
		proto = pkt->proto;
		pkt->proto = NULL;
		proto->process(pkt);
	}
	if (end != NULL)
		if (likely(end->process))
			end->process(pkt);
	tprintf_flush();
	pkt_free(pkt);
}

void dissector_entry_point(uint8_t *packet, size_t len, int linktype)
{
	struct protocol *proto_start = NULL;
	struct protocol *proto_end   = NULL;
	struct pkt_buff *pkt         = pkt_alloc(packet, len);

	switch (linktype) {
	case LINKTYPE_EN10MB:
		proto_start = dissector_get_ethernet_entry_point();
		proto_end = dissector_get_ethernet_exit_point();
		break;
	default:
		return;
	};

	if (pkt != NULL)
		dissector_main(pkt, proto_start, proto_end);
}

void dissector_init_all(int fnttype)
{
	dissector_init_ethernet(fnttype);
}

void dissector_cleanup_all(void)
{
	dissector_cleanup_ethernet();
}

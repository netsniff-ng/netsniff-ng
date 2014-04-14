/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010, 2011, 2012 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "built_in.h"
#include "tprintf.h"
#include "pkt_buff.h"
#include "proto.h"
#include "dissector.h"
#include "dissector_eth.h"
#include "dissector_80211.h"
#include "linktype.h"

int dissector_set_print_type(void *ptr, int type)
{
	struct protocol *proto;

	for (proto = ptr; proto; proto = proto->next) {
		switch (type) {
		case PRINT_NORM:
			proto->process = proto->print_full;
			break;
		case PRINT_LESS:
			proto->process = proto->print_less;
			break;
		default:
			proto->process = NULL;
			break;
		}
	}

	return 0;
}

static void dissector_main(struct pkt_buff *pkt, struct protocol *start,
			   struct protocol *end)
{
	struct protocol *proto;

	if (!start)
		return;

	for (pkt->proto = start; pkt->proto; ) {
		if (unlikely(!pkt->proto->process))
			break;

		proto = pkt->proto;
		pkt->proto = NULL;
		proto->process(pkt);
	}

	if (end && likely(end->process))
		end->process(pkt);
}

void dissector_entry_point(uint8_t *packet, size_t len, int linktype, int mode)
{
	struct protocol *proto_start, *proto_end;
	struct pkt_buff *pkt;

	if (mode == PRINT_NONE)
		return;

	pkt = pkt_alloc(packet, len);

	switch (linktype) {
	case LINKTYPE_EN10MB:
	case ___constant_swab32(LINKTYPE_EN10MB):
		proto_start = dissector_get_ethernet_entry_point();
		proto_end = dissector_get_ethernet_exit_point();
		break;
	case LINKTYPE_IEEE802_11:
	case ___constant_swab32(LINKTYPE_IEEE802_11):
		proto_start = dissector_get_ieee80211_entry_point();
		proto_end = dissector_get_ieee80211_exit_point();
		break;
	default:
		proto_start = &none_ops;
		proto_end = NULL;
		break;
	};

	dissector_main(pkt, proto_start, proto_end);

	switch (mode) {
	case PRINT_HEX:
		hex(pkt);
		break;
	case PRINT_ASCII:
		ascii(pkt);
		break;
	case PRINT_HEX_ASCII:
		hex_ascii(pkt);
		break;
	}

	tprintf_flush();
	pkt_free(pkt);
}

void dissector_init_all(int fnttype)
{
	dissector_init_ethernet(fnttype);
	dissector_init_ieee80211(fnttype);
}

void dissector_cleanup_all(void)
{
	dissector_cleanup_ethernet();
	dissector_cleanup_ieee80211();
}

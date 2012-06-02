/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2012 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */
#include <asm/byteorder.h>

#include "proto.h"
#include "protos.h"
#include "dissector_80211.h"
#include "built_in.h"
#include "pkt_buff.h"
#include "oui.h"

/* Note: Fields are encoded in little-endian! */
struct ieee80211hdr {
	union {
		u16 frame_control;
#if defined(__LITTLE_ENDIAN_BITFIELD)
		/* Correct order here ... */
		__extension__ u16 proto_version:2,
				  type:2,
				  subtype:4,
				  to_ds:1,
				  from_ds:1,
				  more_frags:1,
				  retry:1,
				  power_mgmt:1,
				  more_data:1,
				  wep:1,
				  order:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
		__extension__ u16 subtype:4,
				  type:2,
				  proto_version:2,
				  order:1,
				  wep:1,
				  more_data:1,
				  power_mgmt:1,
				  retry:1,
				  more_frags:1,
				  from_ds:1,
				  to_ds:1;
#else
# error  "Adjust your <asm/byteorder.h> defines"
#endif
	};
	u16 duration;
} __packed;

static const char *frame_control_types[] = {
	"Management",	/* 00 */
	"Control",	/* 01 */
	"Data",		/* 10 */
	"Reserved",	/* 11 */
};

static void ieee80211(struct pkt_buff *pkt)
{
	struct ieee80211hdr *hdr =
		(struct ieee80211hdr *) pkt_pull(pkt, sizeof(*hdr));
	if (hdr == NULL)
		return;

	tprintf(" [ 802.11 Frame Control (0x%04x), Duration/ID (%u) ]\n",
		le16_to_cpu(hdr->frame_control), le16_to_cpu(hdr->duration));
	tprintf("\t [ Proto Version (%u), ", hdr->proto_version);
	tprintf("Type (%u, %s), ", hdr->type, frame_control_types[hdr->type]);
	tprintf("Subtype (%u)", hdr->subtype /*XXX*/);
	tprintf("%s%s",
		hdr->to_ds ? ", Frame goes to DS" : "",
		hdr->from_ds ?  ", Frame comes from DS" : "");
	tprintf("%s", hdr->more_frags ? ", More Fragments" : "");
	tprintf("%s", hdr->retry ? ", Frame is retransmitted" : "");
	tprintf("%s", hdr->power_mgmt ? ", In Power Saving Mode" : "");
	tprintf("%s", hdr->more_data ? ", More Data" : "");
	tprintf("%s", hdr->wep ? ", Needs WEP" : "");
	tprintf("%s", hdr->order ? ", Order" : "");
	tprintf(" ]\n");

//	pkt_set_proto(pkt, &ieee802_lay2, ntohs(eth->h_proto));
}

static void ieee80211_less(struct pkt_buff *pkt)
{
	tprintf("802.11 frame (more on todo)");
}

struct protocol ieee80211_ops = {
	.key = 0,
	.print_full = ieee80211,
	.print_less = ieee80211_less,
};

EXPORT_SYMBOL(ieee80211_ops);

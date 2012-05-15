/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <stdint.h>

#include "proto.h"
#include "protos.h"
#include "dissector_80211.h"
#include "built_in.h"
#include "pkt_buff.h"
#include "oui.h"

struct ieee80211hdr {
	u16 frame_control;
	u16 duration;
/*	u8 da[6];
	u8 sa[6];
	u8 bssid[6];
	u16 seq_ctrl;*/
} __packed;

/* TODO: fix lots of things analyze frame control */
/* this is really just a simple start */
/* FIXME: duration, sequence number, addresses... */
/* Look @:
 * http://www.rhyshaden.com/wireless.htm
 * http://technet.microsoft.com/en-us/library/cc757419(v=ws.10).aspx
 * http://www.ieee802.org/
 * PHY Sublayer (FH, DSSS etc) is not relevant, because it's physical :-)
 *
 * How to make sure which protocol is included (in unencrypted mode)? Only
 * IPv4/6?
 */

static void ieee80211(struct pkt_buff *pkt)
{
	struct ieee80211hdr *hdr =
		(struct ieee80211hdr *) pkt_pull(pkt, sizeof(*hdr));
	if (hdr == NULL)
		return;

	tprintf(" [ 802.11 ");
	/* FIXME: See above */
	/*tprintf("MAC (%.2x:%.2x:%.2x:%.2x:%.2x:%.2x => ",
		hdr->sa[0], hdr->sa[1], hdr->sa[2],
		hdr->sa[3], hdr->sa[4], hdr->sa[5]);
	tprintf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x via BSSID ",
		hdr->da[0], hdr->da[1], hdr->da[2],
		hdr->da[3], hdr->da[4], hdr->da[5]);
	tprintf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x), ",
		hdr->bssid[0], hdr->bssid[1], hdr->bssid[2],
		hdr->bssid[3], hdr->bssid[4], hdr->bssid[5]);*/
	tprintf("Frame Control (%x), Duration (%x)",
		hdr->frame_control, hdr->duration);
	tprintf(" ]\n");

	/*tprintf(" [ BSS Vendor ");
	tprintf("(%s)", lookup_vendor((hdr->bssid[0] << 16) |
				      (hdr->bssid[1] << 8) | hdr->bssid[2]));
	tprintf(" ]\n");*/

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

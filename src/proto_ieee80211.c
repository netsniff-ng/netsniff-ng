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
#include "pkt_buff.h"
#include "oui.h"

struct ieee80211hdr {
	u16 frame_control;
	u16 duration;
	u8 da[6];
	u8 sa[6];
	u8 bssid[6];
	u16 seq_ctrl;
};

/* TODO: fix lots of things analyze frame control */
/* this is really just a simple start */

static void ieee80211(struct pkt_buff *pkt)
{
	struct ieee80211hdr *hdr =
		(struct ieee80211hdr *) pkt_pull(pkt, sizeof(*hdr));
	if (hdr == NULL)
		return;

	tprintf(" [ 802.11 ");
	tprintf("MAC (%.2x:%.2x:%.2x:%.2x:%.2x:%.2x => ",
		hdr->sa[0], hdr->sa[1], hdr->sa[2],
		hdr->sa[3], hdr->sa[4], hdr->sa[5]);
	tprintf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x via BSSID ",
		hdr->da[0], hdr->da[1], hdr->da[2],
		hdr->da[3], hdr->da[4], hdr->da[5]);
	tprintf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x), ",
		hdr->bssid[0], hdr->bssid[1], hdr->bssid[2],
		hdr->bssid[3], hdr->bssid[4], hdr->bssid[5]);
	tprintf("Frame Control (%x), Duration (%x), SeqCtrl (%x)",
		hdr->frame_control, hdr->duration, hdr->seq_ctrl);
	tprintf(" ]\n");

	tprintf(" [ Vendor ");
	tprintf("(%s => %s)",
		lookup_vendor((hdr->sa[0] << 16) | (hdr->sa[1] << 8) | hdr->sa[2]),
		lookup_vendor((hdr->da[0] << 16) | (hdr->da[1] << 8) | hdr->da[2]));
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

/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef DISSECTOR_H
#define DISSECTOR_H

#include <stdlib.h>
#include <stdint.h>

#include "ring.h"
#include "tprintf.h"

#define LINKTYPE_NULL       	0	/* BSD loopback encapsulation */
#define LINKTYPE_EN10MB     	1	/* Ethernet (10Mb) */
#define LINKTYPE_EN3MB      	2	/* Experimental Ethernet (3Mb) */
#define LINKTYPE_AX25      	3	/* Amateur Radio AX.25 */
#define LINKTYPE_PRONET     	4	/* Proteon ProNET Token Ring */
#define LINKTYPE_CHAOS      	5	/* Chaos */
#define LINKTYPE_IEEE802    	6	/* 802.5 Token Ring */
#define LINKTYPE_ARCNET     	7	/* ARCNET, with BSD-style header */
#define LINKTYPE_SLIP       	8	/* Serial Line IP */
#define LINKTYPE_PPP        	9	/* Point-to-point Protocol */
#define LINKTYPE_FDDI      	10	/* FDDI */
#define LINKTYPE_IEEE802_11	105	/* IEEE 802.11 wireless */

#define PRINT_NORM	0
#define PRINT_LESS	1
#define PRINT_HEX	2
#define PRINT_ASCII	3
#define PRINT_HEX_ASCII 4
#define PRINT_NONE	5

extern void dissector_init_all(int fnttype);
extern void dissector_entry_point(uint8_t *packet, size_t len, int linktype, int mode);
extern void dissector_cleanup_all(void);
extern int dissector_set_print_type(void *ptr, int type);

static char *packet_types[]={
	"<", /* Incoming */
	"B", /* Broadcast */
	"M", /* Multicast */
	"P", /* Promisc */
	">", /* Outgoing */
	"?", /* Unknown */
};

static inline void show_frame_hdr(struct frame_map *hdr, int mode,
				  enum ring_mode rmode)
{
	if (mode == PRINT_NONE)
		return;

	switch (mode) {
	case PRINT_LESS:
		if (rmode == RING_MODE_INGRESS) {
			tprintf("%s %d %u",
				packet_types[hdr->s_ll.sll_pkttype],
				hdr->s_ll.sll_ifindex, hdr->tp_h.tp_len);
		} else {
			tprintf("%u ", hdr->tp_h.tp_len);
		}
		break;
	case PRINT_NORM:
	case PRINT_HEX:
	case PRINT_ASCII:
	case PRINT_HEX_ASCII:
	default:
		if (rmode == RING_MODE_INGRESS) {
			tprintf("%s %d %u %us.%uns\n",
				packet_types[hdr->s_ll.sll_pkttype],
				hdr->s_ll.sll_ifindex, hdr->tp_h.tp_len,
				hdr->tp_h.tp_sec, hdr->tp_h.tp_nsec);
		} else {
			tprintf("%u %us.%uns\n", hdr->tp_h.tp_len,
				hdr->tp_h.tp_sec, hdr->tp_h.tp_nsec);
		}
		break;
	}
}

#endif /* DISSECTOR_H */

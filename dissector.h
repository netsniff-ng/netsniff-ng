/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009 - 2013 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef DISSECTOR_H
#define DISSECTOR_H

#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if.h>

#include "ring.h"
#include "tprintf.h"
#include "pcap_io.h"
#include "built_in.h"

#define PRINT_NORM		0
#define PRINT_LESS		1
#define PRINT_HEX		2
#define PRINT_ASCII		3
#define PRINT_HEX_ASCII		4
#define PRINT_NONE		5

extern char *if_indextoname(unsigned ifindex, char *ifname);

static const char * const packet_types[256] = {
	[PACKET_HOST]		=	"<", /* Incoming */
	[PACKET_BROADCAST]	=	"B", /* Broadcast */
	[PACKET_MULTICAST]	=	"M", /* Multicast */
	[PACKET_OTHERHOST]	=	"P", /* Promisc */
	[PACKET_OUTGOING]	=	">", /* Outgoing */
					"?", /* Unknown */
};

static inline const char *__show_ts_source(uint32_t status)
{
	if (status & TP_STATUS_TS_RAW_HARDWARE)
		return "(raw hw ts)";
	else if (status & TP_STATUS_TS_SYS_HARDWARE)
		return "(sys hw ts)";
	else if (status & TP_STATUS_TS_SOFTWARE)
		return "(sw ts)";
	else
		return "";
}

static inline void __show_frame_hdr(struct sockaddr_ll *s_ll,
				    void *raw, int mode, bool v3)
{
	char tmp[IFNAMSIZ];
	union tpacket_uhdr hdr;

	if (mode == PRINT_NONE)
		return;

	hdr.raw = raw;
	switch (mode) {
	case PRINT_LESS:
		tprintf("%s %s %u",
			packet_types[s_ll->sll_pkttype] ? : "?",
			if_indextoname(s_ll->sll_ifindex, tmp) ? : "?",
			v3 ? hdr.h3->tp_len : hdr.h2->tp_len);
		break;
	default:
		tprintf("%s %s %u %us.%uns %s\n",
			packet_types[s_ll->sll_pkttype] ? : "?",
			if_indextoname(s_ll->sll_ifindex, tmp) ? : "?",
			v3 ? hdr.h3->tp_len : hdr.h2->tp_len,
			v3 ? hdr.h3->tp_sec : hdr.h2->tp_sec,
			v3 ? hdr.h3->tp_nsec : hdr.h2->tp_nsec,
			v3 ? "" : __show_ts_source(hdr.h2->tp_status));
		break;
	}
}

static inline void show_frame_hdr(struct frame_map *hdr, int mode)
{
	__show_frame_hdr(&hdr->s_ll, &hdr->tp_h, mode, false);
}

extern void dissector_init_all(int fnttype);
extern void dissector_entry_point(uint8_t *packet, size_t len, int linktype, int mode);
extern void dissector_cleanup_all(void);
extern int dissector_set_print_type(void *ptr, int type);

#endif /* DISSECTOR_H */

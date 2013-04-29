/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009 - 2013 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef DISSECTOR_H
#define DISSECTOR_H

#include <stdlib.h>
#include <stdint.h>

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

static const char * const packet_types[256]={
	"<", /* Incoming */
	"B", /* Broadcast */
	"M", /* Multicast */
	"P", /* Promisc */
	">", /* Outgoing */
	"?", /* Unknown */
};

extern char *if_indextoname(unsigned ifindex, char *ifname);

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

static inline void show_frame_hdr(struct frame_map *hdr, int mode)
{
	char tmp[IFNAMSIZ];

	if (mode == PRINT_NONE)
		return;

	switch (mode) {
	case PRINT_LESS:
		tprintf("%s %s %u",
			packet_types[hdr->s_ll.sll_pkttype] ? : "?",
			if_indextoname(hdr->s_ll.sll_ifindex, tmp) ? : "?",
			hdr->tp_h.tp_len);
		break;
	default:
		tprintf("%s %s %u %us.%uns %s\n",
			packet_types[hdr->s_ll.sll_pkttype] ? : "?",
			if_indextoname(hdr->s_ll.sll_ifindex, tmp) ? : "?",
			hdr->tp_h.tp_len, hdr->tp_h.tp_sec,
			hdr->tp_h.tp_nsec,
			__show_ts_source(hdr->tp_h.tp_status));
		break;
	}
}

extern void dissector_init_all(int fnttype);
extern void dissector_entry_point(uint8_t *packet, size_t len, int linktype, int mode);
extern void dissector_cleanup_all(void);
extern int dissector_set_print_type(void *ptr, int type);

#endif /* DISSECTOR_H */

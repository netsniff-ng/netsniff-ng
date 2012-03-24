/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef RING_H
#define RING_H

/*
 * "I love the smell of 10GbE in the morning. Smells like ... victory."
 *     - W. Richard Stevens, "Secret Teachings of the UNIX Environment"
 */

#include <stdio.h>
#include <stdint.h>
#include <linux/if_packet.h>

#include "xsys.h"
#include "tprintf.h"
#include "dissector.h"
#include "built_in.h"
#include "mtrand.h"

#define RING_SIZE_FALLBACK (1 << 26)

static char *packet_types[]={
	"<", /* Incoming */
	"B", /* Broadcast */
	"M", /* Multicast */
	"P", /* Promisc */
	">", /* Outgoing */
	"?", /* Unknown */
};

struct frame_map {
	struct tpacket_hdr tp_h __attribute__((aligned(TPACKET_ALIGNMENT)));
	struct sockaddr_ll s_ll __attribute__((aligned(TPACKET_ALIGNMENT)));
};

struct ring {
	struct iovec *frames;
	struct tpacket_req layout;
	struct sockaddr_ll s_ll;
	uint8_t *mm_space;
	size_t mm_len;
} __cacheline_aligned;

static inline void next_slot(unsigned int *it, struct ring *ring)
{
	*it = (*it + 1);
	if (*it >= ring->layout.tp_frame_nr)
		*it = 0;
}

static inline void next_rnd_slot(unsigned int *it, struct ring *ring)
{
	*it = mt_rand_int32() % ring->layout.tp_frame_nr;
}

static inline unsigned int ring_size(char *ifname, unsigned int size)
{
	if (size > 0)
		return size;

	/*
	 * Device bitrate in bytes times two as ring size.
	 *    Fallback => ~    64,00 MB
	 *     10 MBit => ~     2,38 MB
	 *     54 MBit => ~    12,88 MB
	 *    100 MBit => ~    23,84 MB
	 *    300 MBit => ~    71,52 MB
	 *  1.000 MBit => ~   238,42 MB
	 * 10.000 MBit => ~ 2.384.18 MB
	 */
	size = device_bitrate(ifname);
	size = (size * 1000000) / 8;
	size = size * 2;
	if (size == 0)
		size = RING_SIZE_FALLBACK;

	return size;
}

enum ring_mode {
	RING_MODE_EGRESS,
	RING_MODE_INGRESS,
};

static inline void show_frame_hdr(struct frame_map *hdr, int mode,
				  enum ring_mode rmode)
{
	if (mode == FNTTYPE_PRINT_NONE)
		return;
	switch (mode) {
	case FNTTYPE_PRINT_PAAC:
	case FNTTYPE_PRINT_NOPA:
	case FNTTYPE_PRINT_HEX1:
	case FNTTYPE_PRINT_HEX2:
	case FNTTYPE_PRINT_NORM:
	default:
		if (rmode == RING_MODE_INGRESS) {
			tprintf("%s %u %u %u.%06u\n",
				packet_types[hdr->s_ll.sll_pkttype],
				hdr->s_ll.sll_ifindex, hdr->tp_h.tp_len,
				hdr->tp_h.tp_sec, hdr->tp_h.tp_usec);
		} else {
			tprintf("%u %u.%06u\n", hdr->tp_h.tp_len,
				hdr->tp_h.tp_sec, hdr->tp_h.tp_usec);
		}
		break;
	case FNTTYPE_PRINT_LESS:
		if (rmode == RING_MODE_INGRESS) {
			tprintf("%s %u %u",
				packet_types[hdr->s_ll.sll_pkttype],
				hdr->s_ll.sll_ifindex, hdr->tp_h.tp_len);
		} else {
			tprintf("%u ", hdr->tp_h.tp_len);
		}
		break;
	}
}

static inline unsigned int ring_frame_size(struct ring *ring)
{
	return ring->layout.tp_frame_size;
}

static inline void tpacket_hdr_clone(struct tpacket_hdr *thdr_d,
				     struct tpacket_hdr *thdr_s)
{
        thdr_d->tp_sec = thdr_s->tp_sec;
        thdr_d->tp_usec = thdr_s->tp_usec;
        thdr_d->tp_snaplen = thdr_s->tp_snaplen;
        thdr_d->tp_len = thdr_s->tp_len;
}

#endif /* RING_H */

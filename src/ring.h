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
#include "built_in.h"
#include "mtrand.h"

struct frame_map {
	struct tpacket_hdr tp_h __aligned_tpacket;
	struct sockaddr_ll s_ll __aligned_tpacket;
};

struct ring {
	struct iovec *frames __cacheline_aligned;
	uint8_t *mm_space __cacheline_aligned;
	size_t mm_len;
	struct tpacket_req layout;
	struct sockaddr_ll s_ll;
};

static inline void next_slot(unsigned int *it, struct ring *ring)
{
	(*it)++;
	atomic_cmp_swp(it, ring->layout.tp_frame_nr, 0);
}

static inline void next_rnd_slot(unsigned int *it, struct ring *ring)
{
	*it = mt_rand_int32() % ring->layout.tp_frame_nr;
}

#define RING_SIZE_FALLBACK (1 << 26)

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

static inline unsigned int ring_frame_size(struct ring *ring)
{
	return ring->layout.tp_frame_size;
}

static inline void tpacket_hdr_clone(struct tpacket_hdr *thdrd,
				     struct tpacket_hdr *thdrs)
{
        thdrd->tp_sec = thdrs->tp_sec;
        thdrd->tp_usec = thdrs->tp_usec;
        thdrd->tp_snaplen = thdrs->tp_snaplen;
        thdrd->tp_len = thdrs->tp_len;
}

#endif /* RING_H */

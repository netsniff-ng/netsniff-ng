/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef RX_RING_H
#define RX_RING_H

#include "ring.h"
#include "built_in.h"

extern void destroy_rx_ring(int sock, struct ring *ring);
extern void create_rx_ring(int sock, struct ring *ring);
extern void mmap_rx_ring(int sock, struct ring *ring);
extern void alloc_rx_ring_frames(struct ring *ring);
extern void bind_rx_ring(int sock, struct ring *ring, int ifindex);
extern void setup_rx_ring_layout(int sock, struct ring *ring,
				 unsigned int size, int jumbo_support);

static inline int user_may_pull_from_rx(struct tpacket_hdr *hdr)
{
	return ((hdr->tp_status & TP_STATUS_USER) == TP_STATUS_USER);
}

static inline void kernel_may_pull_from_rx(struct tpacket_hdr *hdr)
{
	hdr->tp_status = TP_STATUS_KERNEL;
}

#endif /* RX_RING_H */

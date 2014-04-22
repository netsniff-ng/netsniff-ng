/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef RX_RING_H
#define RX_RING_H

#include <stdbool.h>

#include "ring.h"

extern void destroy_rx_ring(int sock, struct ring *ring);
extern void create_rx_ring(int sock, struct ring *ring, int verbose);
extern void mmap_rx_ring(int sock, struct ring *ring);
extern void alloc_rx_ring_frames(int sock, struct ring *ring);
extern void bind_rx_ring(int sock, struct ring *ring, int ifindex);
extern void setup_rx_ring_layout(int sock, struct ring *ring,
				 unsigned int size, bool jumbo_support, bool v3);
extern void sock_rx_net_stats(int sock, unsigned long seen);

static inline int user_may_pull_from_rx(struct tpacket2_hdr *hdr)
{
	return ((hdr->tp_status & TP_STATUS_USER) == TP_STATUS_USER);
}

static inline int user_may_pull_from_rx_block(struct block_desc *pbd)
{
	return ((pbd->h1.block_status & TP_STATUS_USER) == TP_STATUS_USER);
}

static inline void kernel_may_pull_from_rx(struct tpacket2_hdr *hdr)
{
	hdr->tp_status = TP_STATUS_KERNEL;
}

static inline void kernel_may_pull_from_rx_block(struct block_desc *pbd)
{
	pbd->h1.block_status = TP_STATUS_KERNEL;
}

#endif /* RX_RING_H */

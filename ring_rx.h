/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef RX_RING_H
#define RX_RING_H

#include <stdbool.h>

#include "ring.h"

extern void ring_rx_setup(struct ring *ring, int sock, size_t size, int ifindex,
			  struct pollfd *poll, bool v3, bool jumbo_support,
			  bool verbose);
extern void destroy_rx_ring(int sock, struct ring *ring);
extern void sock_rx_net_stats(int sock, unsigned long seen);

static inline int user_may_pull_from_rx(struct tpacket2_hdr *hdr)
{
	return ((hdr->tp_status & TP_STATUS_USER) == TP_STATUS_USER);
}

static inline void kernel_may_pull_from_rx(struct tpacket2_hdr *hdr)
{
	hdr->tp_status = TP_STATUS_KERNEL;
}

#ifdef HAVE_TPACKET3
static inline int user_may_pull_from_rx_block(struct block_desc *pbd)
{
	return ((pbd->h1.block_status & TP_STATUS_USER) == TP_STATUS_USER);
}

static inline void kernel_may_pull_from_rx_block(struct block_desc *pbd)
{
	pbd->h1.block_status = TP_STATUS_KERNEL;
}
#endif /* HAVE_TPACKET3 */

#endif /* RX_RING_H */

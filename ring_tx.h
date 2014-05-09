/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef TX_RING_H
#define TX_RING_H

#include <stdbool.h>

#include "ring.h"

/* Give userland 10 us time to push packets to the ring */
#define TX_KERNEL_PULL_INT	10

void ring_tx_setup(struct ring *ring, int sock, size_t size, int ifindex,
		   bool jumbo_support, bool verbose);
extern void destroy_tx_ring(int sock, struct ring *ring);

static inline int user_may_pull_from_tx(struct tpacket2_hdr *hdr)
{
	return !(hdr->tp_status & (TP_STATUS_SEND_REQUEST | TP_STATUS_SENDING));
}

static inline void kernel_may_pull_from_tx(struct tpacket2_hdr *hdr)
{
	hdr->tp_status = TP_STATUS_SEND_REQUEST;
}

static inline int pull_and_flush_tx_ring(int sock)
{
	return sendto(sock, NULL, 0, MSG_DONTWAIT, NULL, 0);
}

static inline int pull_and_flush_tx_ring_wait(int sock)
{
	return sendto(sock, NULL, 0, 0, NULL, 0);
}

#endif /* TX_RING_H */

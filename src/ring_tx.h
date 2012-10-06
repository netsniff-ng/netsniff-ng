/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef TX_RING_H
#define TX_RING_H

#include "ring.h"
#include "built_in.h"

/* Give userland 10 us time to push packets to the ring */
#define TX_KERNEL_PULL_INT	10

extern void destroy_tx_ring(int sock, struct ring *ring);
extern void create_tx_ring(int sock, struct ring *ring, int verbose);
extern void mmap_tx_ring(int sock, struct ring *ring);
extern void alloc_tx_ring_frames(struct ring *ring);
extern void bind_tx_ring(int sock, struct ring *ring, int ifindex);
extern void setup_tx_ring_layout(int sock, struct ring *ring,
				 unsigned int size, int jumbo_support);
extern void set_packet_loss_discard(int sock);

static inline int user_may_pull_from_tx(struct tpacket2_hdr *hdr)
{
	return ((hdr->tp_status & TP_STATUS_AVAILABLE) == TP_STATUS_AVAILABLE);
}

static inline void kernel_may_pull_from_tx(struct tpacket2_hdr *hdr)
{
	hdr->tp_status = TP_STATUS_SEND_REQUEST;
}

static inline int pull_and_flush_tx_ring(int sock)
{
	return sendto(sock, NULL, 0, MSG_DONTWAIT, NULL, 0);
}

#endif /* TX_RING_H */

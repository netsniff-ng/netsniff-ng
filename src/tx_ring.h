/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef TX_RING_H
#define TX_RING_H

#include <linux/version.h>

#include "ring.h"
#include "compiler.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
# define HAVE_TX_RING
#else
# undef HAVE_TX_RING
# error "Your kernel is too old! No TX_RING available!"
#endif /* LINUX_VERSION_CODE */

#ifdef HAVE_TX_RING
#define TX_KERNEL_PULL_INT 10

extern void destroy_tx_ring(int sock, struct ring *ring);
extern void create_tx_ring(int sock, struct ring *ring);
extern void mmap_tx_ring(int sock, struct ring *ring);
extern void alloc_tx_ring_frames(struct ring *ring);
extern void bind_tx_ring(int sock, struct ring *ring, int ifindex);
extern void setup_tx_ring_layout(int sock, struct ring *ring,
				 unsigned int size);
extern void set_packet_loss_discard(int sock);
extern int pull_and_flush_tx_ring(int sock);

static inline int user_may_pull_from_tx(struct tpacket_hdr *hdr)
{
	return (hdr->tp_status == TP_STATUS_AVAILABLE);
}

static inline void kernel_may_pull_from_tx(struct tpacket_hdr *hdr)
{
	barrier();
	hdr->tp_status = TP_STATUS_SEND_REQUEST;
}
#endif /* HAVE_TX_RING */

#endif /* TX_RING_H */

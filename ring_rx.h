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
			  bool verbose, uint32_t fanout_group, uint32_t fanout_type);
extern void destroy_rx_ring(int sock, struct ring *ring);
extern int get_rx_net_stats(int sock, uint64_t *packets, uint64_t *drops, bool v3);

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

/* Fanout types. */

#ifndef PACKET_FANOUT_HASH
# define PACKET_FANOUT_HASH		0
#endif

#ifndef PACKET_FANOUT_LB
# define PACKET_FANOUT_LB		1
#endif

#ifndef PACKET_FANOUT_CPU
# define PACKET_FANOUT_CPU		2
#endif

#ifndef PACKET_FANOUT_ROLLOVER
# define PACKET_FANOUT_ROLLOVER		3
#endif

#ifndef PACKET_FANOUT_RND
# define PACKET_FANOUT_RND		4
#endif

#ifndef PACKET_FANOUT_QM
# define PACKET_FANOUT_QM		5
#endif

#ifndef PACKET_FANOUT_FLAG_ROLLOVER
# define PACKET_FANOUT_FLAG_ROLLOVER	0x1000
#endif

#ifndef PACKET_FANOUT_FLAG_DEFRAG
# define PACKET_FANOUT_FLAG_DEFRAG	0x8000
#endif

#endif /* RX_RING_H */

/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010 Daniel Borkmann.
 * Copyright 2009, 2010 Emmanuel Roullit.
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>

#include "die.h"
#include "xmalloc.h"
#include "ring_tx.h"
#include "built_in.h"

static void set_packet_loss_discard(int sock)
{
	int ret, discard = 1;
	ret = setsockopt(sock, SOL_PACKET, PACKET_LOSS, (void *) &discard,
			 sizeof(discard));
	if (ret < 0)
		panic("setsockopt: cannot set packet loss");
}

void destroy_tx_ring(int sock, struct ring *ring)
{
	int ret;

	munmap(ring->mm_space, ring->mm_len);
	ring->mm_len = 0;

	fmemset(&ring->layout, 0, sizeof(ring->layout));
	ret = setsockopt(sock, SOL_PACKET, PACKET_TX_RING, &ring->layout,
			 sizeof(ring->layout));
	if (unlikely(ret))
		panic("Cannot destroy the TX_RING: %s!\n", strerror(errno));

	xfree(ring->frames);
}

static void setup_tx_ring_layout(int sock, struct ring *ring, size_t size,
				 bool jumbo_support)
{
	fmemset(&ring->layout, 0, sizeof(ring->layout));

	ring->layout.tp_block_size = (jumbo_support ?
				      RUNTIME_PAGE_SIZE << 4 :
				      RUNTIME_PAGE_SIZE << 2);

	ring->layout.tp_frame_size = (jumbo_support ?
				      TPACKET_ALIGNMENT << 12 :
				      TPACKET_ALIGNMENT << 7);

	ring->layout.tp_block_nr = size / ring->layout.tp_block_size;
	ring->layout.tp_frame_nr = ring->layout.tp_block_size /
				   ring->layout.tp_frame_size *
				   ring->layout.tp_block_nr;

	set_sockopt_tpacket_v2(sock);

	ring_verify_layout(ring);
}

static void create_tx_ring(int sock, struct ring *ring, bool verbose)
{
	int ret;
retry:
	ret = setsockopt(sock, SOL_PACKET, PACKET_TX_RING, &ring->layout,
			 sizeof(ring->layout));

	if (errno == ENOMEM && ring->layout.tp_block_nr > 1) {
		ring->layout.tp_block_nr >>= 1;
		ring->layout.tp_frame_nr = ring->layout.tp_block_size / 
					   ring->layout.tp_frame_size * 
					   ring->layout.tp_block_nr;
		goto retry;
	}

	if (ret < 0)
		panic("Cannot allocate TX_RING!\n");

	ring->mm_len = (size_t) ring->layout.tp_block_size * ring->layout.tp_block_nr;

	if (verbose) {
		printf("TX,V2: %.2Lf MiB, %u Frames, each %u Byte allocated\n",
		       (long double) ring->mm_len / (1 << 20),
		       ring->layout.tp_frame_nr, ring->layout.tp_frame_size);
	}
}

static void alloc_tx_ring_frames(int sock __maybe_unused, struct ring *ring)
{
	alloc_ring_frames_generic(ring, ring->layout.tp_frame_nr,
				  ring->layout.tp_frame_size);
}

void ring_tx_setup(struct ring *ring, int sock, size_t size, int ifindex,
		   bool jumbo_support, bool verbose)
{
	fmemset(ring, 0, sizeof(*ring));
	set_packet_loss_discard(sock);
	setup_tx_ring_layout(sock, ring, size, jumbo_support);
	create_tx_ring(sock, ring, verbose);
	mmap_ring_generic(sock, ring);
	alloc_tx_ring_frames(sock, ring);
	bind_ring_generic(sock, ring, ifindex, true);
}

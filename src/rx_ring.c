/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>

#include "xmalloc.h"
#include "die.h"
#include "rx_ring.h"

void destroy_rx_ring(int sock, struct ring *ring)
{
	memset(&ring->layout, 0, sizeof(ring->layout));
	setsockopt(sock, SOL_PACKET, PACKET_RX_RING, &ring->layout,
		   sizeof(ring->layout));

	munmap(ring->mm_space, ring->mm_len);
	ring->mm_len = 0;

	xfree(ring->frames);
}

void setup_rx_ring_layout(int sock, struct ring *ring, unsigned int size)
{
	memset(&ring->layout, 0, sizeof(ring->layout));
	ring->layout.tp_block_size = getpagesize() << 2;
	ring->layout.tp_frame_size = TPACKET_ALIGNMENT << 10;
	ring->layout.tp_block_nr = size / ring->layout.tp_block_size;
	ring->layout.tp_frame_nr = ring->layout.tp_block_size /
				   ring->layout.tp_frame_size *
				   ring->layout.tp_block_nr;

	assert(ring->layout.tp_block_size >= ring->layout.tp_frame_size);
	assert((ring->layout.tp_block_size % ring->layout.tp_frame_size) == 0);
}

void create_rx_ring(int sock, struct ring *ring)
{
	int ret;
retry:
	ret = setsockopt(sock, SOL_PACKET, PACKET_RX_RING, &ring->layout,
			 sizeof(ring->layout));
	if (errno == ENOMEM && ring->layout.tp_block_nr > 1) {
		ring->layout.tp_block_nr >>= 1;
		ring->layout.tp_frame_nr = ring->layout.tp_block_size / 
					   ring->layout.tp_frame_size * 
					   ring->layout.tp_block_nr;
		goto retry;
	}

	if (ret < 0)
		error_and_die(EXIT_FAILURE, "Cannot allocate RX_RING!\n");

	ring->mm_len = ring->layout.tp_block_size * ring->layout.tp_block_nr;

	printf("RX: %.2f MB, %u Frames each %u Byte allocated\n",
	       1.f * ring->mm_len / (1 << 20),
	       ring->layout.tp_frame_nr, ring->layout.tp_frame_size);
}

void mmap_rx_ring(int sock, struct ring *ring)
{
	ring->mm_space = mmap(0, ring->mm_len, PROT_READ | PROT_WRITE,
			      MAP_SHARED, sock, 0);
	if (ring->mm_space == MAP_FAILED) {
		destroy_rx_ring(sock, ring);
		error_and_die(EXIT_FAILURE, "Cannot mmap RX_RING!\n");
	}
}

void alloc_rx_ring_frames(struct ring *ring)
{
	int i;

	ring->frames = xzmalloc(ring->layout.tp_frame_nr *
				sizeof(*ring->frames));

	for (i = 0; i < ring->layout.tp_frame_nr; ++i) {
		ring->frames[i].iov_len = ring->layout.tp_frame_size;
		ring->frames[i].iov_base = ring->mm_space +
					   (i * ring->layout.tp_frame_size);
	}
}

void bind_rx_ring(int sock, struct ring *ring, int ifindex)
{
	/*
	 * The RX_RING registers itself to the networking stack with
	 * dev_add_pack(), so we have one single RX_RING for all devs
	 * otherwise you'll get the packet twice.
	 */
	memset(&ring->s_ll, 0, sizeof(ring->s_ll));
	ring->s_ll.sll_family = AF_PACKET;
	ring->s_ll.sll_protocol = htons(ETH_P_ALL);
	ring->s_ll.sll_ifindex = ifindex; /* Take 0 for "any"-device */
	ring->s_ll.sll_hatype = 0;
	ring->s_ll.sll_halen = 0;
	ring->s_ll.sll_pkttype = 0;

	int ret = bind(sock, (struct sockaddr *) &ring->s_ll,
		       sizeof(ring->s_ll));
	if (ret < 0) {
		destroy_rx_ring(sock, ring);
		error_and_die(EXIT_FAILURE, "Cannot bind RX_RING!\n");
	}
}


/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
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

#include "xmalloc.h"
#include "die.h"
#include "ring_rx.h"
#include "built_in.h"

void destroy_rx_ring(int sock, struct ring *ring)
{
	fmemset(&ring->layout, 0, sizeof(ring->layout));
	setsockopt(sock, SOL_PACKET, PACKET_RX_RING, &ring->layout,
		   sizeof(ring->layout));

	munmap(ring->mm_space, ring->mm_len);
	ring->mm_len = 0;

	xfree(ring->frames);
}

void setup_rx_ring_layout(int sock, struct ring *ring, unsigned int size,
			  int jumbo_support)
{
	fmemset(&ring->layout, 0, sizeof(ring->layout));

	ring->layout.tp_block_size = (jumbo_support ?
				      getpagesize() << 4 :
				      getpagesize() << 2);
	ring->layout.tp_frame_size = (jumbo_support ?
				      TPACKET_ALIGNMENT << 12 :
				      TPACKET_ALIGNMENT << 7);
	ring->layout.tp_block_nr = size / ring->layout.tp_block_size;
	ring->layout.tp_frame_nr = ring->layout.tp_block_size /
				   ring->layout.tp_frame_size *
				   ring->layout.tp_block_nr;

	bug_on(ring->layout.tp_block_size < ring->layout.tp_frame_size);
	bug_on((ring->layout.tp_block_size % ring->layout.tp_frame_size) != 0);
	bug_on((ring->layout.tp_block_size % getpagesize()) != 0);
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
		panic("Cannot allocate RX_RING!\n");

	ring->mm_len = ring->layout.tp_block_size * ring->layout.tp_block_nr;

	printf("RX: %.2f MiB, %u Frames, each %u Byte allocated\n",
	       1.f * ring->mm_len / (1 << 20),
	       ring->layout.tp_frame_nr, ring->layout.tp_frame_size);
}

void mmap_rx_ring(int sock, struct ring *ring)
{
	ring->mm_space = mmap(0, ring->mm_len, PROT_READ | PROT_WRITE,
			      MAP_SHARED | MAP_LOCKED, sock, 0);
	if (ring->mm_space == MAP_FAILED) {
		destroy_rx_ring(sock, ring);
		panic("Cannot mmap RX_RING!\n");
	}
}

void alloc_rx_ring_frames(struct ring *ring)
{
	int i;
	size_t len = ring->layout.tp_frame_nr * sizeof(*ring->frames);

	ring->frames = xmalloc_aligned(len, CO_CACHE_LINE_SIZE);
	fmemset(ring->frames, 0, len);

	for (i = 0; i < ring->layout.tp_frame_nr; ++i) {
		ring->frames[i].iov_len = ring->layout.tp_frame_size;
		ring->frames[i].iov_base = ring->mm_space +
					   (i * ring->layout.tp_frame_size);
	}
}

void bind_rx_ring(int sock, struct ring *ring, int ifindex)
{
	int ret;
	/*
	 * The RX_RING registers itself to the networking stack with
	 * dev_add_pack(), so we have one single RX_RING for all devs
	 * otherwise you'll get the packet twice.
	 */
	fmemset(&ring->s_ll, 0, sizeof(ring->s_ll));

	ring->s_ll.sll_family = AF_PACKET;
	ring->s_ll.sll_protocol = htons(ETH_P_ALL);
	ring->s_ll.sll_ifindex = ifindex;
	ring->s_ll.sll_hatype = 0;
	ring->s_ll.sll_halen = 0;
	ring->s_ll.sll_pkttype = 0;

	ret = bind(sock, (struct sockaddr *) &ring->s_ll, sizeof(ring->s_ll));
	if (ret < 0) {
		destroy_rx_ring(sock, ring);
		panic("Cannot bind RX_RING!\n");
	}
}

/*
 * netsniff-ng - the packet sniffing beast
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
#include "ring.h"
#include "built_in.h"

void mmap_ring_generic(int sock, struct ring *ring)
{
	ring->mm_space = mmap(NULL, ring->mm_len, PROT_READ | PROT_WRITE,
			      MAP_SHARED | MAP_LOCKED | MAP_POPULATE, sock, 0);
	if (ring->mm_space == MAP_FAILED)
		panic("Cannot mmap {TX,RX}_RING!\n");
}

void alloc_ring_frames_generic(struct ring *ring, int num, size_t size)
{
	int i;
	size_t len = num * sizeof(*ring->frames);

	ring->frames = xmalloc_aligned(len, CO_CACHE_LINE_SIZE);
	fmemset(ring->frames, 0, len);

	for (i = 0; i < num; ++i) {
		ring->frames[i].iov_len = size;
		ring->frames[i].iov_base = ring->mm_space + (i * size);
	}
}

void bind_ring_generic(int sock, struct ring *ring, int ifindex, bool tx_only)
{
	int ret;
	/* The {TX,RX}_RING registers itself to the networking stack with
	 * dev_add_pack(), so we have one single RX_RING for all devs
	 * otherwise you'll get the packet twice.
	 */
	fmemset(&ring->s_ll, 0, sizeof(ring->s_ll));

	ring->s_ll.sll_family = AF_PACKET;
	if (tx_only)
		ring->s_ll.sll_protocol = 0;
	else
		ring->s_ll.sll_protocol = htons(ETH_P_ALL);
	ring->s_ll.sll_ifindex = ifindex;
	ring->s_ll.sll_hatype = 0;
	ring->s_ll.sll_halen = 0;
	ring->s_ll.sll_pkttype = 0;

	ret = bind(sock, (struct sockaddr *) &ring->s_ll, sizeof(ring->s_ll));
	if (ret < 0)
		panic("Cannot bind {TX,RX}_RING!\n");
}

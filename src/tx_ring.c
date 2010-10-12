/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Copyright 2009, 2010 Emmanuel Roullit.
 * Subject to the GPL.
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
#include "error_and_die.h"
#include "tx_ring.h"

#ifdef HAVE_TX_RING
void set_packet_loss_discard(int sock)
{
	int ret, discard = 1;

	ret = setsockopt(sock, SOL_PACKET, PACKET_LOSS, (void *) &discard,
			 sizeof(discard));
	if (ret < 0)
		error_and_die(EXIT_FAILURE, "setsockopt: cannot set packet "
			      "loss");
}

void destroy_tx_ring(int sock, struct ring *ring)
{
	memset(&ring->layout, 0, sizeof(ring->layout));
	setsockopt(sock, SOL_PACKET, PACKET_TX_RING, &ring->layout,
		   sizeof(ring->layout));

	munmap(ring->mm_space, ring->mm_len);
	ring->mm_len = 0;

	xfree(ring->frames);
}

void setup_tx_ring_layout(int sock, struct ring *ring, unsigned int size)
{
	/*
	 * FIXME: We currently have 2048 Byte per frame. Frames need to
	 * fit exactly into blocks. Blocks can only be a multiple of the 
	 * systems page size. What do we do with jumbo frames?
	 */
	memset(&ring->layout, 0, sizeof(ring->layout));
	ring->layout.tp_block_size = getpagesize() << 2;
	ring->layout.tp_frame_size = TPACKET_ALIGNMENT << 7;
	ring->layout.tp_block_nr = size / ring->layout.tp_block_size;
	ring->layout.tp_frame_nr = ring->layout.tp_block_size /
				   ring->layout.tp_frame_size *
				   ring->layout.tp_block_nr;
}

void create_tx_ring(int sock, struct ring *ring)
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
		error_and_die(EXIT_FAILURE, "Cannot allocate TX_RING!\n");

	ring->mm_len = ring->layout.tp_block_size * ring->layout.tp_block_nr;

	printf("TX: %.2f MB, %u Frames each %u Byte allocated\n",
	       1.f * ring->mm_len / (1 << 20),
	       ring->layout.tp_frame_nr, ring->layout.tp_frame_size);
}

void mmap_tx_ring(int sock, struct ring *ring)
{
	ring->mm_space = mmap(0, ring->mm_len, PROT_READ | PROT_WRITE,
			      MAP_SHARED, sock, 0);
	if (ring->mm_space == MAP_FAILED) {
		destroy_tx_ring(sock, ring);
		error_and_die(EXIT_FAILURE, "Cannot mmap TX_RING!\n");
	}
}

void alloc_tx_ring_frames(struct ring *ring)
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

void bind_tx_ring(int sock, struct ring *ring, int ifindex)
{
	memset(&ring->s_ll, 0, sizeof(ring->s_ll));
	ring->s_ll.sll_family = AF_PACKET;
	ring->s_ll.sll_protocol = htons(ETH_P_ALL);
	ring->s_ll.sll_ifindex = ifindex;
	ring->s_ll.sll_hatype = 0;
	ring->s_ll.sll_halen = 0;
	ring->s_ll.sll_pkttype = 0;

	int ret = bind(sock, (struct sockaddr *) &ring->s_ll,
		       sizeof(ring->s_ll));
	if (ret < 0) {
		destroy_tx_ring(sock, ring);
		error_and_die(EXIT_FAILURE, "Cannot bind TX_RING!\n");
	}
}

int pull_and_flush_tx_ring(int sock)
{
	/* Flush buffers with TP_STATUS_SEND_REQUEST */
	return sendto(sock, NULL, 0, MSG_DONTWAIT, NULL, 0);
}

#endif /* HAVE_TX_RING */

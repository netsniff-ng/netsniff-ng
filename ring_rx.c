/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010 Daniel Borkmann.
 * Copyright 2014 Tobias Klauser.
 * Subject to the GPL, version 2.
 */

#include <inttypes.h>
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

/*
 * tpacket v3 data structures and constants are not available for older kernel
 * versions which only support tpacket v2, thus we need protect access to them.
 */
#ifdef HAVE_TPACKET3
static inline bool is_tpacket_v3(int sock)
{
	return get_sockopt_tpacket(sock) == TPACKET_V3;
}

static inline size_t get_ring_layout_size(struct ring *ring, bool v3)
{
	return v3 ? sizeof(ring->layout3) : sizeof(ring->layout);
}

static inline void setup_rx_ring_layout_v3(struct ring *ring)
{
	/* Pass out, if this will ever change and we do crap on it! */
	build_bug_on(offsetof(struct tpacket_req, tp_frame_nr) !=
		     offsetof(struct tpacket_req3, tp_frame_nr) &&
		     sizeof(struct tpacket_req) !=
		     offsetof(struct tpacket_req3, tp_retire_blk_tov));

	ring->layout3.tp_retire_blk_tov = 100; /* 0: let kernel decide */
	ring->layout3.tp_sizeof_priv = 0;
	ring->layout3.tp_feature_req_word = 0;
}

static inline int rx_ring_get_num(struct ring *ring, bool v3)
{
	return v3 ? ring->layout3.tp_block_nr : ring->layout.tp_frame_nr;
}

static inline size_t rx_ring_get_size(struct ring *ring, bool v3)
{
	return v3 ? ring->layout3.tp_block_size : ring->layout.tp_frame_size;
}

static int get_rx_net_stats(int sock, uint64_t *packets, uint64_t *drops, bool v3)
{
	int ret;
	union {
		struct tpacket_stats	k2;
		struct tpacket_stats_v3 k3;
	} stats;
	socklen_t slen = v3 ? sizeof(stats.k3) : sizeof(stats.k2);

	memset(&stats, 0, sizeof(stats));
	ret = getsockopt(sock, SOL_PACKET, PACKET_STATISTICS, &stats, &slen);
	if (ret == 0) {
		*packets = stats.k3.tp_packets;
		*drops = stats.k3.tp_drops;
	}
	return ret;
}
#else
static inline bool is_tpacket_v3(int sock __maybe_unused)
{
	return false;
}

static inline size_t get_ring_layout_size(struct ring *ring, bool v3 __maybe_unused)
{
	return sizeof(ring->layout);
}

static inline void setup_rx_ring_layout_v3(struct ring *ring __maybe_unused)
{
}

static inline int rx_ring_get_num(struct ring *ring, bool v3 __maybe_unused)
{
	return ring->layout.tp_frame_nr;
}

static inline size_t rx_ring_get_size(struct ring *ring, bool v3 __maybe_unused)
{
	return ring->layout.tp_frame_size;
}

static int get_rx_net_stats(int sock, uint64_t *packets, uint64_t *drops, bool v3 __maybe_unused)
{
	int ret;
	struct tpacket_stats stats;
	socklen_t slen = sizeof(stats);

	memset(&stats, 0, sizeof(stats));
	ret = getsockopt(sock, SOL_PACKET, PACKET_STATISTICS, &stats, &slen);
	if (ret == 0) {
		*packets = stats.tp_packets;
		*drops = stats.tp_drops;
	}
	return ret;
}
#endif /* HAVE_TPACKET3 */

void destroy_rx_ring(int sock, struct ring *ring)
{
	int ret;
	bool v3 = is_tpacket_v3(sock);

	munmap(ring->mm_space, ring->mm_len);
	ring->mm_len = 0;

	xfree(ring->frames);

	/* In general, this is freed during close(2) anyway. */
	if (v3)
		return;

	fmemset(&ring->layout, 0, sizeof(ring->layout));
	ret = setsockopt(sock, SOL_PACKET, PACKET_RX_RING, &ring->layout,
			 sizeof(ring->layout));
	if (unlikely(ret))
		panic("Cannot destroy the RX_RING: %s!\n", strerror(errno));
}

static void setup_rx_ring_layout(int sock, struct ring *ring, size_t size,
				 bool jumbo_support, bool v3)
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

	if (v3) {
		setup_rx_ring_layout_v3(ring);
		set_sockopt_tpacket_v3(sock);
	} else {
		set_sockopt_tpacket_v2(sock);
	}

	ring_verify_layout(ring);
}

static void create_rx_ring(int sock, struct ring *ring, bool verbose)
{
	int ret;
	bool v3 = is_tpacket_v3(sock);
	size_t layout_size = get_ring_layout_size(ring, v3);

retry:
	ret = setsockopt(sock, SOL_PACKET, PACKET_RX_RING, &ring->raw,
			 layout_size);

	if (errno == ENOMEM && ring->layout.tp_block_nr > 1) {
		ring->layout.tp_block_nr >>= 1;
		ring->layout.tp_frame_nr = ring->layout.tp_block_size / 
					   ring->layout.tp_frame_size * 
					   ring->layout.tp_block_nr;
		goto retry;
	}
	if (ret < 0)
		panic("Cannot allocate RX_RING!\n");

	ring->mm_len = (size_t) ring->layout.tp_block_size * ring->layout.tp_block_nr;

	if (verbose) {
		if (!v3) {
			printf("RX,V2: %.2Lf MiB, %u Frames, each %u Byte allocated\n",
			       (long double) ring->mm_len / (1 << 20),
			       ring->layout.tp_frame_nr, ring->layout.tp_frame_size);
		} else {
			printf("RX,V3: %.2Lf MiB, %u Blocks, each %u Byte allocated\n",
			       (long double) ring->mm_len / (1 << 20),
			       ring->layout.tp_block_nr, ring->layout.tp_block_size);
		}
	}
}

static void alloc_rx_ring_frames(int sock, struct ring *ring)
{
	bool v3 = is_tpacket_v3(sock);

	alloc_ring_frames_generic(ring, rx_ring_get_num(ring, v3),
				  rx_ring_get_size(ring, v3));
}

void join_fanout_group(int sock, uint32_t fanout_group, uint32_t fanout_type)
{
	uint32_t fanout_opt = 0;
	int ret;

	if (fanout_group == 0)
		return;

	fanout_opt = (fanout_group & 0xffff) | (fanout_type << 16);

	ret = setsockopt(sock, SOL_PACKET, PACKET_FANOUT, &fanout_opt,
			 sizeof(fanout_opt));
	if (ret < 0)
		panic("Cannot set fanout ring mode!\n");
}

void ring_rx_setup(struct ring *ring, int sock, size_t size, int ifindex,
		   struct pollfd *poll, bool v3, bool jumbo_support,
		   bool verbose, uint32_t fanout_group, uint32_t fanout_type)
{
	fmemset(ring, 0, sizeof(*ring));
	setup_rx_ring_layout(sock, ring, size, jumbo_support, v3);
	create_rx_ring(sock, ring, verbose);
	mmap_ring_generic(sock, ring);
	alloc_rx_ring_frames(sock, ring);
	bind_ring_generic(sock, ring, ifindex, false);
	join_fanout_group(sock, fanout_group, fanout_type);
	prepare_polling(sock, poll);
}

void sock_rx_net_stats(int sock, unsigned long seen)
{
	int ret;
	uint64_t packets, drops;
	bool v3 = is_tpacket_v3(sock);

	ret = get_rx_net_stats(sock, &packets, &drops, v3);
	if (ret == 0) {
		printf("\r%12"PRIu64"  packets incoming (%"PRIu64" unread on exit)\n",
		       v3 ? (uint64_t)seen : packets, v3 ? packets - seen : 0);
		printf("\r%12"PRIu64"  packets passed filter\n", packets - drops);
		printf("\r%12"PRIu64"  packets failed filter (out of space)\n", drops);
		if (packets > 0)
			printf("\r%12.4lf%% packet droprate\n",
			       (1.0 * drops / packets) * 100.0);
	}
}

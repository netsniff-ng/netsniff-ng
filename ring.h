/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef RING_H
#define RING_H

/*
 * "I love the smell of 10GbE in the morning. Smells like ... victory."
 *     - W. Richard Stevens, "Secret Teachings of the UNIX Environment"
 */

#include <stdio.h>
#include <stdint.h>
#include <linux/if_packet.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <string.h>
#include <poll.h>

#include "built_in.h"
#include "die.h"
#include "dev.h"
#include "config.h"

#ifndef POLLRDNORM
# define POLLRDNORM	0x0040
#endif

union tpacket_uhdr {
	struct tpacket_hdr  *h1;
	struct tpacket2_hdr *h2;
#ifdef HAVE_TPACKET3
	struct tpacket3_hdr *h3;
#endif
	void *raw;
};

#ifdef HAVE_TPACKET3
#define tpacket_uhdr(hdr, member, v3)	\
	((v3) ? ((hdr).h3)->member : ((hdr).h2)->member)
#else
#define tpacket_uhdr(hdr, member, v3)	\
	(((hdr).h2)->member)
#endif /* HAVE_TPACKET3 */

struct frame_map {
	struct tpacket2_hdr tp_h __aligned_tpacket;
	struct sockaddr_ll s_ll __align_tpacket(sizeof(struct tpacket2_hdr));
};

#ifdef HAVE_TPACKET3
struct block_desc {
	uint32_t version;
	uint32_t offset_to_priv;
	struct tpacket_hdr_v1 h1;
};
#endif

struct ring {
	struct iovec *frames;
	uint8_t *mm_space;
	size_t mm_len;
	struct sockaddr_ll s_ll;
	union {
		struct tpacket_req layout;
#ifdef HAVE_TPACKET3
		struct tpacket_req3 layout3;
#endif
		uint8_t raw;
	};
};

static inline void next_rnd_slot(unsigned int *it, struct ring *ring)
{
	*it = rand() % ring->layout.tp_frame_nr;
}

static inline size_t ring_size(char *ifname, size_t size)
{
	if (size > 0)
		return size;

	/*
	 * Device bitrate in bytes times two as ring size.
	 *    Fallback => ~    64,00 MB
	 *     10 MBit => ~     2,38 MB
	 *     54 MBit => ~    12,88 MB
	 *    100 MBit => ~    23,84 MB
	 *    300 MBit => ~    71,52 MB
	 *  1.000 MBit => ~   238,42 MB
	 * 10.000 MBit => ~ 2.384.18 MB
	 */
	size = device_bitrate(ifname);
	size = (size * 1000000) / 8;
	size = size * 2;
	if (size == 0)
		size = 1 << 26;

	return round_up_cacheline(size);
}

static inline unsigned int ring_frame_size(struct ring *ring)
{
	return ring->layout.tp_frame_size;
}

static inline void ring_verify_layout(struct ring *ring)
{
	bug_on(ring->layout.tp_block_size  < ring->layout.tp_frame_size);
	bug_on((ring->layout.tp_block_size % ring->layout.tp_frame_size) != 0);
	bug_on((ring->layout.tp_block_size % RUNTIME_PAGE_SIZE) != 0);
}

static inline void tpacket_hdr_clone(struct tpacket2_hdr *thdrd,
				     struct tpacket2_hdr *thdrs)
{
        thdrd->tp_sec = thdrs->tp_sec;
        thdrd->tp_nsec = thdrs->tp_nsec;
        thdrd->tp_snaplen = thdrs->tp_snaplen;
        thdrd->tp_len = thdrs->tp_len;
}

static inline void prepare_polling(int sock, struct pollfd *pfd)
{
	memset(pfd, 0, sizeof(*pfd));
	pfd->fd = sock;
	pfd->revents = 0;
	pfd->events = POLLIN | POLLRDNORM | POLLERR;
}

static inline void __set_sockopt_tpacket(int sock, int val)
{
	int ret = setsockopt(sock, SOL_PACKET, PACKET_VERSION, &val, sizeof(val));
	if (ret)
		panic("Cannot set tpacketv2!\n");
}

static inline void set_sockopt_tpacket_v2(int sock)
{
	__set_sockopt_tpacket(sock, TPACKET_V2);
}

#ifdef HAVE_TPACKET3
static inline void set_sockopt_tpacket_v3(int sock)
{
	__set_sockopt_tpacket(sock, TPACKET_V3);
}
#else
static inline void set_sockopt_tpacket_v3(int sock __maybe_unused)
{
}
#endif

static inline int get_sockopt_tpacket(int sock)
{
	int val, ret;
	socklen_t len = sizeof(val);

	ret = getsockopt(sock, SOL_PACKET, PACKET_VERSION, &val, &len);
	if (ret)
		panic("Cannot get tpacket version!\n");

	return val;
}

extern void mmap_ring_generic(int sock, struct ring *ring);
extern void alloc_ring_frames_generic(struct ring *ring, int num, size_t size);
extern void bind_ring_generic(int sock, struct ring *ring, int ifindex, bool tx_only);

#endif /* RING_H */

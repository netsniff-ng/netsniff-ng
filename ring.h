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
#include <sys/poll.h>

#include "xutils.h"
#include "built_in.h"
#include "die.h"

struct frame_map {
	struct tpacket2_hdr tp_h __aligned_tpacket;
	struct sockaddr_ll s_ll __align_tpacket(sizeof(struct tpacket2_hdr));
};

struct ring {
	struct iovec *frames;
	uint8_t *mm_space;
	size_t mm_len;
	struct tpacket_req layout;
	struct sockaddr_ll s_ll;
};

static inline void next_rnd_slot(unsigned int *it, struct ring *ring)
{
	*it = rand() % ring->layout.tp_frame_nr;
}

#define RING_SIZE_FALLBACK (1 << 26)

static inline unsigned int ring_size(char *ifname, unsigned int size)
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
		size = RING_SIZE_FALLBACK;

	return round_up_cacheline(size);
}

static inline unsigned int ring_frame_size(struct ring *ring)
{
	return ring->layout.tp_frame_size;
}

static inline void tpacket_hdr_clone(struct tpacket2_hdr *thdrd,
				     struct tpacket2_hdr *thdrs)
{
        thdrd->tp_sec = thdrs->tp_sec;
        thdrd->tp_nsec = thdrs->tp_nsec;
        thdrd->tp_snaplen = thdrs->tp_snaplen;
        thdrd->tp_len = thdrs->tp_len;
}

#ifndef POLLRDNORM
# define POLLRDNORM	0x0040
#endif
#ifndef POLLWRNORM
# define POLLWRNORM	0x0100
#endif
#ifndef POLLRDHUP
# define POLLRDHUP	0x2000
#endif

static inline void prepare_polling(int sock, struct pollfd *pfd)
{
	memset(pfd, 0, sizeof(*pfd));
	pfd->fd = sock;
	pfd->revents = 0;
	pfd->events = POLLIN | POLLRDNORM | POLLERR;
}

static inline void set_sockopt_tpacket_v2(int sock)
{
	int ret, val = TPACKET_V2;

	ret = setsockopt(sock, SOL_PACKET, PACKET_VERSION, &val, sizeof(val));
	if (ret)
		panic("Cannot set tpacketv2!\n");
}

#endif /* RING_H */

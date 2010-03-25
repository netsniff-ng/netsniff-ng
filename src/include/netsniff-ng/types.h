/*
 * Copyright (C) 2009, 2010  Daniel Borkmann <daniel@netsniff-ng.org> and 
 *                           Emmanuel Roullit <emmanuel@netsniff-ng.org>
 *
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation; either version 2 of the License, or (at 
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License 
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
 */

#ifndef _NET_TYPES_H_
#define _NET_TYPES_H_

#include <stdint.h>

#include <sys/socket.h>
#include <sys/poll.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>

/*
 * Internal data structures
 */

typedef uint8_t ring_buff_bytes_t;

typedef struct ring_buff_private {
	struct sockaddr_ll params;
	struct tpacket_req layout;
	struct iovec *frames;
	ring_buff_bytes_t *buffer;
	uint32_t len;
} ring_buff_t;

typedef struct frame_map {
	struct tpacket_hdr tp_h __attribute__ ((aligned(TPACKET_ALIGNMENT)));
	struct sockaddr_ll s_ll __attribute__ ((aligned(TPACKET_ALIGNMENT)));
} frame_map_t;

/*
 * Some external data structures (wich are used for
 * data transmission via a unix domain socket inode)
 */

struct fb_count {
	uint64_t frames;
	uint64_t bytes;
};

typedef struct ring_buff_private_stat {
	struct fb_count total;
	struct fb_count per_sec;
	struct fb_count per_min;
	struct fb_count s_per_sec;
	struct fb_count s_per_min;
	uint16_t t_elapsed;
	struct timespec m_start;
} ring_buff_stat_t;

#endif				/* _NET_TYPES_H_ */

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

#ifndef _NET_RINGBUFF_H_
#define _NET_RINGBUFF_H_

#include <net/ethernet.h>

#define CHUNK_STATUS_FREE 0
#define CHUNK_STATUS_BUSY 1

/* The MTU size is the amount of allowed payload + the ethernet header */
#define DEFAULT_PAYLOAD_SIZE    1500
#define DEFAULT_MTU             DEFAULT_PAYLOAD_SIZE + ETH_HLEN

struct ringbuffer_user {
	/* XXX: MTU size and aligned */
	char payload[DEFAULT_MTU];
	size_t len;
};

struct ringbuffer_chunk {
	uint8_t ch_status;
	struct ringbuffer_user ch_user;
};

struct ringbuffer {
	size_t max_slots;
	size_t cur_slots;
	size_t next_free;
	size_t next_user;
	struct ringbuffer_chunk **ring;
};

extern int ringbuffer_init(struct ringbuffer **rb, size_t slots);
extern void ringbuffer_cleanup(struct ringbuffer *rb);
extern int ringbuffer_put(struct ringbuffer *rb, struct ringbuffer_user *rb_data);
extern int ringbuffer_get(struct ringbuffer *rb, struct ringbuffer_user *rb_data);

#endif				/* _NET_RINGBUFF_H_ */

/* XXX: Coding Style - use the tool indent with the following (Linux kernel
 *                     code indents)
 *
 * indent -nbad -bap -nbc -bbo -hnl -br -brs -c33 -cd33 -ncdb -ce -ci4   \
 *        -cli0 -d0 -di1 -nfc1 -i8 -ip0 -l120 -lp -npcs -nprs -npsl -sai \
 *        -saf -saw -ncs -nsc -sob -nfca -cp33 -ss -ts8 -il1
 *
 *
 * netsniff-ng
 *
 * High performance network sniffer for packet inspection
 *
 * Copyright (C) 2009, 2010  Daniel Borkmann <danborkmann@googlemail.com> and 
 *                           Emmanuel Roullit <emmanuel.roullit@googlemail.com>
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
 *
 * Note: Your kernel has to be compiled with CONFIG_PACKET_MMAP=y option in 
 *       order to use this.
 */

/*
 * This file contains a ringbuffer implementation for data exchange via 
 * Netlink protocol and can be used for fetching samples of the netdata 
 * (for instance).
 */

#ifndef _NET_RINGBUFF_H_
#define _NET_RINGBUFF_H_

#define CHUNK_STATUS_FREE 0
#define CHUNK_STATUS_BUSY 1

typedef size_t ringbuffer_offs_t;

typedef struct {
	/* XXX: MTU size and aligned */
	char payload[1500];
	size_t len;
} ringbuffer_user_t;

typedef struct {
	uint8_t ch_status;
	ringbuffer_user_t ch_user;
} ringbuffer_chunk_t;

typedef struct {
	size_t max_slots;
	size_t cur_slots;
	ringbuffer_offs_t next_free;
	ringbuffer_offs_t next_user;
	ringbuffer_chunk_t **ring;
} ringbuffer_t;

extern int ringbuffer_init(ringbuffer_t ** rb, size_t slots);
extern void ringbuffer_cleanup(ringbuffer_t * rb);
extern int ringbuffer_put(ringbuffer_t * rb, ringbuffer_user_t * rb_data);
extern int ringbuffer_get(ringbuffer_t * rb, ringbuffer_user_t * rb_data);

#endif				/* _NET_RINGBUFF_H_ */

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
 * Contains: 
 *    Stuff that can be used for RX_RING as well as for TX_RING
 */

#ifndef _NET_RXTX_COMMON_H_
#define _NET_RXTX_COMMON_H_

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <netsniff-ng/macros.h>
#include <netsniff-ng/types.h>

/* Inline stuff */

/**
 * alloc_frame_buffer - Allocates frame buffer
 * @rb:                ring buff struct
 */
static inline void alloc_frame_buffer(ring_buff_t * rb)
{
	int i = 0;

	assert(rb);

	rb->frames = malloc(rb->layout.tp_frame_nr * sizeof(*rb->frames));
	if (!rb->frames) {
		err("No mem left");
		exit(EXIT_FAILURE);
	}

	memset(rb->frames, 0, rb->layout.tp_frame_nr * sizeof(*rb->frames));

	for (i = 0; i < rb->layout.tp_frame_nr; ++i) {
		rb->frames[i].iov_base = (void *)((long)rb->buffer) + (i * rb->layout.tp_frame_size);
		rb->frames[i].iov_len = rb->layout.tp_frame_size;
	}
}

#endif	/* _NET_RXTX_COMMON_H_ */

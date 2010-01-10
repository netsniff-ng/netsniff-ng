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
 * Copyright (C) 2009, 2010  Daniel Borkmann <danborkmann@googlemail.com>
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
 *    Mostly RX_RING related stuff and other networking code
 */

#ifndef _NET_RX_RING_H_
#define _NET_RX_RING_H_

#include <stdlib.h>
#include <assert.h>

#include <linux/filter.h>
#include <linux/if_packet.h>

#include <netsniff-ng/macros.h>
#include <netsniff-ng/types.h>

/* Function signatures */

extern void destroy_virt_ring(int sock, ring_buff_t * rb);
extern void create_virt_ring(int sock, ring_buff_t * rb);
extern void mmap_virt_ring(int sock, ring_buff_t * rb);
extern void bind_dev_to_ring(int sock, int ifindex, ring_buff_t * rb);
extern void put_dev_into_promisc_mode(int sock, int ifindex);
extern void inject_kernel_bpf(int sock, struct sock_filter *bpf, int len);
extern void reset_kernel_bpf(int sock);
extern int ethdev_to_ifindex(int sock, char *dev);
extern void net_stat(int sock);
extern int alloc_pf_sock(void);
extern void parse_rules(char *rulefile, struct sock_filter **bpf, int *len);

/* Inline stuff */

/**
 * alloc_frame_buffer - Allocates frame buffer
 * @rb:                ring buff struct
 */
static inline void alloc_frame_buffer(ring_buff_t * rb)
{
	int i = 0;

	assert(rb);

	rb->frames =
	    (struct iovec *)malloc(rb->layout.tp_frame_nr *
				   sizeof(*rb->frames));
	if (!rb->frames) {
		err("No mem left!\n");
		exit(EXIT_FAILURE);
	}

	memset(rb->frames, 0, rb->layout.tp_frame_nr * sizeof(*rb->frames));

	for (i = 0; i < rb->layout.tp_frame_nr; ++i) {
		rb->frames[i].iov_base =
		    (void *)((long)rb->buffer) + (i * rb->layout.tp_frame_size);
		rb->frames[i].iov_len = rb->layout.tp_frame_size;
	}
}

/**
 * mem_notify_user - Checks whether kernel has written its data into our 
 *                   virtual RX_RING
 * @frame:          ethernet frame data
 */
static inline int mem_notify_user(struct iovec frame)
{
	struct tpacket_hdr *header = frame.iov_base;
	return (header->tp_status == TP_STATUS_USER);
}

/**
 * mem_notify_kernel - We tell the kernel that we are done with processing 
 *                     data from our virtual RX_RING
 * @header:           packet header with status flag
 */
static inline void mem_notify_kernel(struct tpacket_hdr *header)
{
	assert(header);
	header->tp_status = TP_STATUS_KERNEL;
}

#endif				/* _NET_RX_RING_H_ */

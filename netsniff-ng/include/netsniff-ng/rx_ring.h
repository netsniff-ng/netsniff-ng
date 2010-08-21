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

#ifndef _NET_RX_RING_H_
#define _NET_RX_RING_H_

#include <stdlib.h>
#include <assert.h>

#include <netsniff-ng/macros.h>
#include <netsniff-ng/types.h>
#include <netsniff-ng/rxtx_common.h>
#include <netsniff-ng/config.h>

/* Function signatures */

extern void destroy_virt_rx_ring(int sock, struct ring_buff *rb);
extern void create_virt_rx_ring(int sock, struct ring_buff *rb, char *ifname, unsigned int usize);
extern void mmap_virt_rx_ring(int sock, struct ring_buff *rb);
extern void bind_dev_to_rx_ring(int sock, int ifindex, struct ring_buff *rb);
extern void fetch_packets(struct system_data *sd, int sock, struct ring_buff *rb);
extern void compat_fetch_packets(struct system_data *sd, int sock, struct ring_buff *rb);
extern void start_fetching_packets(struct system_data *sd, int sock, struct ring_buff *rb);

#define DEFAULT_RX_RING_SILENT_MESSAGE "Receive ring dumping ... |"

/* Inline stuff */

/**
 * mem_notify_user_for_rx - Checks whether kernel has written its data into our 
 *                          virtual RX_RING
 * @frame:                 ethernet frame data
 */
static inline int mem_notify_user_for_rx(struct iovec frame)
{
	struct tpacket_hdr *header = frame.iov_base;
	return (header->tp_status == TP_STATUS_USER);
}

/**
 * mem_notify_kernel_for_rx - We tell the kernel that we are done with processing 
 *                            data from our virtual RX_RING
 * @header:                  packet header with status flag
 */
static inline void mem_notify_kernel_for_rx(struct tpacket_hdr *header)
{
	assert(header);
	header->tp_status = TP_STATUS_KERNEL;
}

#endif				/* _NET_RX_RING_H_ */

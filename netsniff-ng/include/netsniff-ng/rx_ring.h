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
#include <pthread.h>
#include <sys/queue.h>

#include <netsniff-ng/macros.h>
#include <netsniff-ng/types.h>
#include <netsniff-ng/thread.h>
#include <netsniff-ng/rxtx_common.h>
#include <netsniff-ng/config.h>
#include <netsniff-ng/ringbuff.h>

#if 0
/* a rx ring must only belong to one entity */
struct netsniff_ng_rx_nic_context
{
	/* Structure which describe a nic instead? */
	const char *				rx_dev[IFNAMSIZ];
	void	(*print_pkt)(ring_buff_bytes_t *, const struct tpacket_hdr *);
	/* Maybe multiple ring buffer for one device */
	uint32_t				flags;
	int					bpf_fd;
	int 					pcap_fd;
	size_t					nic_rb_slots;
	ringbuffer_t				nic_rb;
	SLIST_ENTRY(netsniff_ng_rx_nic_info)	nic_entry;
};

struct netsniff_ng_rx_thread_config
{
	struct netsniff_ng_thread_context			thread_ctx;
	SLIST_HEAD(rx_rb_head, netsniff_ng_rx_nic_context)	nic_head;
};
#endif
/* Function signatures */

extern void destroy_virt_rx_ring(int sock, ring_buff_t * rb);
extern void create_virt_rx_ring(int sock, ring_buff_t * rb, char *ifname, unsigned int usize);
extern void mmap_virt_rx_ring(int sock, ring_buff_t * rb);
extern void bind_dev_to_rx_ring(int sock, int ifindex, ring_buff_t * rb);
extern void fetch_packets(system_data_t * sd, int sock, ring_buff_t * rb, struct pollfd *pfd);

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

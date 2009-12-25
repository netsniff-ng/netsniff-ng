/* 
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

#include <netsniff-ng/types.h>

/* Function signatures */

extern void destroy_virt_ring(int sock, ring_buff_t *rb);
extern void create_virt_ring(int sock, ring_buff_t *rb);
extern void mmap_virt_ring(int sock, ring_buff_t *rb);
extern void bind_dev_to_ring(int sock, int ifindex, ring_buff_t *rb);
extern void put_dev_into_promisc_mode(int sock, int ifindex);
extern void inject_kernel_bpf(int sock, struct sock_filter *bpf, int len);
extern int ethdev_to_ifindex(int sock, char *dev);
extern void net_stat(int sock);
extern int alloc_pf_sock(void);
extern void parse_rules(char *rulefile, struct sock_filter **bpf, int *len);

/* Inline stuff */

/**
 * mem_notify_user - Checks whether kernel has written its data into our 
 *                   virtual RX_RING
 * @frame:          ethernet frame data
 */
static inline int mem_notify_user(struct iovec frame)
{
        struct tpacket_hdr *header = frame.iov_base;

        /* XXX: Normally it should be TP_STATUS_USER, but frames larger than 
                our defined framesize will be truncated and set to 
                TP_STATUS_COPY or see other flags as well, so we grab them 
                all in order to get most things working with our stats ... */ 

        return (TP_STATUS_KERNEL != header->tp_status);
}

/**
 * mem_notify_kernel - We tell the kernel that we are done with processing 
 *                     data from our virtual RX_RING
 * @header:           packet header with status flag
 */
static inline void mem_notify_kernel(struct tpacket_hdr *header)
{
        header->tp_status = TP_STATUS_KERNEL;
}

#endif /* _NET_RX_RING_H_ */


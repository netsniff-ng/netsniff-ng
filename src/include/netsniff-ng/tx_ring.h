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
 *    Mostly TX_RING related stuff and other networking code
 */

#ifndef _NET_TX_RING_H_
#define _NET_TX_RING_H_

#include <stdlib.h>
#include <assert.h>

#include <linux/version.h>

#include <netsniff-ng/macros.h>
#include <netsniff-ng/types.h>
#include <netsniff-ng/config.h>
#include <netsniff-ng/rxtx_common.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
# define __HAVE_TX_RING__
#else
# undef __HAVE_TX_RING__
#endif				/* LINUX_VERSION_CODE */

/* Function signatures */

extern void destroy_virt_tx_ring(int sock, ring_buff_t * rb);
extern void create_virt_tx_ring(int sock, ring_buff_t * rb, char *ifname);
extern void mmap_virt_tx_ring(int sock, ring_buff_t * rb);
extern void bind_dev_to_tx_ring(int sock, int ifindex, ring_buff_t * rb);
extern int flush_virt_tx_ring(int sock, ring_buff_t * rb);
extern void transmit_packets(system_data_t * sd, int sock, ring_buff_t * rb);

/* Inline stuff */

#ifdef __HAVE_TX_RING__
/**
 * mem_notify_kernel_for_tx - We tell the kernel that we are done with setting up 
 *                            data.
 * @header:                  packet header with status flag
 */
static inline void mem_notify_kernel_for_tx(struct tpacket_hdr *header)
{
	assert(header);
	header->tp_status = TP_STATUS_SEND_REQUEST;
}
#endif				/* __HAVE_TX_RING__ */

#endif				/* _NET_TX_RING_H_ */

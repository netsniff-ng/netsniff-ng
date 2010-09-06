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

#ifndef _NET_TX_RING_H_
#define _NET_TX_RING_H_

#include <stdlib.h>
#include <assert.h>

#include <linux/version.h>

#include "macros.h"
#include "types.h"
#include "config.h"
#include "rxtx_common.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
# define __HAVE_TX_RING__
#else
# undef __HAVE_TX_RING__
#endif				/* LINUX_VERSION_CODE */

#define DEFAULT_TX_RING_SILENT_MESSAGE	"Transmit ring flushing ... |"

/* Function signatures */

extern void destroy_virt_tx_ring(int sock, struct ring_buff *rb);
extern void create_virt_tx_ring(int sock, struct ring_buff *rb, char *ifname, unsigned int usize);
extern void mmap_virt_tx_ring(int sock, struct ring_buff *rb);
extern void bind_dev_to_tx_ring(int sock, int ifindex, struct ring_buff *rb);
extern int flush_virt_tx_ring(int sock, struct ring_buff *rb);
extern void transmit_packets(struct system_data *sd, int sock, struct ring_buff *rb);

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

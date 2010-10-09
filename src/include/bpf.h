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

#ifndef _NET_BPF_H_
#define _NET_BPF_H_

#include <linux/filter.h>
#include <linux/if_packet.h>

extern void bpf_dump_all(struct sock_fprog *bpf);
extern int bpf_validate(const struct sock_fprog *bpf);
extern uint32_t bpf_filter(const struct sock_fprog *bpf, uint8_t * packet,
			   size_t plen);

#endif				/* _NET_BPF_H_ */

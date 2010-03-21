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
 *    Packet printing routines
 */

#ifndef _NET_PRINT_H_
#define _NET_PRINT_H_

//#include <linux/if_packet.h>
#include <linux/ip.h>
//#include <netinet/in.h>

#include <netsniff-ng/types.h>

/* Function signatures */
extern void print_packet_buffer_mode_1(ring_buff_bytes_t * rbb, const struct tpacket_hdr *tp);
extern void dump_hex(const void const *to_print, int len, size_t tty_len, size_t tty_off);
extern void dump_printable(const void const *to_print, int len, size_t tty_len, size_t tty_off);
extern void dump_ethhdr_all(struct ethhdr *eth);
extern void dump_iphdr_all(struct iphdr *ip);

extern void versatile_print(ring_buff_bytes_t * rbb, const struct tpacket_hdr *tp);
extern void payload_human_only_print(ring_buff_bytes_t * rbb, const struct tpacket_hdr *tp);
extern void payload_hex_only_print(ring_buff_bytes_t * rbb, const struct tpacket_hdr *tp);
extern void reduced_print(ring_buff_bytes_t * rbb, const struct tpacket_hdr *tp);

#endif				/* _NET_PRINT_H_ */

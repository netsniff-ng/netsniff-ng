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

#ifndef _NET_PRINT_H_
#define _NET_PRINT_H_

#include <linux/ip.h>

#include "types.h"

/* Function signatures */
extern void print_packet_buffer_mode_1(uint8_t * rbb, const struct tpacket_hdr *tp);
extern void dump_hex(const void const *to_print, int len, size_t tty_len, size_t tty_off);
extern void dump_printable(const void const *to_print, int len, size_t tty_len, size_t tty_off);
extern void dump_ethhdr_all(struct ethhdr *eth);
extern void dump_iphdr_all(struct iphdr *ip);

extern void versatile_print(uint8_t * rbb, const struct tpacket_hdr *tp, uint8_t pkttype);
extern void versatile_header_only_print(uint8_t * rbb, const struct tpacket_hdr *tp, uint8_t pkttype);
extern void versatile_hex_cstyle_print(uint8_t * rbb, const struct tpacket_hdr *tp, uint8_t pkttype);
extern void payload_human_only_print(uint8_t * rbb, const struct tpacket_hdr *tp, uint8_t pkttype);
extern void payload_hex_only_print(uint8_t * rbb, const struct tpacket_hdr *tp, uint8_t pkttype);
extern void all_hex_only_print(uint8_t * rbb, const struct tpacket_hdr *tp, uint8_t pkttype);
extern void reduced_print(uint8_t * rbb, const struct tpacket_hdr *tp, uint8_t pkttype);
extern void regex_print(uint8_t * rbb, const struct tpacket_hdr *tp, uint8_t pkttype);

extern void init_regex(char *pattern);
extern void cleanup_regex(void);

#endif				/* _NET_PRINT_H_ */

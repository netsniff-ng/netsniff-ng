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
 *    Internal data types
 */

#ifndef _NET_TYPES_H_
#define _NET_TYPES_H_

/*
 * Internal data structures
 */

typedef uint8_t               *ring_buff_bytes_t;

typedef struct ring_buff_private {
        ring_buff_bytes_t      buffer;
        uint32_t               len;
        struct tpacket_req     layout;
        struct iovec          *frames;
        struct sockaddr_ll     params;
} ring_buff_t;

typedef struct frame_map {
        struct tpacket_hdr     tp_h __attribute__((aligned(TPACKET_ALIGNMENT)));
        struct sockaddr_ll     s_ll __attribute__((aligned(TPACKET_ALIGNMENT)));
} frame_map_t;

#endif /* _NET_TYPES_H_ */

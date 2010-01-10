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
 * Copyright (C) 2009  Daniel Borkmann <danborkmann@googlemail.com>
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

/*
 * Contains: 
 *    External structures for a unix domain socket client
 */

#ifndef _NETSNIFF_NG_H_
#define _NETSNIFF_NG_H_

#include <stdint.h>
#include <time.h>

#include <sys/time.h>

/**
 * Some external data structures (wich are used for
 * data transmission via a unix domain socket inode)
 */

struct fb_count {
	uint64_t frames;
	uint64_t bytes;
};

typedef struct ring_buff_private_stat {
	struct fb_count total;
	struct fb_count per_sec;
	struct fb_count per_min;
	struct fb_count s_per_sec;
	struct fb_count s_per_min;
	uint16_t t_elapsed;
	struct timespec m_start;
} ring_buff_stat_t;

#endif				/* _NETSNIFF_NG_H_ */

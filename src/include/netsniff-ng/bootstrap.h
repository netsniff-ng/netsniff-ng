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

/*
 * Contains: 
 *    Routines for starting / stopping the beast ;)
 */

#ifndef _NET_BOOTSTRAP_H_
#define _NET_BOOTSTRAP_H_

#include <sys/poll.h>

#include <netsniff-ng/types.h>
#include <netsniff-ng/config.h>

extern int init_system(system_data_t * sd, int *sock, ring_buff_t ** rb, struct pollfd *pfd);
extern void cleanup_system(system_data_t * sd, int *sock, ring_buff_t ** rb);

#endif				/* _NET_BOOTSTRAP_H_ */

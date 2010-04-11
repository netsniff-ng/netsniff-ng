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

/* External IPC API */

#ifndef _NETSNIFF_NG_H_
#define _NETSNIFF_NG_H_

#define MAX_SEGMENT_LEN 256

struct netsniff_msg {
	long int    pid;                     /* Programs process id */
	int         type;                    /* Message type */
	char        buff[MAX_SEGMENT_LEN];   /* Message buffer */
};

#endif /* _NETSNIFF_NG_H_ */

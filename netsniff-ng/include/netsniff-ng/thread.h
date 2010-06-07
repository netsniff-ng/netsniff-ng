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

#ifndef	_NET_THREAD_H_
#define	_NET_THREAD_H_

enum netsniff_ng_thread_type
{
	RX_THREAD,
	TX_THREAD,
	SPINNER_THREAD,
};

struct netsniff_ng_thread_context
{
	pthread_t			thread;
	pthread_attr_t			thread_attr;
	pthread_mutex_t			wait_mutex;
	pthread_cond_t			wait_cond;
	pthread_spinlock_t		config_lock;
	cpu_set_t			run_on;
	enum netsniff_ng_thread_type 	type;
};

#endif	/* _NET_THREAD_H_ */

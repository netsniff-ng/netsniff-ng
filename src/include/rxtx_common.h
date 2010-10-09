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

#ifndef _NET_RXTX_COMMON_H_
#define _NET_RXTX_COMMON_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

#include <sys/poll.h>

#include "macros.h"
#include "types.h"
#include "xmalloc.h"

#ifndef POLLRDNORM
# define POLLRDNORM      0x0040
#endif
#ifndef POLLWRNORM
# define POLLWRNORM      0x0100
#endif

/* Inline stuff */

 /**
 * prepare_polling - Sets params for ringbuff polling
 * @sock:           socket
 * @pfd:            file descriptor for polling
 */
static inline void prepare_polling(int sock, struct pollfd *pfd)
{
	assert(pfd);

	memset(pfd, 0, sizeof(*pfd));

	pfd->fd = sock;
	pfd->revents = 0;
	pfd->events = POLLIN | POLLRDNORM | POLLOUT | POLLWRNORM | POLLERR;
}

/**
 * alloc_frame_buffer - Allocates frame buffer
 * @rb:                ring buff struct
 */
static inline void alloc_frame_buffer(struct ring_buff *rb)
{
	int i = 0;

	assert(rb);

	rb->frames = xzmalloc(rb->layout.tp_frame_nr * sizeof(*rb->frames));

	for (i = 0; i < rb->layout.tp_frame_nr; ++i) {
		rb->frames[i].iov_base = (uint8_t *) ((long)rb->buffer) +
		    (i * rb->layout.tp_frame_size);
		rb->frames[i].iov_len = rb->layout.tp_frame_size;
	}
}

#endif				/* _NET_RXTX_COMMON_H_ */

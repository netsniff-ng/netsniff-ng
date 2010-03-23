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
 * This file contains a ringbuffer implementation for data exchange via 
 * Netlink protocol and can be used for fetching samples of the netdata 
 * (for instance).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>

#include <netsniff-ng/ringbuff.h>
#include <netsniff-ng/macros.h>

int ringbuffer_init(ringbuffer_t ** rb, size_t slots)
{
	ringbuffer_offs_t i, j, rc = 0;

	if (rb == NULL || slots == 0)
		return -EINVAL;

	(*rb) = malloc(sizeof(**rb));
	if ((*rb) == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	memset((*rb), 0, sizeof(**rb));

	(*rb)->ring = malloc(sizeof(*((*rb)->ring)) * slots);
	if ((*rb)->ring == NULL) {
		rc = -ENOMEM;
		goto clean_out;
	}

	for (i = 0; i < slots; ++i) {
		(*rb)->ring[i] = malloc(sizeof(**((*rb)->ring)));
		if ((*rb)->ring[i] == NULL) {
			rc = -ENOMEM;
			goto clean_out_ring;
		}

		memset((*rb)->ring[i], 0, sizeof(**((*rb)->ring)));
		(*rb)->ring[i]->ch_status = CHUNK_STATUS_FREE;
	}

	(*rb)->max_slots = slots;
	(*rb)->cur_slots = 0;
	(*rb)->next_free = 0;
	(*rb)->next_user = 0;

	return 0;

 clean_out_ring:
	for (j = 0; j < i; ++j) {
		free((*rb)->ring[j]);
	}
	free((*rb)->ring);
 clean_out:
	free((*rb));
 out:
	return rc;
}

void ringbuffer_cleanup(ringbuffer_t * rb)
{
	ringbuffer_offs_t i;

	if (rb == NULL)
		return;
	for (i = 0; i < rb->max_slots; ++i)
		free(rb->ring[i]);
	free(rb->ring);
	free(rb);
}

int ringbuffer_put(ringbuffer_t * rb, ringbuffer_user_t * rb_data)
{
	if (rb == NULL || rb_data == NULL)
		return -EINVAL;
	if (rb->max_slots == rb->cur_slots)
		return -ENOMEM;
	if (rb->ring[rb->next_free]->ch_status == CHUNK_STATUS_BUSY)
		return -EBUSY;

	assert(sizeof(*rb_data) == sizeof(rb->ring[rb->next_free]->ch_user));

	/* FIXME: shared mmap */
	memcpy(&rb->ring[rb->next_free]->ch_user, rb_data, sizeof(*rb_data));

	rb->ring[rb->next_free]->ch_status = CHUNK_STATUS_BUSY;
	rb->next_free = (rb->next_free + 1) % rb->max_slots;
	rb->cur_slots++;

	return 0;
}

int ringbuffer_get(ringbuffer_t * rb, ringbuffer_user_t * rb_data)
{
	if (rb == NULL || rb_data == NULL)
		return -EINVAL;
	if (rb->ring[rb->next_user]->ch_status == CHUNK_STATUS_FREE)
		return -ENODATA;

	assert(sizeof(*rb_data) == sizeof(rb->ring[rb->next_user]->ch_user));

	/* FIXME: shared mmap */
	memcpy(rb_data, &rb->ring[rb->next_user]->ch_user, sizeof(*rb_data));

	rb->ring[rb->next_user]->ch_status = CHUNK_STATUS_FREE;
	rb->next_user = (rb->next_user + 1) % rb->max_slots;
	rb->cur_slots--;

	return 0;
}

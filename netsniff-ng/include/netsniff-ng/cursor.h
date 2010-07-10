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

#ifndef _CURSOR_H_
#define _CURSOR_H_

#include <stdint.h>

#define MAX_MESSAGE_SIZE	64

struct spinner_thread_context {
	pthread_t thread;
	uint8_t active;
	char msg[MAX_MESSAGE_SIZE];
	uint64_t events;
};

/* Function signatures */

extern void *print_progress_spinner(void *arg);
extern void spinner_trigger_event(struct spinner_thread_context *ctx);
extern void spinner_set_msg(struct spinner_thread_context *ctx, const char *msg);
extern void spinner_cancel(struct spinner_thread_context *ctx);
extern int spinner_create(struct spinner_thread_context *ctx);

#endif				/* _CURSOR_H_ */

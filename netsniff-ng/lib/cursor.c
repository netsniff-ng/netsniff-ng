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

#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>

#include <netsniff-ng/cursor.h>
#include <netsniff-ng/macros.h>

#define SPINNER_SLEEP_TIME	250000

static const char spinning_chars[] = { '|', '/', '-', '\\' };

void spinner_trigger_event(struct spinner_thread_context * ctx)
{
	ctx->events++;
}

void spinner_set_msg(struct spinner_thread_context * ctx, const char * msg)
{
	assert(ctx);
	assert(msg);

	strncpy(ctx->msg, msg, sizeof(ctx->msg) - 1);
}

void spinner_cancel(struct spinner_thread_context * ctx)
{
	if (ctx->active)
		pthread_cancel(ctx->thread);
}

int spinner_create(struct spinner_thread_context * ctx)
{
	return (pthread_create(&ctx->thread, NULL, print_progress_spinner, ctx));
}

void * print_progress_spinner(void * arg)
{
	uint8_t	spin_count = 0;
	uint64_t prev_events = 0;
	struct spinner_thread_context * ctx = (struct spinner_thread_context *) arg;

	ctx->active = 1;

	info("%s", ctx->msg);

	while (1) {
		info("\b%c", spinning_chars[spin_count]);
		fflush(stdout);
		usleep(SPINNER_SLEEP_TIME);

		if (prev_events != ctx->events)
		{
			spin_count++;
			spin_count %= sizeof(spinning_chars);
			prev_events = ctx->events;
		}
	}
}


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
#include <limits.h>

#include <netsniff-ng/cursor.h>
#include <netsniff-ng/macros.h>

static char spinning_chars[] = { '|', '/', '-', '\\' };

static int spinning_count = 0;

volatile sig_atomic_t cursor_prog_intr = 0;
static volatile sig_atomic_t cursor_prog_trigger = 0;

void *print_progress_spinner_static(void *msg)
{
	info("%s", (char *)msg);

	while (likely(!cursor_prog_intr)) {
		info("\b%c", spinning_chars[spinning_count++ % sizeof(spinning_chars)]);
		fflush(stdout);
		usleep(25000);
	}

	pthread_exit(0);
}

void *print_progress_spinner_dynamic(void *msg)
{
	unsigned int idle = 0;
	info("%s", (char *)msg);

	while (likely(!cursor_prog_intr)) {
		info("\b%c", spinning_chars[spinning_count++ % sizeof(spinning_chars)]);
		fflush(stdout);
		while (likely(!cursor_prog_trigger)) {
			if (idle++ % UINT_MAX)
				break;
		}
		cursor_prog_trigger = 0;
	}

	pthread_exit(0);
}

void print_progress_spinner_dynamic_trigger(void)
{
	cursor_prog_trigger = 0;
}

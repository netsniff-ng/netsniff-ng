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
 *    A simple spinning command line cursor
 */

#ifndef _CURSOR_H_
#define _CURSOR_H_

#include <signal.h>

extern volatile sig_atomic_t cursor_prog_intr;

/* Function signatures */

extern void *print_progress_spinner_static(void *msg);
extern void *print_progress_spinner_dynamic(void *msg);
extern void print_progress_spinner_dynamic_trigger(void);

/* Inline stuff */

#define enable_print_progress_spinner()		\
	do {					\
		cursor_prog_intr = 0;		\
	} while (0);

#define disable_print_progress_spinner()	\
	do {					\
		cursor_prog_intr = 1;		\
		info("\n");			\
		fflush(stdout);			\
	} while (0);

#endif				/* _CURSOR_H_ */

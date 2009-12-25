/* XXX: Coding Style - use the tool indent with the following (Linux kernel
 *                     code indentions)
 *
 * indent -nbad -bap -nbc -bbo -hnl -br -brs -c33 -cd33 -ncdb -ce -ci4  \
 *        -cli0 -d0 -di1 -nfc1 -i8 -ip0 -l80 -lp -npcs -nprs -npsl -sai \
 *        -saf -saw -ncs -nsc -sob -nfca -cp33 -ss -ts8 -il1
 *
 *
 * netsniff-ng
 *
 * High performance network sniffer for packet inspection
 *
 * Copyright (C) 2009, 2010  Daniel Borkmann <danborkmann@googlemail.com>
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
 *
 * Note: Your kernel has to be compiled with CONFIG_PACKET_MMAP=y option in 
 *       order to use this.
 */

/*
 * Contains: 
 *    Some miscellaneous stuff
 */

#ifndef _NET_MISC_H_
#define _NET_MISC_H_

#include <time.h>
#include <sys/time.h>

/* Function signatures */

extern void help(void);
extern void version(void);
extern void header(void);

/* Inline stuff */

/**
 * timespec_subtract - Subtracts two timespecs
 * @result:           result
 * @after:            second timespec
 * @before:           first timespec
 */
static inline int timespec_subtract(struct timespec *result,
				    struct timespec *after,
				    struct timespec *before)
{
	result->tv_nsec = after->tv_nsec - before->tv_nsec;

	if (result->tv_nsec < 0) {
		/* Borrow 1sec from 'tv_sec' if subtraction -ve */
		result->tv_nsec += 1000000000;
		result->tv_sec = after->tv_sec - before->tv_sec - 1;
		return (1);
	} else {
		result->tv_sec = after->tv_sec - before->tv_sec;
		return (0);
	}
}

#endif				/* _NET_MISC_H_ */

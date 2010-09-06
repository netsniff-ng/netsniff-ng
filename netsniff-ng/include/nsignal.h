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

#ifndef _NET_SIGNAL_H_
#define _NET_SIGNAL_H_

#include <stdio.h>
#include <stdarg.h>
#include <signal.h>

#include "misc.h"

extern volatile sig_atomic_t sigint;

/* Function signatures */

static inline void register_softirq(int sig, void (*softirq_handler) (int));
static inline void hold_softirq(int num_count, ...);
static inline void restore_softirq(int num_count, ...);
static inline void hold_softirq_pthread(int num_count, ...);

/* Inline stuff */

/**
 * register_softirq - Registers signal + signal handler function
 * @signal:          signal number
 * @softirq_handler: signal handler function
 */
static inline void register_softirq(int signal, void (*softirq_handler) (int))
{
	sigset_t block_mask;
	struct sigaction saction;

	assert(softirq_handler);

	sigfillset(&block_mask);

	saction.sa_handler = softirq_handler;
	saction.sa_mask = block_mask;
	saction.sa_flags = SA_RESTART;

	sigaction(signal, &saction, NULL);
}

/**
 * hold_softirq - Set defined signals to blocking 
 * @...:         signals (type of int)
 */
static inline void hold_softirq(int num_count, ...)
{
	int i;
	int signal;

	va_list al;
	sigset_t block_mask;

	sigemptyset(&block_mask);
	va_start(al, num_count);

	for (i = 1; i <= num_count; ++i) {
		signal = va_arg(al, int);
		sigaddset(&block_mask, signal);
	}

	va_end(al);
	sigprocmask(SIG_BLOCK, &block_mask, NULL);
}

/**
 * restore_softirq - Unblocks and delivers pending signals
 * @...:            signals (type of int)
 */
static inline void restore_softirq(int num_count, ...)
{
	int i;
	int signal;

	va_list al;
	sigset_t block_mask;

	sigemptyset(&block_mask);
	va_start(al, num_count);

	for (i = 1; i <= num_count; ++i) {
		signal = va_arg(al, int);
		sigaddset(&block_mask, signal);
	}

	va_end(al);
	sigprocmask(SIG_UNBLOCK, &block_mask, NULL);
}

/**
 * hold_softirq - Set defined signals to blocking (for POSIX threads)
 * @...:         signals (type of int)
 */
static inline void hold_softirq_pthread(int num_count, ...)
{
	int i;
	int signal;

	va_list al;
	sigset_t block_mask;

	sigemptyset(&block_mask);
	va_start(al, num_count);

	for (i = 1; i <= num_count; ++i) {
		signal = va_arg(al, int);
		sigaddset(&block_mask, signal);
	}

	va_end(al);
	pthread_sigmask(SIG_BLOCK, &block_mask, NULL);
}

/* XXX is there a need for a restore_softirq_pthread ? */

/*
 * Signal handling
 */

extern struct ring_buff_stat netstat;
extern pthread_mutex_t gs_loc_mutex;

/**
 * refresh_counters - Refreshes global packet counters
 * TODO: this looks ugly
 */
static inline void refresh_counters(void)
{
	float curr_weight = 0.68f;

	netstat.per_min.frames += netstat.per_sec.frames;
	netstat.per_min.bytes += netstat.per_sec.bytes;

	netstat.t_elapsed++;

	if (unlikely(netstat.t_elapsed % 60 == 0)) {
		netstat.s_per_min.frames =
		    curr_weight * netstat.per_min.frames + (1.f - curr_weight) * netstat.s_per_min.frames;
		netstat.s_per_min.bytes =
		    curr_weight * netstat.per_min.bytes + (1.f - curr_weight) * netstat.s_per_min.bytes;

		netstat.per_min.frames = netstat.per_min.bytes = 0;
	}

	netstat.s_per_sec.frames =
	    curr_weight * netstat.per_sec.frames + (1.f - curr_weight) * netstat.s_per_sec.frames;
	netstat.s_per_sec.bytes = curr_weight * netstat.per_sec.bytes + (1.f - curr_weight) * netstat.s_per_sec.bytes;

	netstat.per_sec.frames = netstat.per_sec.bytes = 0;
}

/**
 * print_counters - Prints global counters to terminal
 * TODO: this looks ugly
 */
static inline void print_counters(void)
{
	struct timespec t_curr, diff;
	unsigned long long d_day, d_h, d_min, d_sec, d_nsec;

	clock_gettime(CLOCK_REALTIME, &t_curr);
	timespec_subtract(&diff, &t_curr, &netstat.m_start);

	d_day = DIV_S2DAYS(diff.tv_sec);
	diff.tv_sec = MOD_DAYS2S(diff.tv_sec);
	d_h = DIV_S2HOURS(diff.tv_sec);
	diff.tv_sec = MOD_HOURS2S(diff.tv_sec);
	d_min = DIV_S2MINUT(diff.tv_sec);
	diff.tv_sec = MOD_MINUT2S(diff.tv_sec);
	d_sec = diff.tv_sec;
	d_nsec = diff.tv_nsec;

	/*
	 * FIXME Find a way to print a uint64_t
	 * on 32 and 64 bit arch w/o gcc warnings
	 */
	info("stats summary:\n");
	info("--------------------------------------------------------------------------------------------\n");
	info("elapsed time: %llu d, %llu h, %llu min, %llu s, %llu ns\n", d_day, d_h, d_min, d_sec, d_nsec);
	info("-----------+--------------------------+--------------------------+--------------------------\n");
	info("           |  per sec                 |  per min                 |  total                   \n");
	info("-----------+--------------------------+--------------------------+--------------------------\n");
	info("  frames   | %24llu | %24llu | %24llu \n",
	     netstat.s_per_sec.frames, netstat.s_per_min.frames, netstat.total.frames);
	info("-----------+--------------------------+--------------------------+--------------------------\n");
	info("  in B     | %24llu | %24llu | %24llu \n",
	     netstat.s_per_sec.bytes, netstat.s_per_min.bytes, netstat.total.bytes);
	info("  in KB    | %24llu | %24llu | %24llu \n",
	     DIV_KBYTES(netstat.s_per_sec.bytes), DIV_KBYTES(netstat.s_per_min.bytes), DIV_KBYTES(netstat.total.bytes));
	info("  in MB    | %24llu | %24llu | %24llu \n",
	     DIV_MBYTES(netstat.s_per_sec.bytes), DIV_MBYTES(netstat.s_per_min.bytes), DIV_MBYTES(netstat.total.bytes));
	info("  in GB    | %24llu | %24llu | %24llu \n",
	     DIV_GBYTES(netstat.s_per_sec.bytes), DIV_GBYTES(netstat.s_per_min.bytes), DIV_GBYTES(netstat.total.bytes));
	info("-----------+--------------------------+--------------------------+--------------------------\n\n");
}

#endif				/* _NET_SIGNAL_H_ */

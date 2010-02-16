/* XXX: Coding Style - use the tool indent with the following (Linux kernel
 *                     code indents)
 *
 * indent -nbad -bap -nbc -bbo -hnl -br -brs -c33 -cd33 -ncdb -ce -ci4   \
 *        -cli0 -d0 -di1 -nfc1 -i8 -ip0 -l120 -lp -npcs -nprs -npsl -sai \
 *        -saf -saw -ncs -nsc -sob -nfca -cp33 -ss -ts8 -il1
 *
 *
 * netsniff-ng
 *
 * High performance network sniffer for packet inspection
 *
 * Copyright (C) 2009, 2010  Daniel Borkmann <danborkmann@googlemail.com> and 
 *                           Emmanuel Roullit <emmanuel.roullit@googlemail.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>

#include <netsniff-ng/types.h>
#include <netsniff-ng/misc.h>
#include <netsniff-ng/rx_ring.h>
#include <netsniff-ng/macros.h>
#include <netsniff-ng/config.h>
#include <netsniff-ng/bootstrap.h>

/*
 * Global vars
 */

volatile sig_atomic_t sigint = 0;
volatile sig_atomic_t sigusr2 = 0;

ring_buff_stat_t netstat;
pthread_mutex_t gs_loc_mutex;

/*
 * Functions
 */

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
	uint64_t d_day, d_h, d_min, d_sec, d_nsec;

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
	info("-----------+--------------------------+--------------------------+--------------------------\n");
}

/**
 * softirq_handler - Signal handling multiplexer
 * @number:         signal number
 */
void softirq_handler(int number)
{
	switch (number) {
	case SIGALRM:
		refresh_counters();
		break;
	case SIGUSR1:
		print_counters();
		break;
	case SIGINT:
		sigint = 1;
		info("caught SIGINT! ... bye bye\n");
		break;
	case SIGHUP:
		info("caught SIGHUP! ... ignoring\n");
		break;
	default:
		break;
	}
}

/**
 * main  - Main routine
 * @argc: number of args
 * @argv: arguments passed from tty
 */
int main(int argc, char **argv)
{
	int sock;
	ring_buff_t *rb;
	system_data_t sd = { 0 };
	struct pollfd pfd = { 0 };

	/*
	 * Config stuff
	 */

	init_configuration(&sd);
	set_configuration(argc, argv, &sd);
	check_config(&sd);

	/*
	 * Main stuff
	 */

	init_system(&sd, &sock, &rb, &pfd);
	fetch_packets(rb, &pfd, &sd, sock);
	cleanup_system(&sd, &sock, &rb);

	return 0;
}

/* XXX: Coding Style - use the tool indent with the following (Linux kernel
 *                     code indents)
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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <pthread.h>
#include <netsniff-ng.h>

#include <sys/un.h>
#include <sys/types.h>
#include <sys/poll.h>

#include <netsniff-ng/misc.h>
#include <netsniff-ng/system.h>
#include <netsniff-ng/rx_ring.h>
#include <netsniff-ng/signal.h>
#include <netsniff-ng/macros.h>
#include <netsniff-ng/types.h>
#include <netsniff-ng/print.h>

/*
 * Global vars
 */

volatile sig_atomic_t sigint = 0;
ring_buff_stat_t netstat;
pthread_mutex_t gs_loc_mutex;

fetch_packets_from_ring_t fetch_packets = NULL;
print_packet_buff_t print_packet_buffer = print_packet_buffer_mode_1;

/*
 * Functions
 */

/**
 * refresh_counters - Refreshes global packet counters
 */
static inline void refresh_counters(void)
{
	float curr_weight = 0.68f;

	netstat.per_min.frames += netstat.per_sec.frames;
	netstat.per_min.bytes += netstat.per_sec.bytes;

	netstat.t_elapsed++;

	if (unlikely(netstat.t_elapsed % 60 == 0)) {
		netstat.s_per_min.frames =
		    curr_weight * netstat.per_min.frames + (1.f -
							    curr_weight) *
		    netstat.s_per_min.frames;
		netstat.s_per_min.bytes =
		    curr_weight * netstat.per_min.bytes + (1.f -
							   curr_weight) *
		    netstat.s_per_min.bytes;

		netstat.per_min.frames = netstat.per_min.bytes = 0;
	}

	netstat.s_per_sec.frames =
	    curr_weight * netstat.per_sec.frames + (1.f -
						    curr_weight) *
	    netstat.s_per_sec.frames;
	netstat.s_per_sec.bytes =
	    curr_weight * netstat.per_sec.bytes + (1.f -
						   curr_weight) *
	    netstat.s_per_sec.bytes;

	netstat.per_sec.frames = netstat.per_sec.bytes = 0;
}

/**
 * print_counters - Prints global counters to terminal
 */
static inline void print_counters(void)
{
	uint64_t d_day, d_h, d_min, d_sec, d_nsec;

	struct timespec t_curr, diff;

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

	dbg("stats summary:\n");
	dbg("--------------------------------------------------------------------------------------------\n");
	dbg("elapsed time: %llu d, %llu h, %llu min, %llu s, %llu ns\n", d_day,
	    d_h, d_min, d_sec, d_nsec);
	dbg("-----------+--------------------------+--------------------------+--------------------------\n");
	dbg("           |  per sec                 |  per min                 |  total                   \n");
	dbg("-----------+--------------------------+--------------------------+--------------------------\n");
	dbg("  frames   | %24llu | %24llu | %24llu \n",
	    netstat.s_per_sec.frames, netstat.s_per_min.frames,
	    netstat.total.frames);
	dbg("-----------+--------------------------+--------------------------+--------------------------\n");
	dbg("  in B     | %24llu | %24llu | %24llu \n", netstat.s_per_sec.bytes,
	    netstat.s_per_min.bytes, netstat.total.bytes);
	dbg("  in KB    | %24llu | %24llu | %24llu \n",
	    DIV_KBYTES(netstat.s_per_sec.bytes),
	    DIV_KBYTES(netstat.s_per_min.bytes),
	    DIV_KBYTES(netstat.total.bytes));
	dbg("  in MB    | %24llu | %24llu | %24llu \n",
	    DIV_MBYTES(netstat.s_per_sec.bytes),
	    DIV_MBYTES(netstat.s_per_min.bytes),
	    DIV_MBYTES(netstat.total.bytes));
	dbg("  in GB    | %24llu | %24llu | %24llu \n",
	    DIV_GBYTES(netstat.s_per_sec.bytes),
	    DIV_GBYTES(netstat.s_per_min.bytes),
	    DIV_GBYTES(netstat.total.bytes));
	dbg("-----------+--------------------------+--------------------------+--------------------------\n");
}

/**
 * uds_thread - Unix Domain Socket thread for sending internal counter states
 * @psock:     socket pointer
 */
static void *uds_thread(void *psock)
{
	int ret;
	int sock;

	/* Signalmask is per thread. we don't want to interrupt the 
	   send-syscall */
	hold_softirq_pthread(SIGUSR1, SIGALRM);

	dbg("unix domain socket server: entering thread\n");
	sock = *((int *)psock);

	pthread_mutex_lock(&gs_loc_mutex);

	ret = send(sock, &netstat, sizeof(netstat), 0);
	if (ret < 0) {
		perr("cannot send ring buffer stats - ");
	}

	pthread_mutex_unlock(&gs_loc_mutex);

	close(sock);

	dbg("unix domain socket server: quitting thread\n");
	pthread_exit(0);
}

/**
 * start_uds_server - Unix Domain Socket server main
 * @psockfile:       path to UDS inode
 */
void *start_uds_server(void *psockfile)
{
	int ret, len;
	int sock, sock2;

	char *sockfile = (char *)psockfile;

	pthread_t tid;

	struct sockaddr_un local;
	struct sockaddr_un remote;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		perr("cannot create uds socket %d - ", errno);
		pthread_exit(0);
	}

	local.sun_family = AF_UNIX;
	strncpy(local.sun_path, sockfile, sizeof(local.sun_path));
	unlink(local.sun_path);

	len = strlen(local.sun_path) + sizeof(local.sun_family);

	dbg("bind socket to %s\n", local.sun_path);

	ret = bind(sock, (struct sockaddr *)&local, len);
	if (ret < 0) {
		perr("cannot bind uds socket %d - ", errno);
		pthread_exit(0);
	}

	ret = listen(sock, INTERNAL_UDS_QUEUE_LEN);
	if (ret < 0) {
		perr("cannot set up uds listening queue %d - ", errno);
		pthread_exit(0);
	}

	while (1) {
		size_t t = sizeof(remote);
		dbg("unix domain socket server: waiting for a connection\n");

		sock2 =
		    accept(sock, (struct sockaddr *)&remote, (socklen_t *) & t);
		if (sock2 < 0) {
			perr("cannot do accept on uds socket %d - ", errno);
			pthread_exit(0);
		}

		dbg("unix domain socket server: connected to client\n");

		/* We're not interested in joining... 
		   so a single thread id is sufficient */
		ret = pthread_create(&tid, NULL, uds_thread, &sock2);
		if (ret < 0) {
			perr("uds server: error creating thread - ");
			pthread_exit(0);
		}

		pthread_detach(tid);
	}

	dbg("unix domain socket server: quit\n");
	pthread_exit(0);
}

/**
 * softirq_handler - Signal handling multiplexer
 * @number:         signal number
 */
void softirq_handler(int number)
{
	switch (number) {
	case SIGALRM:
		{
			refresh_counters();
			break;
		}
	case SIGUSR1:
		{
			print_counters();
			break;
		}
	case SIGUSR2:
		{
			// TODO: switch main loop functions
			break;
		}
	case SIGINT:
		{
			sigint = 1;
			dbg("caught SIGINT! ... bye bye\n");
			break;
		}
	case SIGHUP:
		{
			dbg("caught SIGHUP! ... ignoring\n");
			break;
		}
	default:
		{
			break;
		}
	}
}

/**
 * fetch_packets_and_print - Traverses RX_RING and prints content
 * @rb:                     ring buffer
 * @pfd:                    file descriptor for polling
 */
void fetch_packets_and_print(ring_buff_t * rb, struct pollfd *pfd)
{
	int i = 0;

	while (likely(!sigint)) {
		while (mem_notify_user(rb->frames[i]) && likely(!sigint)) {
			struct frame_map *fm = rb->frames[i].iov_base;
			ring_buff_bytes_t *rbb =
			    (ring_buff_bytes_t *) (rb->frames[i].iov_base +
						   sizeof(*fm) + sizeof(short));

			print_packet_buffer(rbb, fm->tp_h.tp_len);

			/* Pending singals will be delivered after netstat 
			   manipulation */
			hold_softirq(SIGUSR1, SIGALRM);
			pthread_mutex_lock(&gs_loc_mutex);

			netstat.per_sec.frames++;
			netstat.per_sec.bytes += fm->tp_h.tp_len;

			netstat.total.frames++;
			netstat.total.bytes += fm->tp_h.tp_len;

			pthread_mutex_unlock(&gs_loc_mutex);
			restore_softirq(SIGUSR1, SIGALRM);

			i = (i + 1) % rb->layout.tp_frame_nr;

			/* This is very important, otherwise poll() does active 
			   wait with 100% cpu */
			mem_notify_kernel(&(fm->tp_h));
		}

		poll(pfd, 1, -1);
	}
}

/**
 * fetch_packets_no_print - Traverses RX_RING in silent mode, only updates counter
 * @rb:                    ring buffer
 * @pfd:                   file descriptor for polling
 */
void fetch_packets_no_print(ring_buff_t * rb, struct pollfd *pfd)
{
	int i = 0;

	while (likely(!sigint)) {
		while (mem_notify_user(rb->frames[i]) && likely(!sigint)) {
			struct frame_map *fm = rb->frames[i].iov_base;

			/* Pending singals will be delivered after netstat 
			   manipulation */
			hold_softirq(SIGUSR1, SIGALRM);
			pthread_mutex_lock(&gs_loc_mutex);

			netstat.per_sec.frames++;
			netstat.per_sec.bytes += fm->tp_h.tp_len;

			netstat.total.frames++;
			netstat.total.bytes += fm->tp_h.tp_len;

			pthread_mutex_unlock(&gs_loc_mutex);
			restore_softirq(SIGUSR1, SIGALRM);

			i = (i + 1) % rb->layout.tp_frame_nr;

			/* This is very important, otherwise poll() does active 
			   wait with 100% cpu */
			mem_notify_kernel(&(fm->tp_h));
		}

		poll(pfd, 1, -1);
	}
}

/**
 * init_system - Initializes netsniff-ng main
 * @sd:         system configuration data
 * @sock:       socket
 * @rb:         ring buffer
 * @pfd:        file descriptor for polling
 */
static int init_system(system_data_t * sd, int *sock, ring_buff_t ** rb,
		       struct pollfd *pfd)
{
	int ret, bpf_len = 0;

	struct sock_filter **bpf;
	struct itimerval val_r;

	/* We are only allowed to do these nasty things as root ;) */
	check_for_root();

	/* Scheduler timeslice & prio tuning */
	set_proc_prio(DEFAULT_PROCESS_PRIO);
	set_sched_status(DEFAULT_SCHED_POLICY, DEFAULT_SCHED_PRIO);

	register_softirq(SIGINT, &softirq_handler);
	register_softirq(SIGALRM, &softirq_handler);
	register_softirq(SIGUSR1, &softirq_handler);
	register_softirq(SIGUSR2, &softirq_handler);
	register_softirq(SIGHUP, &softirq_handler);

	if (sd->sysdaemon) {
		ret =
		    daemonize(sd->pidfile, sd->logfile, sd->sockfile,
			      start_uds_server);
		if (ret != 0) {
			err("daemonize failed");
			exit(EXIT_FAILURE);
		}
	}

	/* Print program header */
	header();

	bpf = (struct sock_filter **)malloc(sizeof(*bpf));
	if (bpf == NULL) {
		perr("Cannot allocate socket filter\n");
		exit(EXIT_FAILURE);
	}

	memset(bpf, 0, sizeof(**bpf));

	(*rb) = (ring_buff_t *) malloc(sizeof(**rb));
	if ((*rb) == NULL) {
		perr("Cannot allocate ring buffer\n");
		exit(EXIT_FAILURE);
	}

	memset((*rb), 0, sizeof(**rb));

	(*sock) = alloc_pf_sock();
	put_dev_into_promisc_mode((*sock), ethdev_to_ifindex((*sock), sd->dev));

	/* Berkeley Packet Filter stuff */
	parse_rules(sd->rulefile, bpf, &bpf_len);
	inject_kernel_bpf((*sock), *bpf, bpf_len * sizeof(**bpf));

	/* RX_RING stuff */
	create_virt_ring((*sock), (*rb));
	bind_dev_to_ring((*sock), ethdev_to_ifindex((*sock), sd->dev), (*rb));
	mmap_virt_ring((*sock), (*rb));

	alloc_frame_buffer((*rb));
	prepare_polling((*sock), pfd);

	memset(&netstat, 0, sizeof(netstat));

	/* Timer settings for counter update */
	val_r.it_value.tv_sec = (INTERVAL_COUNTER_REFR / 1000);
	val_r.it_value.tv_usec = (INTERVAL_COUNTER_REFR * 1000) % 1000000;
	val_r.it_interval = val_r.it_value;

	ret = setitimer(ITIMER_REAL, &val_r, NULL);
	if (ret < 0) {
		perr("cannot set itimer - ");
		exit(EXIT_FAILURE);
	}

	clock_gettime(CLOCK_REALTIME, &netstat.m_start);

	free(*bpf);
	free(bpf);

	return 0;
}

/**
 * cleanup_system - Cleans up netsniff-ng main
 * @sd:            system configuration data
 * @sock:          socket
 * @rb:            ring buffer
 */
static void cleanup_system(system_data_t * sd, int *sock, ring_buff_t ** rb)
{
	net_stat((*sock));
	destroy_virt_ring((*sock), (*rb));

	free((*rb));
	close((*sock));

	dbg("captured frames: %llu, "
	    "captured bytes: %llu [%llu KB, %llu MB, %llu GB]\n",
	    netstat.total.frames, netstat.total.bytes,
	    netstat.total.bytes / 1024,
	    netstat.total.bytes / (1024 * 1024),
	    netstat.total.bytes / (1024 * 1024 * 1024));

	if (sd->sysdaemon) {
		undaemonize(sd->pidfile);
	}
}

/**
 * main  - Main routine
 * @argc: number of args
 * @argv: arguments passed from tty
 */
int main(int argc, char **argv)
{
	int i, c;
	int sock;

	system_data_t *sd;
	ring_buff_t *rb;
	struct pollfd pfd;

	sd = malloc(sizeof(*sd));
	if (!sd) {
		err("No mem left!\n");
		exit(EXIT_FAILURE);
	}

	memset(sd, 0, sizeof(*sd));

	/* Default is verbose mode */
	fetch_packets = fetch_packets_and_print;

	while ((c = getopt(argc, argv, "vhd:P:L:Df:sS:b:B:")) != EOF) {
		switch (c) {
		case 'h':
			{
				help();
				break;
			}
		case 'v':
			{
				version();
				break;
			}
		case 'd':
			{
				sd->dev = optarg;
				break;
			}
		case 'f':
			{
				sd->rulefile = optarg;
				break;
			}
		case 's':
			{
				/* Switch to silent mode */
				fetch_packets = fetch_packets_no_print;
				break;
			}
		case 'D':
			{
				sd->sysdaemon = 1;
				break;
			}
		case 'P':
			{
				sd->pidfile = optarg;
				break;
			}
		case 'L':
			{
				sd->logfile = optarg;
				break;
			}
		case 'S':
			{
				sd->sockfile = optarg;
				break;
			}
		case 'b':
			{
				set_cpu_affinity(optarg);
				break;
			}
		case 'B':
			{
				set_cpu_affinity(optarg);	/* TODO: inverted */
				break;
			}

		case '?':
			{
				switch (optopt) {
				case 'd':
				case 'f':
				case 'P':
				case 'L':
				case 'S':
				case 'b':
				case 'B':
					{
						fprintf(stderr,
							"option -%c requires an argument\n",
							optopt);
						break;
					}
				default:
					{
						if (isprint(optopt)) {
							fprintf(stderr,
								"unknown option character `0x%X\'\n",
								optopt);
						}
						break;
					}
				}

				return 1;
			}
		default:
			{
				abort();
			}
		}
	}

	if (argc < 2 || !sd->dev || !sd->rulefile) {
		help();
		exit(EXIT_FAILURE);
	}

	if (sd->sysdaemon && (!sd->pidfile || !sd->logfile || !sd->sockfile)) {
		help();
		exit(EXIT_FAILURE);
	}

	for (i = optind; i < argc; ++i) {
		err("non-option argument %s\n", argv[i]);
	}

	if (optind < argc) {
		exit(EXIT_FAILURE);
	}

	/*
	 * Main stuff
	 */

	init_system(sd, &sock, &rb, &pfd);
	fetch_packets(rb, &pfd);
	cleanup_system(sd, &sock, &rb);

	free(sd);
	return 0;
}

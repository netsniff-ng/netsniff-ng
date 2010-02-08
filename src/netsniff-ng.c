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
#include <getopt.h>
#include <netsniff-ng.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/ioctl.h>
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
#include <netsniff-ng/dump.h>
#include <netsniff-ng/netdev.h>
#include <netsniff-ng/bpf.h>

/*
 * Global vars
 */

volatile sig_atomic_t sigint = 0;
volatile sig_atomic_t sigusr2 = 0;

ring_buff_stat_t netstat;
pthread_mutex_t gs_loc_mutex;

print_packet_buff_t print_packet_buffer = versatile_print;

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
			switch (++sigusr2 % 2) {
			case 0:
				{
					print_packet_buffer = versatile_print;
					break;
				}
			case 1:
				{
					print_packet_buffer = NULL;
					break;
				}
			default:
				{
					print_packet_buffer = versatile_print;
					break;
				}
			}
			break;
		}
	case SIGINT:
		{
			sigint = 1;
			info("caught SIGINT! ... bye bye\n");
			break;
		}
	case SIGHUP:
		{
			info("caught SIGHUP! ... ignoring\n");
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
void fetch_packets(ring_buff_t * rb, struct pollfd *pfd, int timeout, FILE * pcap, int packet_type, int sock)
{
	int ret, foo, i = 0;

	assert(rb);
	assert(pfd);

	/* This is our critical path ... */
	while (likely(!sigint)) {
		while (mem_notify_user_for_rx(rb->frames[i]) && likely(!sigint)) {
			struct frame_map *fm = rb->frames[i].iov_base;
			ring_buff_bytes_t *rbb =
			    (ring_buff_bytes_t *) (rb->frames[i].iov_base + sizeof(*fm) + sizeof(short));

			/* Check if the user wants to have a specific 
			   packet type */
			if (packet_type != PACKET_DONT_CARE) {
				if (fm->s_ll.sll_pkttype != packet_type) {
					goto __out_notify_kernel;
				}
			}

			if (pcap != NULL) {
				pcap_dump(pcap, &fm->tp_h, (struct ethhdr *)rbb);
			}

			if (print_packet_buffer) {
				/* This path here slows us down ... well, but
				   the user wants to see what's going on */
				print_packet_buffer(rbb, &fm->tp_h);
			}

			/* Pending singals will be delivered after netstat 
			   manipulation */
			hold_softirq(2, SIGUSR1, SIGALRM);
			pthread_mutex_lock(&gs_loc_mutex);

			netstat.per_sec.frames++;
			netstat.per_sec.bytes += fm->tp_h.tp_len;

			netstat.total.frames++;
			netstat.total.bytes += fm->tp_h.tp_len;

			pthread_mutex_unlock(&gs_loc_mutex);
			restore_softirq(2, SIGUSR1, SIGALRM);

			/* Next frame */
			i = (i + 1) % rb->layout.tp_frame_nr;

 __out_notify_kernel:
			/* This is very important, otherwise kernel starts
			   to drop packages */
			mem_notify_kernel_for_rx(&(fm->tp_h));
		}

		while ((ret = poll(pfd, 1, timeout)) <= 0) {
			if (sigint) {
				return;
			}
		}

		if (ret > 0 && (pfd->revents & (POLLHUP | POLLRDHUP | POLLERR | POLLNVAL))) {
			if (pfd->revents & (POLLHUP | POLLRDHUP)) {
				err("Hangup on socket occured.\n\n");
				return;
			} else if (pfd->revents & POLLERR) {
				/* recv is more specififc on the error */
				errno = 0;
				if (recv(sock, &foo, sizeof(foo), MSG_PEEK) != -1)
					goto __out_grab_frame;	/* Hmm... no error */
				if (errno == ENETDOWN) {
					err("Interface went down\n\n");
				} else {
					err("%s\n\n", strerror(errno));
				}
				return;
			} else if (pfd->revents & POLLNVAL) {
				err("Invalid polling request on socket.\n\n");
				return;
			}
		}

 __out_grab_frame:
		/* Look-ahead if current frame is status kernel, otherwise we have
		   have incoming frames and poll spins / hangs all the time :( */
		for (; ((struct tpacket_hdr *)rb->frames[i].iov_base)->tp_status
		     != TP_STATUS_USER; i = (i + 1) % rb->layout.tp_frame_nr)
			/* NOP */ ;
		/* Why this should be okay:
		   1) Current frame[i] is TP_STATUS_USER:
		   This is our original case that occurs without 
		   the for loop.
		   2) Current frame[i] is not TP_STATUS_USER:
		   poll returns correctly with return value 1 (number of 
		   file descriptors), so an event has occured which has 
		   to be POLLIN since all error conditions have been 
		   caught previously. Furthermore, during ring traversal 
		   a frame that has been set to TP_STATUS_USER will be 
		   given back to kernel on finish with TP_STATUS_KERNEL.
		   So, if we look ahead all skipped frames are not ready 
		   for user access. Since the kernel decides to put 
		   frames, which are 'behind' our pointer, into 
		   TP_STATUS_USER we do one loop and return at the 
		   correct position after passing the for loop again. If 
		   we grab frame which are 'in front of' our pointer 
		   we'll fetch them within the first for loop. 
		 */
	}
}

/**
 * init_system - Initializes netsniff-ng main
 * @sd:         system configuration data
 * @sock:       socket
 * @rb:         ring buffer
 * @pfd:        file descriptor for polling
 */
static int init_system(system_data_t * sd, int *sock, ring_buff_t ** rb, struct pollfd *pfd)
{
	int stmp, i, ret, bpf_len = 0;
	char dev_buff[1024];

	struct sock_filter *bpf = NULL;
	struct ifconf ifc;
	struct ifreq *ifr = NULL;
	struct ifreq *ifr_elem = NULL;
	struct itimerval val_r;

	assert(sd);
	assert(sock);
	assert(rb);
	assert(pfd);

	/* We are only allowed to do these nasty things as root ;) */
	check_for_root();

	/* Scheduler timeslice & prio tuning */
	if (!sd->no_prioritization) {
		set_proc_prio(DEFAULT_PROCESS_PRIO);
		set_sched_status(DEFAULT_SCHED_POLICY, DEFAULT_SCHED_PRIO);
	}

	register_softirq(SIGINT, &softirq_handler);
	register_softirq(SIGALRM, &softirq_handler);
	register_softirq(SIGUSR1, &softirq_handler);
	register_softirq(SIGUSR2, &softirq_handler);
	register_softirq(SIGHUP, &softirq_handler);

	if (sd->sysdaemon) {
		ret = daemonize(sd->pidfile);
		if (ret != 0) {
			err("daemonize failed");
			exit(EXIT_FAILURE);
		}
	}

	/* Print program header */
	header();

	(*rb) = (ring_buff_t *) malloc(sizeof(**rb));
	if ((*rb) == NULL) {
		perr("Cannot allocate ring buffer\n");
		exit(EXIT_FAILURE);
	}

	memset((*rb), 0, sizeof(**rb));

	/* User didn't specify a device, so we switch to the default running 
	   dev. This is the first running dev found (except lo). If we find 
	   nothing, we switch to lo. */
	if (!sd->dev) {
		sd->dev = strdup("lo");
		if (!sd->dev) {
			perror("Cannot allocate mem");
			exit(EXIT_FAILURE);
		}

		stmp = socket(AF_INET, SOCK_DGRAM, 0);
		if (stmp < 0) {
			perror("socket");
			exit(EXIT_FAILURE);
		}

		ifc.ifc_len = sizeof(dev_buff);
		ifc.ifc_buf = dev_buff;

		if (ioctl(stmp, SIOCGIFCONF, &ifc) < 0) {
			perror("ioctl(SIOCGIFCONF)");
			exit(EXIT_FAILURE);
		}

		ifr = ifc.ifc_req;

		for (i = 0; i < ifc.ifc_len / sizeof(struct ifreq); ++i) {
			ifr_elem = &ifr[i];

			if (ioctl(stmp, SIOCGIFFLAGS, ifr_elem) < 0) {
				perror("ioctl(SIOCGIFFLAGS)");
				exit(EXIT_FAILURE);
			}

			if ((ifr_elem->ifr_flags & IFF_UP) &&
			    (ifr_elem->ifr_flags & IFF_RUNNING) && strncmp(ifr_elem->ifr_name, "lo", IFNAMSIZ)) {
				sd->dev = strdup(ifr_elem->ifr_name);
				if (!sd->dev) {
					perror("Cannot allocate mem");
					exit(EXIT_FAILURE);
				}
				break;
			}
		}

		close(stmp);

		info("No device specified, using `%s`.\n\n", sd->dev);
	}

	put_dev_into_promisc_mode(sd->dev);

	(*sock) = get_pf_socket();
	if (sd->bypass_bpf == BPF_NO_BYPASS) {
		/* XXX: If you try to create custom filters with tcpdump, you 
		   have to edit the ret opcode, otherwise your payload 
		   will be cut off at 96 Byte:

		   { 0x6, 0, 0, 0xFFFFFFFF },

		   The kernel now takes skb->len instead of 0xFFFFFFFF ;)
		 */

		/* Berkeley Packet Filter stuff */
		if (parse_rules(sd->rulefile, &bpf, &bpf_len) == 0) {
			info("BPF is not valid\n");
			exit(EXIT_FAILURE);
		}

		inject_kernel_bpf((*sock), bpf, bpf_len * sizeof(*bpf));

		/* Print info for the user */
		bpf_dump_all(bpf, bpf_len);
	} else {
		info("No filter applied. Sniffing all traffic.\n\n");
	}

	/* RX_RING stuff */
	create_virt_rx_ring((*sock), (*rb), sd->dev);
	bind_dev_to_rx_ring((*sock), ethdev_to_ifindex(sd->dev), (*rb));
	mmap_virt_rx_ring((*sock), (*rb));

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

	info("--- Listening ---\n\n");

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
	assert(sd);
	assert(sock);
	assert(rb);
	assert(*rb);

	net_stat((*sock));
	destroy_virt_rx_ring((*sock), (*rb));

	free((*rb));
	close((*sock));

	/*
	 * FIXME Find a way to print a uint64_t
	 * on 32 and 64 bit arch w/o gcc warnings
	 */

	info("captured frames: %llu, "
	     "captured bytes: %llu [%llu KiB, %llu MiB, %llu GiB]\n",
	     netstat.total.frames, netstat.total.bytes,
	     netstat.total.bytes / 1024,
	     netstat.total.bytes / (1024 * 1024), netstat.total.bytes / (1024 * 1024 * 1024));

	free(sd->dev);

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
	FILE *dump_pcap = NULL;
	int i, c, opt_idx;
	int sock;

	system_data_t *sd;
	ring_buff_t *rb;
	struct pollfd pfd;

	static struct option long_options[] = {
		{"dev", required_argument, 0, 'd'},
		{"dump", required_argument, 0, 'p'},
		{"replay", required_argument, 0, 'r'},
		{"quit-after", required_argument, 0, 'q'},
		{"generate", required_argument, 0, 'g'},
		{"type", required_argument, 0, 't'},
		{"filter", required_argument, 0, 'f'},
		{"bind-cpu", required_argument, 0, 'b'},
		{"unbind-cpu", required_argument, 0, 'B'},
		{"prio-norm", no_argument, 0, 'H'},
		{"non-block", no_argument, 0, 'n'},
		{"no-color", no_argument, 0, 'N'},
		{"silent", no_argument, 0, 's'},
		{"daemonize", no_argument, 0, 'D'},
		{"pidfile", required_argument, 0, 'P'},
		{"version", no_argument, 0, 'v'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	sd = malloc(sizeof(*sd));
	if (!sd) {
		err("No mem left!\n");
		exit(EXIT_FAILURE);
	}

	memset(sd, 0, sizeof(*sd));
	memset(&pfd, 0, sizeof(pfd));

	/* Some default sys configuration */
	sd->blocking_mode = POLL_WAIT_INF;
	sd->bypass_bpf = BPF_BYPASS;
	sd->packet_type = PACKET_DONT_CARE;

	while ((c = getopt_long(argc, argv, "vhd:p:P:Df:sb:B:Hnt:", long_options, &opt_idx)) != EOF) {
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
				sd->dev = strdup(optarg);
				if (!sd->dev) {
					perror("Cannot allocate mem");
					exit(EXIT_FAILURE);
				}
				break;
			}
		case 'n':
			{
				sd->blocking_mode = POLL_WAIT_NONE;
				break;
			}
		case 'H':
			{
				sd->no_prioritization = PROC_NO_HIGHPRIO;
				break;
			}
		case 't':
			{
				if (!strncmp(optarg, "host", strlen("host"))) {
					sd->packet_type = PACKET_HOST;
				} else if (!strncmp(optarg, "broadcast", strlen("broadcast"))) {
					sd->packet_type = PACKET_BROADCAST;
				} else if (!strncmp(optarg, "multicast", strlen("multicast"))) {
					sd->packet_type = PACKET_MULTICAST;
				} else if (!strncmp(optarg, "others", strlen("others"))) {
					sd->packet_type = PACKET_OTHERHOST;
				} else if (!strncmp(optarg, "outgoing", strlen("outgoing"))) {
					sd->packet_type = PACKET_OUTGOING;
				} else {
					sd->packet_type = PACKET_DONT_CARE;
				}
				break;
			}
		case 'f':
			{
				sd->bypass_bpf = BPF_NO_BYPASS;
				sd->rulefile = optarg;
				break;
			}
		case 's':
			{
				/* Switch to silent mode */
				print_packet_buffer = NULL;
				break;
			}
		case 'D':
			{
				sd->sysdaemon = SYSD_ENABLE;
				/* Daemonize implies silent mode
				 * Users can still dump pcaps */
				print_packet_buffer = NULL;
				break;
			}
		case 'P':
			{
				sd->pidfile = optarg;
				break;
			}
		case 'b':
			{
				set_cpu_affinity(optarg);
				break;
			}
		case 'B':
			{
				set_cpu_affinity_inv(optarg);
				break;
			}
		case 'p':
			{
				if ((dump_pcap = fopen(optarg, "w+")) == NULL) {
					perr("Can't open file: ");
					exit(EXIT_FAILURE);
				}

				sf_write_header(dump_pcap, LINKTYPE_EN10MB, 0, PCAP_DEFAULT_SNAPSHOT_LEN);
				break;
			}
		case '?':
			{
				switch (optopt) {
				case 'd':
				case 'f':
				case 'p':
				case 'P':
				case 'L':
				case 'b':
				case 'B':
					{
						fprintf(stderr, "Option -%c requires an argument!\n", optopt);
						break;
					}
				default:
					{
						if (isprint(optopt)) {
							fprintf(stderr, "Unknown option character `0x%X\'!\n", optopt);
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

	if (sd->sysdaemon && (!sd->pidfile || !dump_pcap)) {
		help();
		exit(EXIT_FAILURE);
	}

	for (i = optind; i < argc; ++i) {
		err("Non-option argument %s!\n", argv[i]);
	}

	if (optind < argc) {
		exit(EXIT_FAILURE);
	}

	/*
	 * Main stuff
	 */

	init_system(sd, &sock, &rb, &pfd);
	fetch_packets(rb, &pfd, sd->blocking_mode, dump_pcap, sd->packet_type, sock);
	cleanup_system(sd, &sock, &rb);

	if (dump_pcap != NULL) {
		fclose(dump_pcap);
	}

	free(sd);
	return 0;
}

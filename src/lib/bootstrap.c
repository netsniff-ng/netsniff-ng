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

/*
 * Contains: 
 *    Routines for starting / stopping the beast ;)
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

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/un.h>
#include <sys/types.h>

#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netsniff-ng/misc.h>
#include <netsniff-ng/dump.h>
#include <netsniff-ng/macros.h>
#include <netsniff-ng/system.h>
#include <netsniff-ng/types.h>
#include <netsniff-ng/rx_ring.h>
#include <netsniff-ng/netdev.h>
#include <netsniff-ng/config.h>
#include <netsniff-ng/signal.h>
#include <netsniff-ng/bpf.h>
#include <netsniff-ng/bootstrap.h>

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
 * init_system - Initializes netsniff-ng main
 * @sd:         system configuration data
 * @sock:       socket
 * @rb:         ring buffer
 * @pfd:        file descriptor for polling
 */
int init_system(system_data_t * sd, int *sock, ring_buff_t ** rb, struct pollfd *pfd)
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
			warn("Daemonize failed!\n");
			exit(EXIT_FAILURE);
		}
	}

	/* Print program header */
	header();

	(*rb) = (ring_buff_t *) malloc(sizeof(**rb));
	if ((*rb) == NULL) {
		err("Cannot allocate ring buffer");
		exit(EXIT_FAILURE);
	}

	memset((*rb), 0, sizeof(**rb));

	/* User didn't specify a device, so we switch to the default running 
	   dev. This is the first running dev found (except lo). If we find 
	   nothing, we switch to lo. */
	if (!sd->dev) {
		sd->dev = strdup("lo");
		if (!sd->dev) {
			err("Cannot allocate mem");
			exit(EXIT_FAILURE);
		}

		stmp = socket(AF_INET, SOCK_DGRAM, 0);
		if (stmp < 0) {
			err("Fetching socket");
			exit(EXIT_FAILURE);
		}

		ifc.ifc_len = sizeof(dev_buff);
		ifc.ifc_buf = dev_buff;

		if (ioctl(stmp, SIOCGIFCONF, &ifc) < 0) {
			err("Doing ioctl(SIOCGIFCONF)");
			exit(EXIT_FAILURE);
		}

		ifr = ifc.ifc_req;

		for (i = 0; i < ifc.ifc_len / sizeof(struct ifreq); ++i) {
			ifr_elem = &ifr[i];

			if (ioctl(stmp, SIOCGIFFLAGS, ifr_elem) < 0) {
				err("Doing ioctl(SIOCGIFFLAGS)");
				exit(EXIT_FAILURE);
			}

			if ((ifr_elem->ifr_flags & IFF_UP) &&
			    (ifr_elem->ifr_flags & IFF_RUNNING) && strncmp(ifr_elem->ifr_name, "lo", IFNAMSIZ)) {
				sd->dev = strdup(ifr_elem->ifr_name);
				if (!sd->dev) {
					err("Cannot allocate mem");
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
		err("Cannot set itimer");
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
void cleanup_system(system_data_t * sd, int *sock, ring_buff_t ** rb)
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

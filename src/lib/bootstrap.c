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

#include <sys/ioctl.h>
#include <net/if.h>

#include <netsniff-ng/hash.h>
#include <netsniff-ng/dump.h>
#include <netsniff-ng/system.h>
#include <netsniff-ng/types.h>
#include <netsniff-ng/rx_ring.h>
#include <netsniff-ng/tx_ring.h>
#include <netsniff-ng/netdev.h>
#include <netsniff-ng/config.h>
#include <netsniff-ng/signal.h>
#include <netsniff-ng/bpf.h>
#include <netsniff-ng/bootstrap.h>

volatile sig_atomic_t sigint = 0;

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

static void __init_phase_common(system_data_t * sd, int *sock, ring_buff_t ** rb, struct pollfd *pfd)
{
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

	memset(&netstat, 0, sizeof(netstat));
}

static void __init_phase_daemon(system_data_t * sd, int *sock, ring_buff_t ** rb, struct pollfd *pfd)
{
	int ret;

	assert(sd);
	assert(sock);
	assert(rb);
	assert(pfd);

	if (sd->sysdaemon == 0)
		return;

	ret = daemonize(sd->pidfile);
	if (ret != 0) {
		warn("Daemonize failed!\n");
		exit(EXIT_FAILURE);
	}
}

static void __init_phase_fallback_dev(system_data_t * sd, int *sock, ring_buff_t ** rb, struct pollfd *pfd)
{
	int i, stmp;
	char dev_buff[1024];

	struct ifconf ifc;
	struct ifreq *ifr = NULL;
	struct ifreq *ifr_elem = NULL;

	assert(sd);
	assert(sock);
	assert(rb);
	assert(pfd);

	/* User specified device, so no work here ... */
	if (sd->dev)
		return;

	/* User didn't specify a device, so we switch to the default running 
	   dev. This is the first running dev found (except lo). If we find 
	   nothing, we switch to lo. */
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

static void __init_phase_mode_common(system_data_t * sd, int *sock, ring_buff_t ** rb, struct pollfd *pfd)
{
	assert(sd);
	assert(sock);
	assert(rb);
	assert(pfd);

	(*rb) = (ring_buff_t *) malloc(sizeof(**rb));
	if ((*rb) == NULL) {
		err("Cannot allocate ring buffer");
		exit(EXIT_FAILURE);
	}

	memset((*rb), 0, sizeof(**rb));

	/* 
	 * Some further common init stuff
	 */

	put_dev_into_promisc_mode(sd->dev);

	(*sock) = get_pf_socket();
}

static void __init_phase_bpf(system_data_t * sd, int *sock, ring_buff_t ** rb, struct pollfd *pfd)
{
	int bpf_len = 0;
	struct sock_filter *bpf = NULL;

	assert(sd);
	assert(sock);
	assert(rb);
	assert(pfd);

	if (sd->mode == MODE_REPLAY)
		return;

	if (sd->bypass_bpf == BPF_BYPASS) {
		info("No filter applied. Sniffing all traffic.\n\n");
		return;
	}

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

	free(bpf);
}

static void __init_phase_rx_ring(system_data_t * sd, int *sock, ring_buff_t ** rb, struct pollfd *pfd)
{
	assert(sd);
	assert(sock);
	assert(rb);
	assert(pfd);

	if (sd->mode == MODE_REPLAY)
		return;

	create_virt_rx_ring((*sock), (*rb), sd->dev);
	bind_dev_to_rx_ring((*sock), ethdev_to_ifindex(sd->dev), (*rb));
	mmap_virt_rx_ring((*sock), (*rb));
	alloc_frame_buffer((*rb));
	prepare_polling((*sock), pfd);
}

static void __init_phase_tx_ring(system_data_t * sd, int *sock, ring_buff_t ** rb, struct pollfd *pfd)
{
	assert(sd);
	assert(sock);
	assert(rb);
	assert(pfd);

	if (sd->mode == MODE_CAPTURE)
		return;

	create_virt_tx_ring((*sock), (*rb), sd->dev);
	bind_dev_to_tx_ring((*sock), ethdev_to_ifindex(sd->dev), (*rb));
	mmap_virt_tx_ring((*sock), (*rb));
	alloc_frame_buffer((*rb));
	prepare_polling((*sock), pfd);
}

static void __init_phase_hashtables(system_data_t * sd, int *sock, ring_buff_t ** rb, struct pollfd *pfd)
{
	assert(sd);
	assert(sock);
	assert(rb);
	assert(pfd);

	ieee_vendors_init();
}

static void __init_phase_timer(system_data_t * sd, int *sock, ring_buff_t ** rb, struct pollfd *pfd)
{
	int ret;
	struct itimerval val_r;

	assert(sd);
	assert(sock);
	assert(rb);
	assert(pfd);

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
}

static void header(void)
{
	int ret;
	size_t len;
	char *cpu_string;

	struct sched_param sp;

	len = sysconf(_SC_NPROCESSORS_CONF) + 1;

	cpu_string = malloc(len);
	if (!cpu_string) {
		err("No mem left");
		exit(EXIT_FAILURE);
	}

	ret = sched_getparam(getpid(), &sp);
	if (ret) {
		err("Cannot determine sched prio");
		exit(EXIT_FAILURE);
	}

	info("%s -- pid (%d)\n\n", colorize_full_str(red, white, PROGNAME_STRING " " VERSION_STRING), (int)getpid());

	info("nice (%d), scheduler (%d prio %d)\n",
	     getpriority(PRIO_PROCESS, getpid()), sched_getscheduler(getpid()), sp.sched_priority);

	info("%ld of %ld CPUs online, affinity bitstring (%s)\n\n",
	     sysconf(_SC_NPROCESSORS_ONLN), sysconf(_SC_NPROCESSORS_CONF), get_cpu_affinity(cpu_string, len));

	free(cpu_string);

	print_device_info();

	info("\n");
}

/**
 * init_system - Initializes netsniff-ng`s main
 * @sd:         system configuration data
 * @sock:       socket
 * @rb:         ring buffer
 * @pfd:        file descriptor for polling
 */
int init_system(system_data_t * sd, int *sock, ring_buff_t ** rb, struct pollfd *pfd)
{
	assert(sd);
	assert(sock);
	assert(rb);
	assert(pfd);

	/* Print program header */
	header();

	__init_phase_common(sd, sock, rb, pfd);
	__init_phase_daemon(sd, sock, rb, pfd);
	__init_phase_fallback_dev(sd, sock, rb, pfd);
	__init_phase_mode_common(sd, sock, rb, pfd);
	__init_phase_bpf(sd, sock, rb, pfd);
	__init_phase_rx_ring(sd, sock, rb, pfd);
	__init_phase_tx_ring(sd, sock, rb, pfd);
	__init_phase_hashtables(sd, sock, rb, pfd);
	__init_phase_timer(sd, sock, rb, pfd);

	return 0;
}

static void __exit_phase_common(system_data_t * sd, int *sock, ring_buff_t ** rb)
{
	assert(sd);
	assert(sock);
	assert(rb);
	/* NOP */
}

static void __exit_phase_daemon(system_data_t * sd, int *sock, ring_buff_t ** rb)
{
	assert(sd);
	assert(sock);
	assert(rb);

	if (sd->sysdaemon == 0)
		return;

	undaemonize(sd->pidfile);
}

static void __exit_phase_fallback_dev(system_data_t * sd, int *sock, ring_buff_t ** rb)
{
	assert(sd);
	assert(sock);
	assert(rb);
	/* NOP */
}

static void __exit_phase_mode_common(system_data_t * sd, int *sock, ring_buff_t ** rb)
{
	assert(sd);
	assert(sock);
	assert(rb);
	/* NOP */
}

static void __exit_phase_bpf(system_data_t * sd, int *sock, ring_buff_t ** rb)
{
	assert(sd);
	assert(sock);
	assert(rb);

	if (sd->mode == MODE_REPLAY)
		return;
	if (sd->bypass_bpf == BPF_BYPASS)
		return;

	reset_kernel_bpf((*sock));
}

static void __exit_phase_rx_ring(system_data_t * sd, int *sock, ring_buff_t ** rb)
{
	assert(sd);
	assert(sock);
	assert(rb);
	assert(*rb);

	if (sd->mode == MODE_REPLAY)
		return;

	destroy_virt_rx_ring((*sock), (*rb));
}

static void __exit_phase_tx_ring(system_data_t * sd, int *sock, ring_buff_t ** rb)
{
	assert(sd);
	assert(sock);
	assert(rb);
	assert(*rb);

	if (sd->mode == MODE_CAPTURE)
		return;

	destroy_virt_tx_ring((*sock), (*rb));
}

static void __exit_phase_hashtables(system_data_t * sd, int *sock, ring_buff_t ** rb)
{
	assert(sd);
	assert(sock);
	assert(rb);

	ieee_vendors_destroy();
}

static void __exit_phase_timer(system_data_t * sd, int *sock, ring_buff_t ** rb)
{
	assert(sd);
	assert(sock);
	assert(rb);

	net_stat((*sock));
}

static void __exit_phase_last(system_data_t * sd, int *sock, ring_buff_t ** rb)
{
	assert(sd);
	assert(sock);
	assert(rb);

	close((*sock));

	free((*rb));
	free(sd->dev);
}

static void footer(void)
{
	/*
	 * FIXME Find a way to print a uint64_t
	 * on 32 and 64 bit arch w/o gcc warnings
	 */

	info("captured frames: %llu, "
	     "captured bytes: %llu [%llu KiB, %llu MiB, %llu GiB]\n",
	     netstat.total.frames, netstat.total.bytes,
	     netstat.total.bytes / 1024,
	     netstat.total.bytes / (1024 * 1024), netstat.total.bytes / (1024 * 1024 * 1024));
}

/**
 * cleanup_system - Cleans up netsniff-ng`s main
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

	__exit_phase_common(sd, sock, rb);
	__exit_phase_daemon(sd, sock, rb);
	__exit_phase_fallback_dev(sd, sock, rb);
	__exit_phase_mode_common(sd, sock, rb);
	__exit_phase_bpf(sd, sock, rb);
	__exit_phase_rx_ring(sd, sock, rb);
	__exit_phase_tx_ring(sd, sock, rb);
	__exit_phase_hashtables(sd, sock, rb);
	__exit_phase_timer(sd, sock, rb);
	__exit_phase_last(sd, sock, rb);

	/* Print program footer */
	footer();

	return;
}

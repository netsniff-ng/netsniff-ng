/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL, version 2.
 *
 * A high-performance network traffic generator that uses the zero-copy
 * kernelspace TX_RING for network I/O. On comodity Gigabit hardware up
 * to 1,488,095 pps 64 Byte pps have been achieved with 2 trafgen instances
 * bound to different CPUs from the userspace and turned off pause frames,
 * ask Ronald from NST (Network Security Toolkit) for more details. ;-)
 * So, this line-rate result is the very same as pktgen from kernelspace!
 *
 *   Who can now hold the fords when the King of the Nine Riders comes? And
 *   other armies will come. I am too late. All is lost. I tarried on the
 *   way. All is lost. Even if my errand is performed, no one will ever
 *   know. There will be no one I can tell. It will be in vain.
 *
 *     -- The Lord of the Rings, Frodo thinking,
 *        Chapter 'The Stairs of Cirith Ungol'.
 */

/*

=head1 NAME

trafgen - a high-performance zero-copy network packet generator

=head1 SYNOPSIS

trafgen	[-d|--dev <netdev>][-c|--conf <file>][-J|--jumbo-support]
	[-x|--interactive][-n|--num <uint>][-r|--rand][-t|--gap <usec>]
	[-S|--ring-size <size>][-k|--kernel-pull <usec>][-b|--bind-cpu <cpu>]
	[-B|--unbind-cpu <cpu>][-H|--prio-high][-Q|--notouch-irq][-v|--version]
	[-h|--help]

=head1 DESCRIPTION

A high-performance network traffic generator that uses the zero-copy TX_RING
for network I/O. For instance, on comodity Gigabit hardware up to 1,488,095 pps
64 Byte pps have been achieved with trafgen.

=head1 OPTIONS

=over

=item trafgen --dev eth0 --conf trafgen.txf --bind-cpu 0

Use packet configuration trafgen.txf, eth0 as transmission device and CPU0
for binding the process.

=back

=head1 OPTIONS

=over

=item -h|--help

Print help text and lists all options.

=item -v|--version

Print version.

=item -d|--dev <netdev>

Device for transmission i.e., eth0.

=item -c|--conf <conf>

Path to packet configuration file.

=item -x|--interactive

Start trafgen in interactive mode.

=item -J|--jumbo-support

Support for 64KB Super Jumbo Frames

=item -n|--num <uint>

Number of packets to generate before exiting.
0 means forever until SIGINT.

=item -r|--rand

Randomize packet selection process instead of round-robin.

=item -t|--gap <uint>

Interpacket gap in microseconds.

=item -S|--ring-size <size>

Manually set ring size to <size>: mmap space in KB/MB/GB.

=item -k|--kernel-pull <uint>

Kernel pull from user interval in microseconds.
Default value is 10 microseconds.

=item -b|--bind-cpu <cpu>

Bind to specific CPU (or CPU-range).

=item -B|--unbind-cpu <cpu>

Forbid to use specific CPU (or CPU-range).

=item -H|--prio-high

Make this high priority process.

=item -Q|--notouch-irq

Do not touch IRQ CPU affinity of NIC.

=back

=head1 EXAMPLES

=over

=item Generate traffic defined in trafgen.txf on eth0 using CPU 0

trafgen --dev eth0 --conf trafgen.txf --bind-cpu 0

=item Generate traffic on eth0 using CPU 0, wait 100 us between packets

trafgen --dev eth0 --conf trafgen.txf --bind-cpu 0 --gap 100

=item Generate 100,000 packet on eth0 using CPU 0

trafgen --dev eth0 --conf trafgen.txf --bind-cpu 0 --num 100000

=back

=head1 AUTHOR

Written by Daniel Borkmann <daniel@netsniff-ng.org>

=head1 DOCUMENTATION

Documentation by Emmanuel Roullit <emmanuel@netsniff-ng.org>

=head1 BUGS

Please report bugs to <bugs@netsniff-ng.org>

=cut

*/

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <net/ethernet.h>

#include "xmalloc.h"
#include "die.h"
#include "mac80211.h"
#include "xutils.h"
#include "xio.h"
#include "trafgen_conf.h"
#include "tprintf.h"
#include "mtrand.h"
#include "ring_tx.h"

struct stats {
	unsigned long tx_bytes;
	unsigned long tx_packets;
};

struct mode {
#define CPU_UNKNOWN  -1
#define CPU_NOTOUCH  -2
	struct stats stats;
	char *device;
	char *device_trans;
	int cpu;
	int rand;
	int rfraw;
	unsigned long kpull;
	/* 0 for automatic, > 0 for manual */
	unsigned int reserve_size;
	int jumbo_support;
	int verbose;
	unsigned long num; 
	unsigned long gap;
};

static int sock;
static struct itimerval itimer;
static unsigned long interval = TX_KERNEL_PULL_INT;

sig_atomic_t sigint = 0;

struct packet *packets = NULL;
unsigned int packets_len = 0;

struct packet_dynamics *packet_dyns = NULL;
unsigned int packet_dyn_len = 0;

static const char *short_options = "d:c:n:t:vJhS:HQb:B:rk:xi:o:VR";

static struct option long_options[] = {
	{"dev", required_argument, 0, 'd'},
	{"out", required_argument, 0, 'o'},
	{"in", required_argument, 0, 'i'},
	{"conf", required_argument, 0, 'c'},
	{"num", required_argument, 0, 'n'},
	{"gap", required_argument, 0, 't'},
	{"ring-size", required_argument, 0, 'S'},
	{"bind-cpu", required_argument, 0, 'b'},
	{"unbind-cpu", required_argument, 0, 'B'},
	{"kernel-pull", required_argument, 0, 'k'},
	{"jumbo-support", no_argument, 0, 'J'},
	{"rfraw", no_argument, 0, 'R'},
	{"interactive", no_argument, 0, 'x'},
	{"rand", no_argument, 0, 'r'},
	{"prio-high", no_argument, 0, 'H'},
	{"notouch-irq", no_argument, 0, 'Q'},
	{"verbose", no_argument, 0, 'V'},
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};

static void signal_handler(int number)
{
	switch (number) {
	case SIGINT:
		sigint = 1;
		break;
	case SIGHUP:
	default:
		break;
	}
}

static void timer_elapsed(int number)
{
	itimer.it_interval.tv_sec = 0;
	itimer.it_interval.tv_usec = interval;
	itimer.it_value.tv_sec = 0;
	itimer.it_value.tv_usec = interval;

	pull_and_flush_tx_ring(sock);
	setitimer(ITIMER_REAL, &itimer, NULL); 
}

static void header(void)
{
	printf("%s%s%s\n", colorize_start(bold), "trafgen "
	       VERSION_STRING, colorize_end());
}

static void help(void)
{
	printf("\ntrafgen %s, high-perf zero-copy network packet generator\n",
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Usage: trafgen [options]\n");
	printf("Options:\n");
/*	printf("  -o|-d|--out|--dev <netdev|pcap>   Networking Device i.e., eth0 or pcap\n"); */
	printf("  -o|-d|--out|--dev <netdev>        Networking Device i.e., eth0\n");
	printf("  -i|-c|--in|--conf <cfg-file>      Packet configuration file\n");
/*	printf("  -x|--interactive                  Start trafgen in interactive server mode\n"); */
	printf("  -J|--jumbo-support                Support for 64KB Super Jumbo Frames\n");
	printf("                                    Default TX slot: 2048Byte\n");
	printf("  -R|--rfraw                        Inject raw 802.11 frames\n");
	printf("  -n|--num <uint>                   Number of packets until exit\n");
	printf("  `--     0                         Loop until interrupt (default)\n");
	printf("   `-     n                         Send n packets and done\n");
	printf("  -r|--rand                         Randomize packet selection process\n");
	printf("                                    Instead of a round robin selection\n");
	printf("  -t|--gap <uint>                   Interpacket gap in us (approx)\n");
	printf("  -S|--ring-size <size>             Manually set ring size to <size>:\n");
	printf("                                    mmap space in KB/MB/GB, e.g. \'10MB\'\n");
	printf("  -k|--kernel-pull <uint>           Kernel pull from user interval in us\n");
	printf("                                    Default is 10us where the TX_RING\n");
	printf("                                    is populated with payload from uspace\n");
	printf("  -b|--bind-cpu <cpu>               Bind to specific CPU (or CPU-range)\n");
	printf("  -B|--unbind-cpu <cpu>             Forbid to use specific CPU (or CPU-range)\n");
	printf("  -H|--prio-high                    Make this high priority process\n");
	printf("  -Q|--notouch-irq                  Do not touch IRQ CPU affinity of NIC\n");
	printf("  -v|--version                      Show version\n");
	printf("  -h|--help                         Guess what?!\n");
	printf("\n");
	printf("Examples:\n");
	printf("  See trafgen.txf for configuration file examples.\n");
	printf("  trafgen --dev eth0 --conf trafgen.txf --bind-cpu 0\n");
	printf("  trafgen --dev wlan0 --rfraw --conf beacon-test.txf --bind-cpu 0\n");
	printf("  trafgen --out eth0 --in trafgen.txf --bind-cpu 0\n");
/*	printf("  trafgen --out test.pcap --in trafgen.txf --bind-cpu 0\n"); */
	printf("  trafgen --dev eth0 --conf trafgen.txf --rand --gap 1000\n");
	printf("  trafgen --dev eth0 --conf trafgen.txf --bind-cpu 0 --num 10 --rand\n");
/*	printf("  trafgen --interactive\n");
	printf("  trafgen --interactive --dev mgmt0    (only start server on mgmt0)\n");
	printf("  trafgen --interactive --conf trafgen-cli.batch\n");*/
	printf("\n");
	printf("Note:\n");
	printf("  This tool is targeted for network developers! You should\n");
	printf("  be aware of what you are doing and what these options above\n");
	printf("  mean! Only use this tool in an isolated LAN that you own!\n");
	printf("\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2011-2012 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,\n");
	printf("Swiss federal institute of technology (ETH Zurich)\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");
	die();
}

static void version(void)
{
	printf("\ntrafgen %s, high-perf zero-copy network packet generator\n",
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2011-2012 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,\n");
	printf("Swiss federal institute of technology (ETH Zurich)\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");
	die();
}

static inline void apply_counter(int i)
{
	int j;

	for (j = 0; j < packet_dyns[i].counter_len; ++j) {
		uint8_t val;
		struct counter *counter = &packet_dyns[i].counter[j];

		val = counter->val;
		val -= counter->min;

		if (counter->type == TYPE_INC)
			val = (val + counter->inc) %
			      (counter->max - counter->min + 1);
		else
			val = (val - counter->inc) %
			      (counter->min - counter->max + 1);

		val += counter->min;
		counter->val = val;

		packets[i].payload[counter->off] = val;
	}
}

static inline void apply_randomizer(int i)
{
	int j;

	for (j = 0; j < packet_dyns[i].randomizer_len; ++j) {
		uint8_t val = (uint8_t) mt_rand_int32();
		struct randomizer *randomizer = &packet_dyns[i].randomizer[j];

		randomizer->val = val;
		packets[i].payload[randomizer->off] = val;
	}
}

static void tx_precheck(struct mode *mode)
{
	int i, mtu;

	if (!mode)
		panic("Panic over invalid args for TX trigger!\n");
	if (packets_len == 0 || packets_len != packet_dyn_len)
		panic("Panic over invalid args for TX trigger!\n");
	if (!mode->rfraw && !device_up_and_running(mode->device))
		panic("Device not up and running!\n");

	mtu = device_mtu(mode->device);

	for (i = 0; i < packets_len; ++i) {
		if (packets[i].len > mtu + 14)
			panic("Device MTU < than your packet size!\n");
		if (packets[i].len <= 14)
			panic("Device packet size too short!\n");
	}
}

static void tx_slowpath_or_die(struct mode *mode)
{
	int ifindex, ret;
	unsigned int i;
	struct sockaddr_ll s_addr;
	unsigned long num = 1;
	struct timeval start, end, diff;

	tx_precheck(mode);

	sock = pf_socket();

	if (mode->rfraw) {
		mode->device_trans = xstrdup(mode->device);
		xfree(mode->device);

		enter_rfmon_mac80211(mode->device_trans, &mode->device);
	}

	ifindex = device_ifindex(mode->device);

	if (mode->num > 0)
		num = mode->num;
	if (mode->rand)
		printf("Note: randomizes output makes trafgen slower!\n");

	printf("MD: TX slowpath %s %luus", mode->rand ? "RND" : "RR", mode->gap);
	if (mode->rfraw)
		printf(" 802.11 raw via %s", mode->device);
	printf("\n\n");
	printf("Running! Hang up with ^C!\n\n");

	fmemset(&s_addr, 0, sizeof(s_addr));
	s_addr.sll_family = PF_PACKET;
	s_addr.sll_halen = ETH_ALEN;
	s_addr.sll_ifindex = ifindex;

	i = 0;

	gettimeofday(&start, NULL);

	while (likely(sigint == 0) && likely(num > 0)) {
		apply_counter(i);
		apply_randomizer(i);

		ret = sendto(sock, packets[i].payload, packets[i].len, 0,
			     (struct sockaddr *) &s_addr, sizeof(s_addr));
		if (ret < 0)
			whine("sendto error!\n");

		mode->stats.tx_bytes += packets[i].len;
		mode->stats.tx_packets++;

		if (mode->rand) {
			i = mt_rand_int32() % packets_len;
		} else {
			i++;
			atomic_cmp_swp(&i, packets_len, 0);
		}

		if (mode->num > 0)
			num--;

		usleep(mode->gap);
	}

	gettimeofday(&end, NULL);
	diff = tv_subtract(end, start);

	if (mode->rfraw)
		leave_rfmon_mac80211(mode->device_trans, mode->device);

	close(sock);

	fflush(stdout);
	printf("\n");
	printf("\r%12lu frames outgoing\n", mode->stats.tx_packets);
	printf("\r%12lu bytes outgoing\n", mode->stats.tx_bytes);
	printf("\r%12lu sec, %lu usec in total\n", diff.tv_sec, diff.tv_usec);
}

static void tx_fastpath_or_die(struct mode *mode)
{
	int irq, ifindex;
	unsigned int i, size, it = 0;
	unsigned long num = 1;
	uint8_t *out = NULL;
	struct ring tx_ring;
	struct frame_map *hdr;
	struct timeval start, end, diff;

	tx_precheck(mode);

	sock = pf_socket();

	fmemset(&tx_ring, 0, sizeof(tx_ring));

	if (mode->rfraw) {
		mode->device_trans = xstrdup(mode->device);
		xfree(mode->device);

		enter_rfmon_mac80211(mode->device_trans, &mode->device);
	}

	ifindex = device_ifindex(mode->device);
	size = ring_size(mode->device, mode->reserve_size);

	set_packet_loss_discard(sock);
	setup_tx_ring_layout(sock, &tx_ring, size, mode->jumbo_support);
	create_tx_ring(sock, &tx_ring);
	mmap_tx_ring(sock, &tx_ring);
	alloc_tx_ring_frames(&tx_ring);
	bind_tx_ring(sock, &tx_ring, ifindex);

	if (mode->cpu >= 0 && ifindex > 0) {
		irq = device_irq_number(mode->device);
		device_bind_irq_to_cpu(mode->cpu, irq);
		printf("IRQ: %s:%d > CPU%d\n", mode->device, irq, 
		       mode->cpu);
	}

	if (mode->kpull)
		interval = mode->kpull;
	if (mode->num > 0)
		num = mode->num;
	if (mode->rand)
		printf("Note: randomizes output makes trafgen slower!\n");

	printf("MD: TX fastpath %s %luus", mode->rand ? "RND" : "RR", interval);
	if (mode->rfraw)
		printf(" 802.11 raw via %s", mode->device);
	printf("\n\n");
	printf("Running! Hang up with ^C!\n\n");

	itimer.it_interval.tv_sec = 0;
	itimer.it_interval.tv_usec = interval;
	itimer.it_value.tv_sec = 0;
	itimer.it_value.tv_usec = interval;
	setitimer(ITIMER_REAL, &itimer, NULL); 

	i = 0;

	gettimeofday(&start, NULL);

	while (likely(sigint == 0) && likely(num > 0)) {
		while (user_may_pull_from_tx(tx_ring.frames[it].iov_base) &&
		       likely(num > 0)) {
			hdr = tx_ring.frames[it].iov_base;

			/* Kernel assumes: data = ph.raw + po->tp_hdrlen -
			 *                        sizeof(struct sockaddr_ll); */
			out = ((uint8_t *) hdr) + TPACKET_HDRLEN -
			      sizeof(struct sockaddr_ll);

			hdr->tp_h.tp_snaplen = packets[i].len;
			hdr->tp_h.tp_len = packets[i].len;

			apply_counter(i);
			apply_randomizer(i);

			fmemcpy(out, packets[i].payload, packets[i].len);

			mode->stats.tx_bytes += packets[i].len;
			mode->stats.tx_packets++;

			if (mode->rand) {
				i = mt_rand_int32() % packets_len;
			} else {
				i++;
				atomic_cmp_swp(&i, packets_len, 0);
			}

			kernel_may_pull_from_tx(&hdr->tp_h);
			next_slot_prewr(&it, &tx_ring);

			if (mode->num > 0)
				num--;
			if (unlikely(sigint == 1))
				break;
		}
	}

	gettimeofday(&end, NULL);
	diff = tv_subtract(end, start);

	destroy_tx_ring(sock, &tx_ring);

	if (mode->rfraw)
		leave_rfmon_mac80211(mode->device_trans, mode->device);

	close(sock);

	fflush(stdout);
	printf("\n");
	printf("\r%12lu frames outgoing\n", mode->stats.tx_packets);
	printf("\r%12lu bytes outgoing\n", mode->stats.tx_bytes);
	printf("\r%12lu sec, %lu usec in total\n", diff.tv_sec, diff.tv_usec);
}

static void main_loop(struct mode *mode, char *confname)
{
	compile_packets(confname, mode->verbose);

	if (mode->gap > 0)
		tx_slowpath_or_die(mode);
	else
		tx_fastpath_or_die(mode);

	cleanup_packets();
}

int main(int argc, char **argv)
{
	int c, opt_index, i, j, interactive = 0;
	char *confname = NULL, *ptr;
	bool prio_high = false;
	struct mode mode;

	check_for_root_maybe_die();

	fmemset(&mode, 0, sizeof(mode));
	mode.cpu = CPU_UNKNOWN;
	mode.gap = 0;
	mode.num = 0;

	while ((c = getopt_long(argc, argv, short_options, long_options,
	       &opt_index)) != EOF) {
		switch (c) {
		case 'h':
			help();
			break;
		case 'v':
			version();
			break;
		case 'V':
			mode.verbose = 1;
			break;
		case 'd':
		case 'o':
			mode.device = xstrndup(optarg, IFNAMSIZ);
			break;
		case 'x':
			interactive = 1;
			break;
		case 'r':
			mode.rand = 1;
			break;
		case 'R':
			mode.rfraw = 1;
			break;
		case 'J':
			mode.jumbo_support = 1;
			break;
		case 'c':
		case 'i':
			confname = xstrdup(optarg);
			break;
		case 'k':
			mode.kpull = atol(optarg);
			break;
		case 'n':
			mode.num = atol(optarg);
			break;
		case 't':
			mode.gap = atol(optarg);
			break;
		case 'S':
			ptr = optarg;
			mode.reserve_size = 0;

			for (j = i = strlen(optarg); i > 0; --i) {
				if (!isdigit(optarg[j - i]))
					break;
				ptr++;
			}

			if (!strncmp(ptr, "KB", strlen("KB")))
				mode.reserve_size = 1 << 10;
			else if (!strncmp(ptr, "MB", strlen("MB")))
				mode.reserve_size = 1 << 20;
			else if (!strncmp(ptr, "GB", strlen("GB")))
				mode.reserve_size = 1 << 30;
			else
				panic("Syntax error in ring size param!\n");
			*ptr = 0;

			mode.reserve_size *= atoi(optarg);
			break;
		case 'b':
			set_cpu_affinity(optarg, 0);
			/* Take the first CPU for rebinding the IRQ */
			if (mode.cpu != CPU_NOTOUCH)
				mode.cpu = atoi(optarg);
			break;
		case 'B':
			set_cpu_affinity(optarg, 1);
			break;
		case 'H':
			prio_high = true;
			break;
		case 'Q':
			mode.cpu = CPU_NOTOUCH;
			break;
		case '?':
			switch (optopt) {
			case 'd':
			case 'c':
			case 'n':
			case 'S':
			case 'b':
			case 'o':
			case 'i':
			case 'k':
			case 'B':
			case 't':
				panic("Option -%c requires an argument!\n",
				      optopt);
			default:
				if (isprint(optopt))
					whine("Unknown option character "
					      "`0x%X\'!\n", optopt);
				die();
			}
		default:
			break;
		}
	}

	if (!interactive && argc < 5)
		help();
	if (interactive && argc < 2)
		help();
	if (!interactive && mode.device == NULL)
		panic("No networking device given!\n");
	if (!interactive && confname == NULL)
		panic("No configuration file given!\n");
	if (!interactive && device_mtu(mode.device) == 0)
		panic("This is no networking device!\n");
	if (!interactive && !mode.rfraw &&
	    device_up_and_running(mode.device) == 0)
		panic("Networking device not running!\n");

	register_signal(SIGINT, signal_handler);
	register_signal(SIGHUP, signal_handler);
	register_signal_f(SIGALRM, timer_elapsed, SA_SIGINFO);

	header();

	if (prio_high == true) {
		set_proc_prio(get_default_proc_prio());
		set_sched_status(get_default_sched_policy(),
				 get_default_sched_prio());
	}

	if (interactive)
		main_loop_interactive(&mode, confname);
	else
		main_loop(&mode, confname);

	if (mode.device)
		xfree(mode.device);
	if (mode.device_trans)
		xfree(mode.device_trans);
	if (confname)
		xfree(confname);

	return 0;
}

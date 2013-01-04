/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 - 2013 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
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
#include "built_in.h"
#include "trafgen_conf.h"
#include "tprintf.h"
#include "ring_tx.h"

struct ctx {
	char *device, *device_trans;
	int cpu, rand, rfraw, jumbo_support, verbose;
	unsigned long kpull, num, gap, reserve_size;
	unsigned long tx_bytes, tx_packets;
};

sig_atomic_t sigint = 0;

struct packet *packets = NULL;
size_t plen = 0;

struct packet_dyn *packet_dyn = NULL;
size_t dlen = 0;

static const char *short_options = "d:c:n:t:vJhS:HQb:B:rk:i:o:VRA";
static const struct option long_options[] = {
	{"dev",			required_argument,	NULL, 'd'},
	{"out",			required_argument,	NULL, 'o'},
	{"in",			required_argument,	NULL, 'i'},
	{"conf",		required_argument,	NULL, 'c'},
	{"num",			required_argument,	NULL, 'n'},
	{"gap",			required_argument,	NULL, 't'},
	{"ring-size",		required_argument,	NULL, 'S'},
	{"bind-cpu",		required_argument,	NULL, 'b'},
	{"unbind-cpu",		required_argument,	NULL, 'B'},
	{"kernel-pull",		required_argument,	NULL, 'k'},
	{"jumbo-support",	no_argument,		NULL, 'J'},
	{"rfraw",		no_argument,		NULL, 'R'},
	{"rand",		no_argument,		NULL, 'r'},
	{"prio-high",		no_argument,		NULL, 'H'},
	{"notouch-irq",		no_argument,		NULL, 'Q'},
	{"verbose",		no_argument,		NULL, 'V'},
	{"no-sock-mem",		no_argument,		NULL, 'A'},
	{"version",		no_argument,		NULL, 'v'},
	{"help",		no_argument,		NULL, 'h'},
	{NULL, 0, NULL, 0}
};

static int sock;

static struct itimerval itimer;

static unsigned long interval = TX_KERNEL_PULL_INT;

#define set_system_socket_memory(vals) \
	do { \
		if ((vals[0] = get_system_socket_mem(sock_rmem_max)) < SMEM_SUG_MAX) \
			set_system_socket_mem(sock_rmem_max, SMEM_SUG_MAX); \
		if ((vals[1] = get_system_socket_mem(sock_rmem_def)) < SMEM_SUG_DEF) \
			set_system_socket_mem(sock_rmem_def, SMEM_SUG_DEF); \
		if ((vals[2] = get_system_socket_mem(sock_wmem_max)) < SMEM_SUG_MAX) \
			set_system_socket_mem(sock_wmem_max, SMEM_SUG_MAX); \
		if ((vals[3] = get_system_socket_mem(sock_wmem_def)) < SMEM_SUG_DEF) \
			set_system_socket_mem(sock_wmem_def, SMEM_SUG_DEF); \
	} while (0)

#define reset_system_socket_memory(vals) \
	do { \
		set_system_socket_mem(sock_rmem_max, vals[0]); \
		set_system_socket_mem(sock_rmem_def, vals[1]); \
		set_system_socket_mem(sock_wmem_max, vals[2]); \
		set_system_socket_mem(sock_wmem_def, vals[3]); \
	} while (0)

static void signal_handler(int number)
{
	switch (number) {
	case SIGINT:
		sigint = 1;
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
	printf("%s%s%s\n", colorize_start(bold), "trafgen " VERSION_STRING, colorize_end());
}

static void help(void)
{
	printf("\ntrafgen %s, zero-copy network packet generator\n", VERSION_STRING);
	puts("http://www.netsniff-ng.org\n\n"
	     "Usage: trafgen [options]\n"
	     "Options:\n"
/*	     "  -o|-d|--out|--dev <netdev|pcap>   Networking Device i.e., eth0 or pcap\n" */
	     "  -o|-d|--out|--dev <netdev>        Networking Device i.e., eth0\n"
	     "  -i|-c|--in|--conf <cfg-file>      Packet configuration file\n"
	     "  -J|--jumbo-support                Support for 64KB Super Jumbo Frames\n"
	     "                                    Default TX slot: 2048Byte\n"
	     "  -R|--rfraw                        Inject raw 802.11 frames\n"
	     "  -n|--num <uint>                   Number of packets until exit\n"
	     "  `--     0                         Loop until interrupt (default)\n"
	     "   `-     n                         Send n packets and done\n"
	     "  -r|--rand                         Randomize packet selection process\n"
	     "                                    Instead of a round robin selection\n"
	     "  -t|--gap <uint>                   Interpacket gap in us (approx)\n"
	     "  -A|--no-sock-mem                  Don't tune core socket memory\n"
	     "  -S|--ring-size <size>             Manually set ring size to <size>:\n"
	     "                                    mmap space in KB/MB/GB, e.g. \'10MB\'\n"
	     "  -k|--kernel-pull <uint>           Kernel pull from user interval in us\n"
	     "                                    Default is 10us where the TX_RING\n"
	     "                                    is populated with payload from uspace\n"
	     "  -b|--bind-cpu <cpu>               Bind to specific CPU (or CPU-range)\n"
	     "  -B|--unbind-cpu <cpu>             Forbid to use specific CPU (or CPU-range)\n"
	     "  -H|--prio-high                    Make this high priority process\n"
	     "  -Q|--notouch-irq                  Do not touch IRQ CPU affinity of NIC\n"
	     "  -V|--verbose                      Be more verbose\n"
	     "  -v|--version                      Show version\n"
	     "  -h|--help                         Guess what?!\n\n"
	     "Examples:\n"
	     "  See trafgen.txf for configuration file examples.\n"
	     "  trafgen --dev eth0 --conf trafgen.txf --bind-cpu 0\n"
	     "  trafgen --dev wlan0 --rfraw --conf beacon-test.txf --bind-cpu 0 -A -V\n"
	     "  trafgen --out eth0 --in trafgen.txf --bind-cpu 0\n"
/*	     "  trafgen --out test.pcap --in trafgen.txf --bind-cpu 0\n" */
	     "  trafgen --dev eth0 --conf trafgen.txf --rand --gap 1000\n"
	     "  trafgen --dev eth0 --conf trafgen.txf --rand --num 1400000 -k1000\n"
	     "  trafgen --dev eth0 --conf trafgen.txf --bind-cpu 0 --num 10 --rand\n\n"
	     "Note:\n"
	     "  This tool is targeted for network developers! You should\n"
	     "  be aware of what you are doing and what these options above\n"
	     "  mean! Only use this tool in an isolated LAN that you own!\n\n"
	     "Please report bugs to <bugs@netsniff-ng.org>\n"
	     "Copyright (C) 2011-2013 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,\n"
	     "Swiss federal institute of technology (ETH Zurich)\n"
	     "License: GNU GPL version 2.0\n"
	     "This is free software: you are free to change and redistribute it.\n"
	     "There is NO WARRANTY, to the extent permitted by law.\n");
	die();
}

static void version(void)
{
	printf("\ntrafgen %s, zero-copy network packet generator\n", VERSION_STRING);
	puts("http://www.netsniff-ng.org\n\n"
	     "Please report bugs to <bugs@netsniff-ng.org>\n"
	     "Copyright (C) 2011-2013 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,\n"
	     "Swiss federal institute of technology (ETH Zurich)\n"
	     "License: GNU GPL version 2.0\n"
	     "This is free software: you are free to change and redistribute it.\n"
	     "There is NO WARRANTY, to the extent permitted by law.\n");
	die();
}

static inline void apply_counter(int counter_id)
{
	int j;
	size_t counter_max = packet_dyn[counter_id].clen;

	for (j = 0; j < counter_max; ++j) {
		uint8_t val;
		struct counter *counter;

		counter = &packet_dyn[counter_id].cnt[j];
		val = counter->val - counter->min;

		switch (counter->type) {
		case TYPE_INC:
			val = (val + counter->inc) % (counter->max - counter->min + 1);
			break;
		case TYPE_DEC:
			val = (val - counter->inc) % (counter->min - counter->max + 1);
			break;
		default:
			bug();
		}

		counter->val = val + counter->min;
		packets[counter_id].payload[counter->off] = val;
	}
}

static inline void apply_randomizer(int rand_id)
{
	int j;
	size_t rand_max = packet_dyn[rand_id].rlen;

	for (j = 0; j < rand_max; ++j) {
		uint8_t val;
		struct randomizer *randomizer;

		val = (uint8_t) rand();

		randomizer = &packet_dyn[rand_id].rnd[j];
		randomizer->val = val;

		packets[rand_id].payload[randomizer->off] = val;
	}
}

static void xmit_precheck(const struct ctx *ctx)
{
	int i;
	size_t mtu;

	if (!ctx)
		panic("Panic, invalid args for TX trigger!\n");
	if (plen == 0 || plen != dlen)
		panic("Panic, invalid args for TX trigger!\n");
	if (!ctx->rfraw && !device_up_and_running(ctx->device))
		panic("Device not up and running!\n");
	for (mtu = device_mtu(ctx->device), i = 0; i < plen; ++i) {
		if (packets[i].len > mtu + 14)
			panic("Device MTU < than your packet size!\n");
		if (packets[i].len <= 14)
			panic("Device packet size too short!\n");
	}
}

static void xmit_slowpath_or_die(struct ctx *ctx)
{
	int ret;
	unsigned long num = 1, i = 0;
	struct timeval start, end, diff;
	struct sockaddr_ll saddr = {
		.sll_family = PF_PACKET,
		.sll_halen = ETH_ALEN,
	};

	if (ctx->rfraw) {
		ctx->device_trans = xstrdup(ctx->device);
		xfree(ctx->device);

		enter_rfmon_mac80211(ctx->device_trans, &ctx->device);
	}

	if (ctx->num > 0)
		num = ctx->num;

	if (ctx->verbose) {
		if (ctx->rand)
			printf("Note: randomized output makes trafgen slower!\n");
		printf("MD: TX sendto %s %luus", ctx->rand ? "RND" : "RR", ctx->gap);
		if (ctx->rfraw)
			printf(" 802.11 raw via %s", ctx->device);
		printf("\n\n");
	}
	printf("Running! Hang up with ^C!\n\n");
	fflush(stdout);

	saddr.sll_ifindex = device_ifindex(ctx->device);

	bug_on(gettimeofday(&start, NULL));

	while (likely(sigint == 0) && likely(num > 0)) {
		apply_counter(i);
		apply_randomizer(i);

		ret = sendto(sock, packets[i].payload, packets[i].len, 0,
			     (struct sockaddr *) &saddr, sizeof(saddr));
		if (ret < 0)
			whine("sendto error!\n");

		ctx->tx_bytes += packets[i].len;
		ctx->tx_packets++;

		if (!ctx->rand) {
			i++;
			atomic_cmp_swp(&i, plen, 0);
		} else {
			i = rand() % plen;
		}

		if (ctx->num > 0)
			num--;

		if (ctx->gap > 0)
			usleep(ctx->gap);
	}

	bug_on(gettimeofday(&end, NULL));
	diff = tv_subtract(end, start);

	if (ctx->rfraw)
		leave_rfmon_mac80211(ctx->device_trans, ctx->device);

	fflush(stdout);
	printf("\n");
	printf("\r%12lu frames outgoing\n", ctx->tx_packets);
	printf("\r%12lu bytes outgoing\n", ctx->tx_bytes);
	printf("\r%12lu sec, %lu usec in total\n", diff.tv_sec, diff.tv_usec);

}

static void xmit_fastpath_or_die(struct ctx *ctx)
{
	int irq, ifindex;
	uint8_t *out = NULL;
	unsigned int it = 0;
	unsigned long num = 1, i = 0, size;
	struct ring tx_ring;
	struct frame_map *hdr;
	struct timeval start, end, diff;

	if (ctx->rfraw) {
		ctx->device_trans = xstrdup(ctx->device);
		xfree(ctx->device);

		enter_rfmon_mac80211(ctx->device_trans, &ctx->device);
	}

	fmemset(&tx_ring, 0, sizeof(tx_ring));

	ifindex = device_ifindex(ctx->device);
	size = ring_size(ctx->device, ctx->reserve_size);

	set_sock_prio(sock, 512);
	set_packet_loss_discard(sock);

	setup_tx_ring_layout(sock, &tx_ring, size, ctx->jumbo_support);
	create_tx_ring(sock, &tx_ring, ctx->verbose);
	mmap_tx_ring(sock, &tx_ring);
	alloc_tx_ring_frames(&tx_ring);
	bind_tx_ring(sock, &tx_ring, ifindex);

	if (ctx->cpu >= 0 && ifindex > 0) {
		irq = device_irq_number(ctx->device);
		device_bind_irq_to_cpu(irq, ctx->cpu);

		if (ctx->verbose)
			printf("IRQ: %s:%d > CPU%d\n",
			       ctx->device, irq, ctx->cpu);
	}

	if (ctx->kpull)
		interval = ctx->kpull;
	if (ctx->num > 0)
		num = ctx->num;

	if (ctx->verbose) {
		if (ctx->rand)
			printf("Note: randomized output makes trafgen slower!\n");
		printf("MD: TX fastpath %s %luus", ctx->rand ? "RND" : "RR", interval);
		if (ctx->rfraw)
			printf(" 802.11 raw via %s", ctx->device);
		printf("\n\n");
	}
	printf("Running! Hang up with ^C!\n\n");
	fflush(stdout);

	itimer.it_interval.tv_sec = 0;
	itimer.it_interval.tv_usec = interval;

	itimer.it_value.tv_sec = 0;
	itimer.it_value.tv_usec = interval;

	setitimer(ITIMER_REAL, &itimer, NULL); 

	bug_on(gettimeofday(&start, NULL));

	while (likely(sigint == 0) && likely(num > 0)) {
		while (user_may_pull_from_tx(tx_ring.frames[it].iov_base) &&
		       likely(num > 0)) {
			hdr = tx_ring.frames[it].iov_base;

			/* Kernel assumes: data = ph.raw + po->tp_hdrlen -
			 *                        sizeof(struct sockaddr_ll); */
			out = ((uint8_t *) hdr) + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll);

			hdr->tp_h.tp_snaplen = packets[i].len;
			hdr->tp_h.tp_len = packets[i].len;

			apply_counter(i);
			apply_randomizer(i);

			fmemcpy(out, packets[i].payload, packets[i].len);

			ctx->tx_bytes += packets[i].len;
			ctx->tx_packets++;

			if (!ctx->rand) {
				i++;
				atomic_cmp_swp(&i, plen, 0);
			} else {
				i = rand() % plen;
			}

			kernel_may_pull_from_tx(&hdr->tp_h);
			next_slot(&it, &tx_ring);

			if (ctx->num > 0)
				num--;

			if (unlikely(sigint == 1))
				break;
		}
	}

	bug_on(gettimeofday(&end, NULL));
	diff = tv_subtract(end, start);

	destroy_tx_ring(sock, &tx_ring);

	if (ctx->rfraw)
		leave_rfmon_mac80211(ctx->device_trans, ctx->device);

	fflush(stdout);
	printf("\n");
	printf("\r%12lu frames outgoing\n", ctx->tx_packets);
	printf("\r%12lu bytes outgoing\n", ctx->tx_bytes);
	printf("\r%12lu sec, %lu usec in total\n", diff.tv_sec, diff.tv_usec);
}

static void main_loop(struct ctx *ctx, char *confname, bool slow)
{
	xmit_precheck(ctx);
	compile_packets(confname, ctx->verbose);

	sock = pf_socket();

	if (slow)
		xmit_slowpath_or_die(ctx);
	else
		xmit_fastpath_or_die(ctx);

	close(sock);

	cleanup_packets();
}

int main(int argc, char **argv)
{
	int c, opt_index, i, j, vals[4] = {0};
	char *confname = NULL, *ptr;
	bool prio_high = false, setsockmem = true, slow = false;
	struct ctx ctx;

	srand(time(NULL));

	fmemset(&ctx, 0, sizeof(ctx));
	ctx.cpu = -1;

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
			ctx.verbose = 1;
			break;
		case 'd':
		case 'o':
			ctx.device = xstrndup(optarg, IFNAMSIZ);
			break;
		case 'r':
			ctx.rand = 1;
			break;
		case 'R':
			ctx.rfraw = 1;
			break;
		case 'J':
			ctx.jumbo_support = 1;
			break;
		case 'c':
		case 'i':
			confname = xstrdup(optarg);
			break;
		case 'k':
			ctx.kpull = atol(optarg);
			break;
		case 'n':
			ctx.num = atol(optarg);
			break;
		case 't':
			slow = true;
			ctx.gap = atol(optarg);
			break;
		case 'A':
			setsockmem = false;
			break;
		case 'S':
			ptr = optarg;
			ctx.reserve_size = 0;

			for (j = i = strlen(optarg); i > 0; --i) {
				if (!isdigit(optarg[j - i]))
					break;
				ptr++;
			}

			if (!strncmp(ptr, "KB", strlen("KB")))
				ctx.reserve_size = 1 << 10;
			else if (!strncmp(ptr, "MB", strlen("MB")))
				ctx.reserve_size = 1 << 20;
			else if (!strncmp(ptr, "GB", strlen("GB")))
				ctx.reserve_size = 1 << 30;
			else
				panic("Syntax error in ring size param!\n");
			*ptr = 0;

			ctx.reserve_size *= strtol(optarg, NULL, 0);
			break;
		case 'b':
			set_cpu_affinity(optarg, 0);
			/* Take the first CPU for rebinding the IRQ */
			if (ctx.cpu != -2)
				ctx.cpu = strtol(optarg, NULL, 0);
			break;
		case 'B':
			set_cpu_affinity(optarg, 1);
			break;
		case 'H':
			prio_high = true;
			break;
		case 'Q':
			ctx.cpu = -2;
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

	if (argc < 5)
		help();
	if (ctx.device == NULL)
		panic("No networking device given!\n");
	if (confname == NULL)
		panic("No configuration file given!\n");
	if (device_mtu(ctx.device) == 0)
		panic("This is no networking device!\n");
	if (!ctx.rfraw && device_up_and_running(ctx.device) == 0)
		panic("Networking device not running!\n");

	register_signal(SIGINT, signal_handler);
	register_signal(SIGHUP, signal_handler);
	register_signal_f(SIGALRM, timer_elapsed, SA_SIGINFO);

	header();

	if (prio_high) {
		set_proc_prio(get_default_proc_prio());
		set_sched_status(get_default_sched_policy(), get_default_sched_prio());
	}

	if (setsockmem)
		set_system_socket_memory(vals);

	main_loop(&ctx, confname, slow);

	if (setsockmem)
		reset_system_socket_memory(vals);

	free(ctx.device);
	free(ctx.device_trans);
	free(confname);

	return 0;
}

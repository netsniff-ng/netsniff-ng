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
#include <sys/wait.h>
#include <sys/mman.h>
#include <net/ethernet.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>

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
	bool rand, rfraw, jumbo_support, verbose;
	unsigned long kpull, num, gap, reserve_size;
	char *device, *device_trans;
};

struct cpu_stats {
	unsigned long long tx_packets, tx_bytes;
	unsigned long tv_sec, tv_usec;
};

sig_atomic_t sigint = 0;

struct packet *packets = NULL;
size_t plen = 0;

struct packet_dyn *packet_dyn = NULL;
size_t dlen = 0;

static const char *short_options = "d:c:n:t:vJhS:rk:i:o:VRf";
static const struct option long_options[] = {
	{"dev",			required_argument,	NULL, 'd'},
	{"out",			required_argument,	NULL, 'o'},
	{"in",			required_argument,	NULL, 'i'},
	{"conf",		required_argument,	NULL, 'c'},
	{"num",			required_argument,	NULL, 'n'},
	{"gap",			required_argument,	NULL, 't'},
	{"ring-size",		required_argument,	NULL, 'S'},
	{"kernel-pull",		required_argument,	NULL, 'k'},
	{"jumbo-support",	no_argument,		NULL, 'J'},
	{"rfraw",		no_argument,		NULL, 'R'},
	{"rand",		no_argument,		NULL, 'r'},
	{"verbose",		no_argument,		NULL, 'V'},
	{"version",		no_argument,		NULL, 'v'},
	{"help",		no_argument,		NULL, 'h'},
	{NULL, 0, NULL, 0}
};

static int sock;

static struct itimerval itimer;

static unsigned long interval = TX_KERNEL_PULL_INT;

static struct cpu_stats *stats;

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
	printf("\ntrafgen %s, multithreaded zero-copy network packet generator\n", VERSION_STRING);
	puts("http://www.netsniff-ng.org\n\n"
	     "Usage: trafgen [options]\n"
	     "Options:\n"
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
	     "  -S|--ring-size <size>             Manually set ring size to <size>:\n"
	     "                                    mmap space in KB/MB/GB, e.g. \'10MB\'\n"
	     "  -k|--kernel-pull <uint>           Kernel pull from user interval in us\n"
	     "                                    Default is 10us where the TX_RING\n"
	     "                                    is populated with payload from uspace\n"
	     "  -V|--verbose                      Be more verbose\n"
	     "  -v|--version                      Show version\n"
	     "  -h|--help                         Guess what?!\n\n"
	     "Examples:\n"
	     "  See trafgen.txf for configuration file examples.\n"
	     "  trafgen --dev eth0 --conf trafgen.txf\n"
	     "  trafgen --dev wlan0 --rfraw --conf beacon-test.txf -V\n"
	     "  trafgen --dev eth0 --conf trafgen.txf --rand --gap 1000\n"
	     "  trafgen --dev eth0 --conf trafgen.txf --rand --num 1400000 -k1000\n\n"
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
	printf("\ntrafgen %s, multithreaded zero-copy network packet generator\n", VERSION_STRING);
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

static struct cpu_stats *setup_shared_var(unsigned long cpus)
{
	int fd;
	char zbuff[cpus * sizeof(struct cpu_stats)];
	struct cpu_stats *buff;

	memset(zbuff, 0, sizeof(zbuff));

	fd = creat(".tmp_mmap", S_IRUSR | S_IWUSR);
	bug_on(fd < 0);
	close(fd);

	fd = open_or_die_m(".tmp_mmap", O_RDWR | O_CREAT | O_TRUNC,
			   S_IRUSR | S_IWUSR);
	write_or_die(fd, zbuff, sizeof(zbuff));

	buff = (void *) mmap(0, sizeof(zbuff), PROT_READ | PROT_WRITE,
			     MAP_SHARED, fd, 0);
	if (buff == (void *) -1)
		panic("Cannot setup shared variable!\n");

	close(fd);
	unlink(".tmp_mmap");

	return buff;
}

static void destroy_shared_var(void *buff, unsigned long cpus)
{
	munmap(buff, cpus * sizeof(struct cpu_stats));
}

static void xmit_slowpath_or_die(struct ctx *ctx, int cpu)
{
	int ret;
	unsigned long num = 1, i = 0;
	struct timeval start, end, diff;
	unsigned long long tx_bytes = 0, tx_packets = 0;
	struct sockaddr_ll saddr = {
		.sll_family = PF_PACKET,
		.sll_halen = ETH_ALEN,
		.sll_ifindex = device_ifindex(ctx->device),
	};

	if (ctx->num > 0)
		num = ctx->num;

	bug_on(gettimeofday(&start, NULL));

	while (likely(sigint == 0) && likely(num > 0)) {
		apply_counter(i);
		apply_randomizer(i);

		ret = sendto(sock, packets[i].payload, packets[i].len, 0,
			     (struct sockaddr *) &saddr, sizeof(saddr));
		if (unlikely(ret < 0))
			panic("Sendto error: %s!\n", strerror(errno));

		tx_bytes += packets[i].len;
		tx_packets++;

		if (!ctx->rand) {
			i++;
			if (i >= plen)
				i = 0;
		} else
			i = rand() % plen;

		if (ctx->num > 0)
			num--;

		if (ctx->gap > 0)
			usleep(ctx->gap);
	}

	bug_on(gettimeofday(&end, NULL));
	diff = tv_subtract(end, start);

	stats[cpu].tx_packets = tx_packets;
	stats[cpu].tx_bytes = tx_bytes;
	stats[cpu].tv_sec = diff.tv_sec;
	stats[cpu].tv_usec = diff.tv_usec;
}

static void xmit_fastpath_or_die(struct ctx *ctx, int cpu)
{
	int ifindex = device_ifindex(ctx->device);
	uint8_t *out = NULL;
	unsigned int it = 0;
	unsigned long num = 1, i = 0, size;
	struct ring tx_ring;
	struct frame_map *hdr;
	struct timeval start, end, diff;
	unsigned long long tx_bytes = 0, tx_packets = 0;

	fmemset(&tx_ring, 0, sizeof(tx_ring));

	size = ring_size(ctx->device, ctx->reserve_size);

	set_sock_prio(sock, 512);
	set_packet_loss_discard(sock);

	setup_tx_ring_layout(sock, &tx_ring, size, ctx->jumbo_support);
	create_tx_ring(sock, &tx_ring, ctx->verbose);
	mmap_tx_ring(sock, &tx_ring);
	alloc_tx_ring_frames(&tx_ring);
	bind_tx_ring(sock, &tx_ring, ifindex);

	if (ctx->kpull)
		interval = ctx->kpull;
	if (ctx->num > 0)
		num = ctx->num;

	itimer.it_interval.tv_sec = 0;
	itimer.it_interval.tv_usec = interval;

	itimer.it_value.tv_sec = 0;
	itimer.it_value.tv_usec = interval;

	setitimer(ITIMER_REAL, &itimer, NULL); 

	bug_on(gettimeofday(&start, NULL));

	while (likely(sigint == 0) && likely(num > 0)) {
		while (user_may_pull_from_tx(tx_ring.frames[it].iov_base) && likely(num > 0)) {
			hdr = tx_ring.frames[it].iov_base;

			/* Kernel assumes: data = ph.raw + po->tp_hdrlen -
			 *                        sizeof(struct sockaddr_ll); */
			out = ((uint8_t *) hdr) + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll);

			hdr->tp_h.tp_snaplen = packets[i].len;
			hdr->tp_h.tp_len = packets[i].len;

			apply_counter(i);
			apply_randomizer(i);

			fmemcpy(out, packets[i].payload, packets[i].len);

			tx_bytes += packets[i].len;
			tx_packets++;

			if (!ctx->rand) {
				i++;
				if (i >= plen)
					i = 0;
			} else
				i = rand() % plen;

			kernel_may_pull_from_tx(&hdr->tp_h);

			it++;
			if (it >= tx_ring.layout.tp_frame_nr)
				it = 0;

			if (ctx->num > 0)
				num--;

			if (unlikely(sigint == 1))
				break;
		}
	}

	bug_on(gettimeofday(&end, NULL));
	diff = tv_subtract(end, start);

	destroy_tx_ring(sock, &tx_ring);

	stats[cpu].tx_packets = tx_packets;
	stats[cpu].tx_bytes = tx_bytes;
	stats[cpu].tv_sec = diff.tv_sec;
	stats[cpu].tv_usec = diff.tv_usec;
}

static void xmit_packet_precheck(const struct ctx *ctx)
{
	int i;
	size_t mtu;

	bug_on(plen == 0 || plen != dlen);

	for (mtu = device_mtu(ctx->device), i = 0; i < plen; ++i) {
		if (packets[i].len > mtu + 14)
			panic("Device MTU < than packet%d's size!\n", i);
		if (packets[i].len <= 14)
			panic("Packet%d's size too short!\n", i);
	}
}

static void main_loop(struct ctx *ctx, char *confname, bool slow, int cpu)
{
	compile_packets(confname, ctx->verbose, cpu);
	xmit_packet_precheck(ctx);

	if (cpu == 0) {
		printf("Running! Hang up with ^C!\n\n");
		fflush(stdout);
	}

	sock = pf_socket();

	if (slow)
		xmit_slowpath_or_die(ctx, cpu);
	else
		xmit_fastpath_or_die(ctx, cpu);

	close(sock);

	cleanup_packets();
}

int main(int argc, char **argv)
{
	bool slow = false;
	int c, opt_index, i, j, vals[4] = {0}, irq;
	char *confname = NULL, *ptr;
	unsigned long cpus = get_number_cpus_online(), num = 0;
	unsigned long long tx_packets, tx_bytes;
	struct ctx ctx;

	srand(time(NULL));
	fmemset(&ctx, 0, sizeof(ctx));

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
			ctx.verbose = true;
			break;
		case 'd':
		case 'o':
			ctx.device = xstrndup(optarg, IFNAMSIZ);
			break;
		case 'r':
			ctx.rand = true;
			break;
		case 'R':
			ctx.rfraw = true;
			break;
		case 'J':
			ctx.jumbo_support = true;
			break;
		case 'c':
		case 'i':
			confname = xstrdup(optarg);
			break;
		case 'k':
			ctx.kpull = strtoul(optarg, NULL, 0);
			break;
		case 'n':
			num = strtoul(optarg, NULL, 0);
			break;
		case 't':
			slow = true;
			ctx.gap = strtoul(optarg, NULL, 0);
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
		case '?':
			switch (optopt) {
			case 'd':
			case 'c':
			case 'n':
			case 'f':
			case 'S':
			case 'o':
			case 'i':
			case 'k':
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

	stats = setup_shared_var(cpus);

	set_system_socket_memory(vals);

	if (ctx.rfraw) {
		ctx.device_trans = xstrdup(ctx.device);
		xfree(ctx.device);

		enter_rfmon_mac80211(ctx.device_trans, &ctx.device);
		sleep(0);
	}

	irq = device_irq_number(ctx.device);
	device_reset_irq_affinity(irq);

	for (i = 0; i < cpus; i++) {
		pid_t pid = fork();

		switch (pid) {
		case 0:
			if (num > 0) {
				ctx.num = num / cpus;
				if (i == cpus - 1)
					ctx.num += num % cpus;
			}

			cpu_affinity(i);
			main_loop(&ctx, confname, slow, i);

			goto thread_out;
		case -1:
			panic("Cannot fork processes!\n");
		}
	}

	for (i = 0; i < cpus; i++) {
		int status;

		wait(&status);
	}

	if (ctx.rfraw)
		leave_rfmon_mac80211(ctx.device_trans, ctx.device);

	reset_system_socket_memory(vals);

	for (i = 0, tx_packets = tx_bytes = 0; i < cpus; i++) {
		tx_packets += stats[i].tx_packets;
		tx_bytes += stats[i].tx_bytes;
	}

	fflush(stdout);
	printf("\n");
	printf("\r%12llu packets outgoing\n", tx_packets);
	printf("\r%12llu bytes outgoing\n", tx_bytes);
	for (i = 0; i < cpus; i++)
		printf("\r%12lu sec, %lu usec on CPU%d\n",
		       stats[i].tv_sec, stats[i].tv_usec, i);

thread_out:
	destroy_shared_var(stats, cpus);

	free(ctx.device);
	free(ctx.device_trans);
	free(confname);

	return 0;
}

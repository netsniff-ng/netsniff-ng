/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2011 - 2013 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>
#include <stdbool.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/fsuid.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/icmp.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <poll.h>
#include <netdb.h>
#include <math.h>
#include <unistd.h>

#include "xmalloc.h"
#include "die.h"
#include "str.h"
#include "sig.h"
#include "sock.h"
#include "cpus.h"
#include "lockme.h"
#include "privs.h"
#include "proc.h"
#include "mac80211.h"
#include "ioops.h"
#include "irq.h"
#include "config.h"
#include "built_in.h"
#include "trafgen_conf.h"
#include "tprintf.h"
#include "timer.h"
#include "ring_tx.h"
#include "csum.h"

struct ctx {
	bool rand, rfraw, jumbo_support, verbose, smoke_test, enforce, qdisc_path;
	size_t reserve_size;
	unsigned long num;
	unsigned int cpus;
	uid_t uid; gid_t gid;
	char *device, *device_trans, *rhost;
	struct timespec gap;
	struct sockaddr_in dest;
};

struct cpu_stats {
	unsigned long tv_sec, tv_usec;
	unsigned long long tx_packets, tx_bytes;
	unsigned long long cf_packets, cf_bytes;
	unsigned long long cd_packets;
	sig_atomic_t state;
};

static sig_atomic_t sigint = 0;

struct packet *packets = NULL;
size_t plen = 0;

struct packet_dyn *packet_dyn = NULL;
size_t dlen = 0;

static const char *short_options = "d:c:n:t:vJhS:rk:i:o:VRs:P:eE:pu:g:CHQq";
static const struct option long_options[] = {
	{"dev",			required_argument,	NULL, 'd'},
	{"out",			required_argument,	NULL, 'o'},
	{"in",			required_argument,	NULL, 'i'},
	{"conf",		required_argument,	NULL, 'c'},
	{"num",			required_argument,	NULL, 'n'},
	{"gap",			required_argument,	NULL, 't'},
	{"cpus",		required_argument,	NULL, 'P'},
	{"ring-size",		required_argument,	NULL, 'S'},
	{"kernel-pull",		required_argument,	NULL, 'k'},
	{"smoke-test",		required_argument,	NULL, 's'},
	{"seed",		required_argument,	NULL, 'E'},
	{"user",		required_argument,	NULL, 'u'},
	{"group",		required_argument,	NULL, 'g'},
	{"prio-high",		no_argument,		NULL, 'H'},
	{"notouch-irq",		no_argument,		NULL, 'Q'},
	{"no-sock-mem", 	no_argument,		NULL, 'A'},
	{"qdisc-path",		no_argument,		NULL, 'q'},
	{"jumbo-support",	no_argument,		NULL, 'J'},
	{"no-cpu-stats",	no_argument,		NULL, 'C'},
	{"cpp",			no_argument,		NULL, 'p'},
	{"rfraw",		no_argument,		NULL, 'R'},
	{"rand",		no_argument,		NULL, 'r'},
	{"verbose",		no_argument,		NULL, 'V'},
	{"version",		no_argument,		NULL, 'v'},
	{"example",		no_argument,		NULL, 'e'},
	{"help",		no_argument,		NULL, 'h'},
	{NULL, 0, NULL, 0}
};

static const char *copyright = "Please report bugs to <bugs@netsniff-ng.org>\n"
	"Copyright (C) 2011-2013 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,\n"
	"Swiss federal institute of technology (ETH Zurich)\n"
	"License: GNU GPL version 2.0\n"
	"This is free software: you are free to change and redistribute it.\n"
	"There is NO WARRANTY, to the extent permitted by law.";

static int sock;
static struct cpu_stats *stats;
static unsigned int seed;

#define CPU_STATS_STATE_CFG	1
#define CPU_STATS_STATE_CHK	2
#define CPU_STATS_STATE_RES	4

#ifndef ICMP_FILTER
# define ICMP_FILTER	1

struct icmp_filter {
	__u32	data;
};
#endif

#define SMOKE_N_PROBES	100

static void signal_handler(int number)
{
	switch (number) {
	case SIGINT:
	case SIGQUIT:
	case SIGTERM:
		sigint = 1;
	case SIGHUP:
	default:
		break;
	}
}

static void __noreturn help(void)
{
	printf("trafgen %s, multithreaded zero-copy network packet generator\n", VERSION_STRING);
	puts("http://www.netsniff-ng.org\n\n"
	     "Usage: trafgen [options]\n"
	     "Options:\n"
	     "  -i|-c|--in|--conf <cfg/->      Packet configuration file/stdin\n"
	     "  -o|-d|--out|--dev <netdev>     Networking device i.e., eth0\n"
	     "  -p|--cpp                       Run packet config through C preprocessor\n"
	     "  -J|--jumbo-support             Support 64KB super jumbo frames (def: 2048B)\n"
	     "  -R|--rfraw                     Inject raw 802.11 frames\n"
	     "  -s|--smoke-test <ipv4>         Probe if machine survived fuzz-tested packet\n"
	     "  -n|--num <uint>                Number of packets until exit (def: 0)\n"
	     "  -r|--rand                      Randomize packet selection (def: round robin)\n"
	     "  -P|--cpus <uint>               Specify number of forks(<= CPUs) (def: #CPUs)\n"
	     "  -t|--gap <time>                Set approx. interpacket gap (s/ms/us/ns, def: us)\n"
	     "  -S|--ring-size <size>          Manually set mmap size (KiB/MiB/GiB)\n"
	     "  -E|--seed <uint>               Manually set srand(3) seed\n"
	     "  -u|--user <userid>             Drop privileges and change to userid\n"
	     "  -g|--group <groupid>           Drop privileges and change to groupid\n"
	     "  -H|--prio-high                 Make this high priority process\n"
	     "  -A|--no-sock-mem               Don't tune core socket memory\n"
	     "  -Q|--notouch-irq               Do not touch IRQ CPU affinity of NIC\n"
	     "  -q|--qdisc-path                Enabled qdisc kernel path (default off since 3.14)\n"
	     "  -V|--verbose                   Be more verbose\n"
	     "  -C|--no-cpu-stats              Do not print CPU time statistics on exit\n"
	     "  -v|--version                   Show version and exit\n"
	     "  -e|--example                   Show built-in packet config example\n"
	     "  -h|--help                      Guess what?!\n\n"
	     "Examples:\n"
	     "  trafgen --dev eth0 --conf trafgen.cfg\n"
	     "  trafgen -e | trafgen -i - -o eth0 --cpp -n 1\n"
	     "  trafgen --dev eth0 --conf fuzzing.cfg --smoke-test 10.0.0.1\n"
	     "  trafgen --dev wlan0 --rfraw --conf beacon-test.txf -V --cpus 2\n"
	     "  trafgen --dev eth0 --conf frag_dos.cfg --rand --gap 1000us\n"
	     "  trafgen --dev eth0 --conf icmp.cfg --rand --num 1400000 -k1000\n"
	     "  trafgen --dev eth0 --conf tcp_syn.cfg -u `id -u bob` -g `id -g bob`\n\n"
	     "Arbitrary packet config examples (e.g. trafgen -e > trafgen.cfg):\n"
	     "  Run packet on  all CPUs:              { fill(0xff, 64) csum16(0, 64) }\n"
	     "  Run packet only on CPU1:    cpu(1):   { rnd(64), 0b11001100, 0xaa }\n"
	     "  Run packet only on CPU1-2:  cpu(1-2): { drnd(64),'a',csum16(1, 8),'b',42 }\n\n"
	     "Generate config files from existing pcap using netsniff-ng:\n"
	     "  netsniff-ng --in dump.pcap --out dump.cfg\n"
	     "Note:\n"
	     "  Smoke/fuzz test example: machine A, 10.0.0.2 (trafgen) is directly\n"
	     "  connected to machine B (test kernel), 10.0.0.1. If ICMP reply fails\n"
	     "  we assume the kernel crashed, thus we print the packet and quit.\n"
	     "  In case you find a ping-of-death, please mention trafgen in your\n"
	     "  commit message of the fix!\n\n"
	     "  For introducing bit errors, delays with random variation and more,\n"
	     "  make use of tc(8) with its different disciplines, i.e. netem.\n\n"
	     "  For generating different package distributions, you can use scripting\n"
	     "  to generate a trafgen config file with packet ratios as:\n\n"
	     "     IMIX             64:7,  570:4,  1518:1\n"
	     "     Tolly            64:55,  78:5,   576:17, 1518:23\n"
	     "     Cisco            64:7,  594:4,  1518:1\n"
	     "     RPR Trimodal     64:60, 512:20, 1518:20\n"
	     "     RPR Quadrimodal  64:50, 512:15, 1518:15, 9218:20\n");
	puts(copyright);
	die();
}

static void __noreturn example(void)
{
	const char *e =
	"/* Note: dynamic elements make trafgen slower! */\n"
	"#include <stddef.h>\n\n"
	"{\n"
	"  /* MAC Destination */\n"
	"  fill(0xff, ETH_ALEN),\n"
	"  /* MAC Source */\n"
	"  0x00, 0x02, 0xb3, drnd(3),\n"
	"  /* IPv4 Protocol */\n"
	"  c16(ETH_P_IP),\n"
	"  /* IPv4 Version, IHL, TOS */\n"
	"  0b01000101, 0,\n"
	"  /* IPv4 Total Len */\n"
	"  c16(59),\n"
	"  /* IPv4 Ident */\n"
	"  drnd(2),\n"
	"  /* IPv4 Flags, Frag Off */\n"
	"  0b01000000, 0,\n"
	"  /* IPv4 TTL */\n"
	"  64,\n"
	"  /* Proto TCP */\n"
	"  0x06,\n"
	"  /* IPv4 Checksum (IP header from, to) */\n"
	"  csumip(14, 33),\n"
	"  /* Source IP */\n"
	"  drnd(4),\n"
	"  /* Dest IP */\n"
	"  drnd(4),\n"
	"  /* TCP Source Port */\n"
	"  drnd(2),\n"
	"  /* TCP Dest Port */\n"
	"  c16(80),\n"
	"  /* TCP Sequence Number */\n"
	"  drnd(4),\n"
	"  /* TCP Ackn. Number */\n"
	"  c32(0),\n"
	"  /* TCP Header length + TCP SYN/ECN Flag */\n"
	"  c16((8 << 12) | TCP_FLAG_SYN | TCP_FLAG_ECE)\n"
	"  /* Window Size */\n"
	"  c16(16),\n"
	"  /* TCP Checksum (offset IP, offset TCP) */\n"
	"  csumtcp(14, 34),\n"
	"  /* TCP Options */\n"
	"  0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x06,\n"
	"  0x91, 0x68, 0x7d, 0x06, 0x91, 0x68, 0x6f,\n"
	"  /* Data blob */\n"
	"  \"gotcha!\",\n"
	"}";
	puts(e);
	die();
}

static void __noreturn version(void)
{
	printf("trafgen %s, Git id: %s\n", VERSION_LONG, GITVERSION);
	puts("multithreaded zero-copy network packet generator\n"
	     "http://www.netsniff-ng.org\n");
	puts(copyright);
	die();
}

static void apply_counter(int id)
{
	size_t j, counter_max = packet_dyn[id].clen;

	for (j = 0; j < counter_max; ++j) {
		uint8_t val;
		struct counter *counter = &packet_dyn[id].cnt[j];

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
		packets[id].payload[counter->off] = val;
	}
}

static void apply_randomizer(int id)
{
	size_t j, rand_max = packet_dyn[id].rlen;

	for (j = 0; j < rand_max; ++j) {
		uint8_t val = (uint8_t) rand();
		struct randomizer *randomizer = &packet_dyn[id].rnd[j];

		packets[id].payload[randomizer->off] = val;
	}
}

static void apply_csum16(int id)
{
	size_t j, csum_max = packet_dyn[id].slen;

	for (j = 0; j < csum_max; ++j) {
		uint16_t sum = 0;
		struct csum16 *csum = &packet_dyn[id].csum[j];

		fmemset(&packets[id].payload[csum->off], 0, sizeof(sum));
		if (unlikely((size_t) csum->to >= packets[id].len))
			csum->to = packets[id].len - 1;

		switch (csum->which) {
		case CSUM_IP:
			sum = calc_csum(packets[id].payload + csum->from,
					csum->to - csum->from + 1, 0);
			break;
		case CSUM_UDP:
			sum = p4_csum((void *) packets[id].payload + csum->from,
				      packets[id].payload + csum->to,
				      (packets[id].len - csum->to),
				      IPPROTO_UDP);
			break;
		case CSUM_TCP:
			sum = p4_csum((void *) packets[id].payload + csum->from,
				      packets[id].payload + csum->to,
				      (packets[id].len - csum->to),
				      IPPROTO_TCP);
			break;
		default:
			bug();
			break;
		}

		fmemcpy(&packets[id].payload[csum->off], &sum, sizeof(sum));
	}
}

static struct cpu_stats *setup_shared_var(unsigned int cpus)
{
	int fd;
	size_t len = cpus * sizeof(struct cpu_stats);
	char *zbuff, file[256];
	struct cpu_stats *buff;

	zbuff = xzmalloc(len);
	slprintf(file, sizeof(file), ".tmp_mmap.%u", (unsigned int) rand());

	fd = creat(file, S_IRUSR | S_IWUSR);
	bug_on(fd < 0);
	close(fd);

	fd = open_or_die_m(file, O_RDWR | O_CREAT | O_TRUNC,
			   S_IRUSR | S_IWUSR);
	write_or_die(fd, zbuff, len);
	xfree(zbuff);

	buff = mmap(NULL, len, PROT_READ | PROT_WRITE,
		    MAP_SHARED, fd, 0);
	if (buff == MAP_FAILED)
		panic("Cannot setup shared variable!\n");

	close(fd);
	unlink(file);

	memset(buff, 0, len);
	return buff;
}

static void destroy_shared_var(void *buff, unsigned int cpus)
{
	munmap(buff, cpus * sizeof(struct cpu_stats));
}

static void dump_trafgen_snippet(uint8_t *payload, size_t len)
{
	size_t i;

	printf("{");
	for (i = 0; i < len; ++i) {
		if (i % 15 == 0)
			printf("\n  ");
		printf("0x%02x, ", payload[i]);
	}
	printf("\n}\n");
	fflush(stdout);
}

static int xmit_smoke_setup(struct ctx *ctx)
{
	int icmp_sock, ret, ttl = 64;
	struct icmp_filter filter;

	icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (icmp_sock < 0)
		panic("Cannot get a ICMP socket: %s!\n", strerror(errno));

	filter.data = ~(1 << ICMP_ECHOREPLY);

	ret = setsockopt(icmp_sock, SOL_RAW, ICMP_FILTER, &filter, sizeof(filter));
	if (ret < 0)
		panic("Cannot install filter!\n");

	ret = setsockopt(icmp_sock, SOL_IP, IP_TTL, &ttl, sizeof(ttl));
	if (ret < 0)
		panic("Cannot set TTL!\n");

	memset(&ctx->dest, 0, sizeof(ctx->dest));
	ctx->dest.sin_family = AF_INET;
	ctx->dest.sin_port = 0;

	ret = inet_aton(ctx->rhost, &ctx->dest.sin_addr);
	if (ret < 0)
		panic("Cannot resolv address!\n");

	return icmp_sock;
}

static int xmit_smoke_probe(int icmp_sock, struct ctx *ctx)
{
	int ret;
	unsigned int i, j;
	short ident, cnt = 1, idstore[SMOKE_N_PROBES];
	uint8_t outpack[512], *data;
	struct icmphdr *icmp;
	struct iphdr *ip;
	size_t len = sizeof(*icmp) + 56;
	struct sockaddr_in from;
	socklen_t from_len;
	struct pollfd fds = {
		.fd = icmp_sock,
		.events = POLLIN,
	};

	fmemset(idstore, 0, sizeof(idstore));
	for (j = 0; j < SMOKE_N_PROBES; j++) {
		while ((ident = htons((short) rand())) == 0)
			sleep(0);
		idstore[j] = ident;

		memset(outpack, 0, sizeof(outpack));
		icmp = (void *) outpack;
		icmp->type = ICMP_ECHO;
		icmp->un.echo.id = ident;
		icmp->un.echo.sequence = htons(cnt++);

		data = ((uint8_t *) outpack + sizeof(*icmp));
		for (i = 0; i < 56; ++i)
			data[i] = (uint8_t) rand();

		icmp->checksum = csum((unsigned short *) outpack,
				      len / sizeof(unsigned short));

		ret = sendto(icmp_sock, outpack, len, MSG_DONTWAIT,
			     (struct sockaddr *) &ctx->dest, sizeof(ctx->dest));
		if (unlikely(ret != (int) len))
			panic("Cannot send out probe: %s!\n", strerror(errno));

		ret = poll(&fds, 1, 50);
		if (ret < 0)
			panic("Poll failed!\n");

		if (fds.revents & POLLIN) {
			ret = recvfrom(icmp_sock, outpack, sizeof(outpack), 0,
				       (struct sockaddr *) &from, &from_len);
			if (unlikely(ret <= 0))
				panic("Probe receive failed!\n");
			if (unlikely(from_len != sizeof(ctx->dest)))
				continue;
			if (unlikely(memcmp(&from, &ctx->dest, sizeof(ctx->dest))))
				continue;
			if (unlikely((size_t) ret < sizeof(*ip) + sizeof(*icmp)))
				continue;
			ip = (void *) outpack;
			if (unlikely(ip->ihl * 4 + sizeof(*icmp) > (size_t) ret))
				continue;
			icmp = (void *) outpack + ip->ihl * 4;
			for (i = 0; i < array_size(idstore); ++i) {
				if (unlikely(icmp->un.echo.id != idstore[i]))
					continue;
				return 0;
			}
		}
	}

	return -1;
}

static void xmit_slowpath_or_die(struct ctx *ctx, unsigned int cpu, unsigned long orig_num)
{
	int ret, icmp_sock = -1;
	unsigned long num = 1, i = 0;
	struct timeval start, end, diff;
	unsigned long long tx_bytes = 0, tx_packets = 0;
	struct packet_dyn *pktd;
	struct sockaddr_ll saddr = {
		.sll_family = PF_PACKET,
		.sll_halen = ETH_ALEN,
		.sll_ifindex = device_ifindex(ctx->device),
	};

	if (ctx->num > 0)
		num = ctx->num;
	if (ctx->num == 0 && orig_num > 0)
		num = 0;

	if (ctx->smoke_test)
		icmp_sock = xmit_smoke_setup(ctx);

	drop_privileges(ctx->enforce, ctx->uid, ctx->gid);

	bug_on(gettimeofday(&start, NULL));

	while (likely(sigint == 0 && num > 0 && plen > 0)) {
		pktd = &packet_dyn[i];
		if (pktd->clen + pktd->rlen + pktd->slen) {
			apply_counter(i);
			apply_randomizer(i);
			apply_csum16(i);
		}
retry:
		ret = sendto(sock, packets[i].payload, packets[i].len, 0,
			     (struct sockaddr *) &saddr, sizeof(saddr));
		if (unlikely(ret < 0)) {
			if (errno == ENOBUFS) {
				sched_yield();
				goto retry;
			}
			if (ctx->smoke_test)
				panic("Sendto error: %s!\n", strerror(errno));
		}

		tx_bytes += packets[i].len;
		tx_packets++;

		if (ctx->smoke_test) {
			ret = xmit_smoke_probe(icmp_sock, ctx);
			if (unlikely(ret < 0)) {
				printf("%sSmoke test alert:%s\n", colorize_start(bold), colorize_end());
				printf("  Remote host seems to be unresponsive to ICMP probes!\n");
				printf("  Last instance was packet%lu, seed:%u, trafgen snippet:\n\n",
				       i, seed);

				dump_trafgen_snippet(packets[i].payload, packets[i].len);
				break;
			}
		}

		if (!ctx->rand) {
			i++;
			if (i >= plen)
				i = 0;
		} else
			i = rand() % plen;

		if (ctx->num > 0)
			num--;

		if ((ctx->gap.tv_sec | ctx->gap.tv_nsec) > 0)
			nanosleep(&ctx->gap, NULL);
	}

	bug_on(gettimeofday(&end, NULL));
	timersub(&end, &start, &diff);

	if (ctx->smoke_test)
		close(icmp_sock);

	stats[cpu].tx_packets = tx_packets;
	stats[cpu].tx_bytes = tx_bytes;
	stats[cpu].tv_sec = diff.tv_sec;
	stats[cpu].tv_usec = diff.tv_usec;

	stats[cpu].state |= CPU_STATS_STATE_RES;
}

static void xmit_fastpath_or_die(struct ctx *ctx, unsigned int cpu, unsigned long orig_num)
{
	int ifindex = device_ifindex(ctx->device);
	uint8_t *out = NULL;
	unsigned int it = 0;
	unsigned long num = 1, i = 0;
	size_t size = ring_size(ctx->device, ctx->reserve_size);
	struct ring tx_ring;
	struct frame_map *hdr;
	struct timeval start, end, diff;
	struct packet_dyn *pktd;
	unsigned long long tx_bytes = 0, tx_packets = 0;

	set_sock_prio(sock, 512);

	ring_tx_setup(&tx_ring, sock, size, ifindex, ctx->jumbo_support, ctx->verbose);

	drop_privileges(ctx->enforce, ctx->uid, ctx->gid);

	if (ctx->num > 0)
		num = ctx->num;
	if (ctx->num == 0 && orig_num > 0)
		num = 0;

	bug_on(gettimeofday(&start, NULL));

	while (likely(sigint == 0 && num > 0 && plen > 0)) {
		if (!user_may_pull_from_tx(tx_ring.frames[it].iov_base)) {
			int ret = pull_and_flush_tx_ring(sock);
			if (unlikely(ret < 0)) {
				/* We could hit EBADF if the socket has been closed before
				 * the timer was triggered.
				 */
				if (errno != EBADF && errno != ENOBUFS)
					panic("Flushing TX_RING failed: %s!\n", strerror(errno));
			}

			continue;
		}

		hdr = tx_ring.frames[it].iov_base;
		out = ((uint8_t *) hdr) + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll);

		hdr->tp_h.tp_snaplen = packets[i].len;
		hdr->tp_h.tp_len = packets[i].len;

		pktd = &packet_dyn[i];
		if (pktd->clen + pktd->rlen + pktd->slen) {
			apply_counter(i);
			apply_randomizer(i);
			apply_csum16(i);
		}

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
	}

	bug_on(gettimeofday(&end, NULL));
	timersub(&end, &start, &diff);

	pull_and_flush_tx_ring_wait(sock);
	destroy_tx_ring(sock, &tx_ring);

	stats[cpu].tx_packets = tx_packets;
	stats[cpu].tx_bytes = tx_bytes;
	stats[cpu].tv_sec = diff.tv_sec;
	stats[cpu].tv_usec = diff.tv_usec;

	stats[cpu].state |= CPU_STATS_STATE_RES;
}

static inline void __set_state(unsigned int cpu, sig_atomic_t s)
{
	stats[cpu].state = s;
}

static inline sig_atomic_t __get_state(unsigned int cpu)
{
	return stats[cpu].state;
}

static unsigned long __wait_and_sum_others(struct ctx *ctx, unsigned int cpu)
{
	unsigned int i;
	unsigned long total;

	for (i = 0, total = plen; i < ctx->cpus; i++) {
		if (i == cpu)
			continue;

		while ((__get_state(i) &
		       (CPU_STATS_STATE_CFG |
			CPU_STATS_STATE_RES)) == 0 &&
		       sigint == 0)
			sched_yield();

		total += stats[i].cf_packets;
	}

	return total;
}

static void __correct_global_delta(struct ctx *ctx, unsigned int cpu, unsigned long orig)
{
	unsigned int i;
	unsigned long total;
	int cpu_sel;
	long long delta_correction = 0;

	for (i = 0, total = ctx->num; i < ctx->cpus; i++) {
		if (i == cpu)
			continue;

		while ((__get_state(i) &
		       (CPU_STATS_STATE_CHK |
			CPU_STATS_STATE_RES)) == 0 &&
		       sigint == 0)
			sched_yield();

		total += stats[i].cd_packets;
	}

	if (total > orig)
		delta_correction = -1 * ((long long) total - orig);
	if (total < orig)
		delta_correction = +1 * ((long long) orig - total);

	for (cpu_sel = -1, i = 0; i < ctx->cpus; i++) {
		if (stats[i].cd_packets > 0) {
			if ((long long) stats[i].cd_packets +
			    delta_correction >= 0) {
				cpu_sel = i;
				break;
			}
		}
	}

	if ((int) cpu == cpu_sel)
		ctx->num += delta_correction;
}

static void __set_state_cf(unsigned int cpu, unsigned long p, unsigned long b,
			   sig_atomic_t s)
{
	stats[cpu].cf_packets = p;
	stats[cpu].cf_bytes = b;
	stats[cpu].state = s;
}

static void __set_state_cd(unsigned int cpu, unsigned long p, sig_atomic_t s)
{
	stats[cpu].cd_packets = p;
	stats[cpu].state = s;
}

static int xmit_packet_precheck(struct ctx *ctx, unsigned int cpu)
{
	unsigned int i;
	unsigned long plen_total, orig = ctx->num;
	size_t mtu, total_len = 0;

	bug_on(plen != dlen);

	for (i = 0; i < plen; ++i)
		total_len += packets[i].len;

	__set_state_cf(cpu, plen, total_len, CPU_STATS_STATE_CFG);
	plen_total = __wait_and_sum_others(ctx, cpu);

	if (orig > 0) {
		ctx->num = (unsigned long) round((1.0 * plen / plen_total) * orig);

		__set_state_cd(cpu, ctx->num, CPU_STATS_STATE_CHK |
			       CPU_STATS_STATE_CFG);
		__correct_global_delta(ctx, cpu, orig);
	}

	if (plen == 0) {
		__set_state(cpu, CPU_STATS_STATE_RES);
		return 0;
	}

	for (mtu = device_mtu(ctx->device), i = 0; i < plen; ++i) {
		if (packets[i].len > mtu + 14)
			panic("Device MTU < than packet%d's size!\n", i);
		if (packets[i].len <= 14)
			panic("Packet%d's size too short!\n", i);
	}

	return 0;
}

static void main_loop(struct ctx *ctx, char *confname, bool slow,
		      unsigned int cpu, bool invoke_cpp, unsigned long orig_num)
{
	compile_packets(confname, ctx->verbose, cpu, invoke_cpp);
	if (xmit_packet_precheck(ctx, cpu) < 0)
		return;

	if (cpu == 0) {
		unsigned int i;
		size_t total_len = 0, total_pkts = 0;

		for (i = 0; i < ctx->cpus; ++i) {
			total_len  += stats[i].cf_bytes;
			total_pkts += stats[i].cf_packets;
		}

		printf("%6zu packets to schedule\n", total_pkts);
		printf("%6zu bytes in total\n", total_len);
		printf("Running! Hang up with ^C!\n\n");
		fflush(stdout);
	}

	sock = pf_socket();

	if (ctx->qdisc_path == false)
		set_sock_qdisc_bypass(sock, ctx->verbose);

	if (slow)
		xmit_slowpath_or_die(ctx, cpu, orig_num);
	else
		xmit_fastpath_or_die(ctx, cpu, orig_num);

	close(sock);

	cleanup_packets();
}

static unsigned int generate_srand_seed(void)
{
	int fd;
	unsigned int _seed;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd < 0)
		return time(NULL);

	read_or_die(fd, &_seed, sizeof(_seed));

	close(fd);
	return _seed;
}

static void on_panic_del_rfmon(void *arg)
{
	leave_rfmon_mac80211(arg);
}

int main(int argc, char **argv)
{
	bool slow = false, invoke_cpp = false, reseed = true, cpustats = true;
	bool prio_high = false, set_irq_aff = true, set_sock_mem = true;
	int c, opt_index, vals[4] = {0}, irq;
	uint64_t gap = 0;
	unsigned int i, j;
	char *confname = NULL, *ptr;
	unsigned long cpus_tmp, orig_num = 0;
	unsigned long long tx_packets, tx_bytes;
	struct ctx ctx;

	fmemset(&ctx, 0, sizeof(ctx));
	ctx.cpus = get_number_cpus_online();
	ctx.uid = getuid();
	ctx.gid = getgid();
	ctx.qdisc_path = false;

	/* Keep an initial small default size to reduce cache-misses. */
	ctx.reserve_size = 512 * (1 << 10);

	while ((c = getopt_long(argc, argv, short_options, long_options,
				&opt_index)) != EOF) {
		switch (c) {
		case 'h':
			help();
			break;
		case 'v':
			version();
			break;
		case 'C':
			cpustats = false;
			break;
		case 'e':
			example();
			break;
		case 'p':
			invoke_cpp = true;
			break;
		case 'V':
			ctx.verbose = true;
			break;
		case 'P':
			cpus_tmp = strtoul(optarg, NULL, 0);
			if (cpus_tmp > 0 && cpus_tmp < ctx.cpus)
				ctx.cpus = cpus_tmp;
			break;
		case 'd':
		case 'o':
			ctx.device = xstrndup(optarg, IFNAMSIZ);
			break;
		case 'H':
			prio_high = true;
			break;
		case 'A':
			set_sock_mem = false;
			break;
		case 'Q':
			set_irq_aff = false;
			break;
		case 'q':
			ctx.qdisc_path = true;
			break;
		case 'r':
			ctx.rand = true;
			break;
		case 's':
			slow = true;
			ctx.cpus = 1;
			ctx.smoke_test = true;
			ctx.rhost = xstrdup(optarg);
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
			if (!strncmp("-", confname, strlen("-")))
				ctx.cpus = 1;
			break;
		case 'u':
			ctx.uid = strtoul(optarg, NULL, 0);
			ctx.enforce = true;
			break;
		case 'g':
			ctx.gid = strtoul(optarg, NULL, 0);
			ctx.enforce = true;
			break;
		case 'k':
			printf("Option -k/--kernel-pull is no longer used and "
			       "will be removed in a future release!\n");
			break;
		case 'E':
			seed = strtoul(optarg, NULL, 0);
			reseed = false;
			break;
		case 'n':
			orig_num = strtoul(optarg, NULL, 0);
			ctx.num = orig_num;
			break;
		case 't':
			slow = true;
			ptr = optarg;
			prctl(PR_SET_TIMERSLACK, 1UL);
			gap = strtoul(optarg, NULL, 0);

			for (j = i = strlen(optarg); i > 0; --i) {
				if (!isdigit(optarg[j - i]))
					break;
				ptr++;
			}

			if (!strncmp(ptr, "ns", strlen("ns"))) {
				ctx.gap.tv_sec = gap / 1000000000;
				ctx.gap.tv_nsec = gap % 1000000000;
			} else if (*ptr == '\0' || !strncmp(ptr, "us", strlen("us"))) {
				/*  Default to microseconds for backwards
				 *  compatibility if no postfix is given.
				 */
				ctx.gap.tv_sec = gap / 1000000;
				ctx.gap.tv_nsec = (gap % 1000000) * 1000;
			} else if (!strncmp(ptr, "ms", strlen("ms"))) {
				ctx.gap.tv_sec = gap / 1000;
				ctx.gap.tv_nsec = (gap % 1000) * 1000000;
			} else if (!strncmp(ptr, "s", strlen("s"))) {
				ctx.gap.tv_sec = gap;
				ctx.gap.tv_nsec = 0;
			} else
				panic("Syntax error in time param!\n");

			if (gap > 0)
				/* Fall back to single core to not mess up
				 * correct timing. We are slow anyway!
				 */
				ctx.cpus = 1;
			break;
		case 'S':
			ptr = optarg;

			for (j = i = strlen(optarg); i > 0; --i) {
				if (!isdigit(optarg[j - i]))
					break;
				ptr++;
			}

			if (!strncmp(ptr, "KiB", strlen("KiB")))
				ctx.reserve_size = 1 << 10;
			else if (!strncmp(ptr, "MiB", strlen("MiB")))
				ctx.reserve_size = 1 << 20;
			else if (!strncmp(ptr, "GiB", strlen("GiB")))
				ctx.reserve_size = 1 << 30;
			else
				panic("Syntax error in ring size param!\n");

			ctx.reserve_size *= strtoul(optarg, NULL, 0);
			break;
		case '?':
			switch (optopt) {
			case 'd':
			case 'c':
			case 'n':
			case 'S':
			case 's':
			case 'P':
			case 'o':
			case 'E':
			case 'i':
			case 'k':
			case 'u':
			case 'g':
			case 't':
				panic("Option -%c requires an argument!\n",
				      optopt);
			default:
				if (isprint(optopt))
					printf("Unknown option character `0x%X\'!\n", optopt);
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

	register_signal(SIGINT, signal_handler);
	register_signal(SIGQUIT, signal_handler);
	register_signal(SIGTERM, signal_handler);
	register_signal(SIGHUP, signal_handler);

	if (prio_high) {
		set_proc_prio(-20);
		set_sched_status(SCHED_FIFO, sched_get_priority_max(SCHED_FIFO));
	}

	if (set_sock_mem)
		set_system_socket_memory(vals, array_size(vals));
	xlockme();

	if (ctx.rfraw) {
		ctx.device_trans = xstrdup(ctx.device);
		xfree(ctx.device);

		enter_rfmon_mac80211(ctx.device_trans, &ctx.device);
		panic_handler_add(on_panic_del_rfmon, ctx.device);
		sleep(0);
	}

	/*
	 * If number of packets is smaller than number of CPUs use only as
	 * many CPUs as there are packets. Otherwise we end up sending more
	 * packets than intended or none at all.
	 */
	if (ctx.num)
		ctx.cpus = min_t(unsigned int, ctx.num, ctx.cpus);

	irq = device_irq_number(ctx.device);
	if (set_irq_aff)
		device_set_irq_affinity_list(irq, 0, ctx.cpus - 1);

	stats = setup_shared_var(ctx.cpus);

	for (i = 0; i < ctx.cpus; i++) {
		pid_t pid = fork();

		switch (pid) {
		case 0:
			if (reseed)
				seed = generate_srand_seed();
			srand(seed);

			cpu_affinity(i);
			main_loop(&ctx, confname, slow, i, invoke_cpp, orig_num);

			goto thread_out;
		case -1:
			panic("Cannot fork processes!\n");
		}
	}

	for (i = 0; i < ctx.cpus; i++) {
		int status;

		wait(&status);
		if (WEXITSTATUS(status) == EXIT_FAILURE)
			die();
	}

	if (ctx.rfraw)
		leave_rfmon_mac80211(ctx.device);

	if (set_sock_mem)
		reset_system_socket_memory(vals, array_size(vals));

	for (i = 0, tx_packets = tx_bytes = 0; i < ctx.cpus; i++) {
		while ((__get_state(i) & CPU_STATS_STATE_RES) == 0)
			sched_yield();

		tx_packets += stats[i].tx_packets;
		tx_bytes   += stats[i].tx_bytes;
	}

	fflush(stdout);
	printf("\n");
	printf("\r%12llu packets outgoing\n", tx_packets);
	printf("\r%12llu bytes outgoing\n", tx_bytes);
	for (i = 0; cpustats && i < ctx.cpus; i++) {
		printf("\r%12lu sec, %lu usec on CPU%d (%llu packets)\n",
		       stats[i].tv_sec, stats[i].tv_usec, i,
		       stats[i].tx_packets);
	}

thread_out:
	xunlockme();
	destroy_shared_var(stats, ctx.cpus);
	if (set_irq_aff)
		device_restore_irq_affinity_list();

	free(ctx.device);
	free(ctx.device_trans);
	free(ctx.rhost);
	free(confname);

	return 0;
}

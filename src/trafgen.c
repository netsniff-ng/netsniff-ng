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
#include <sys/fsuid.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/icmp.h>
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
#include "mac80211.h"
#include "xutils.h"
#include "xio.h"
#include "built_in.h"
#include "trafgen_conf.h"
#include "tprintf.h"
#include "ring_tx.h"
#include "csum.h"

struct ctx {
	bool rand, rfraw, jumbo_support, verbose, smoke_test, enforce;
	unsigned long kpull, num, gap, reserve_size, cpus;
	struct sockaddr_in dest;
	uid_t uid;
	gid_t gid;
	char *device, *device_trans, *rhost;
};

struct cpu_stats {
	unsigned long tv_sec, tv_usec;
	unsigned long long tx_packets, tx_bytes;
	unsigned long long cf_packets, cf_bytes;
	unsigned long long cd_packets;
	sig_atomic_t state;
};

sig_atomic_t sigint = 0;

struct packet *packets = NULL;
size_t plen = 0;

struct packet_dyn *packet_dyn = NULL;
size_t dlen = 0;

static const char *short_options = "d:c:n:t:vJhS:rk:i:o:VRsP:eE:pu:g:";
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
	{"jumbo-support",	no_argument,		NULL, 'J'},
	{"cpp",			no_argument,		NULL, 'p'},
	{"rfraw",		no_argument,		NULL, 'R'},
	{"rand",		no_argument,		NULL, 'r'},
	{"verbose",		no_argument,		NULL, 'V'},
	{"version",		no_argument,		NULL, 'v'},
	{"example",		no_argument,		NULL, 'e'},
	{"help",		no_argument,		NULL, 'h'},
	{NULL, 0, NULL, 0}
};

static int sock;

static struct itimerval itimer;

static unsigned long interval = TX_KERNEL_PULL_INT;

static struct cpu_stats *stats;

unsigned int seed;

#define CPU_STATS_STATE_CFG	1
#define CPU_STATS_STATE_CHK	2
#define CPU_STATS_STATE_RES	4

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

#ifndef ICMP_FILTER
# define ICMP_FILTER	1

struct icmp_filter {
	__u32	data;
};
#endif

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
	     "  -i|-c|--in|--conf <cfg-file/->    Packet configuration file/stdin\n"
	     "  -p|--cpp                          Run packet config through preprocessor\n"
	     "  -J|--jumbo-support                Support 64KB Super Jumbo Frames (def: 2048B)\n"
	     "  -R|--rfraw                        Inject raw 802.11 frames\n"
	     "  -s|--smoke-test <ipv4-receiver>   Test if machine survived packet\n"
	     "  -n|--num <uint>                   Number of packets until exit (def: 0)\n"
	     "  -r|--rand                         Randomize packet selection (def: round robin)\n"
	     "  -P|--cpus <uint>                  Specify number of forks(<= CPUs) (def: #CPUs)\n"
	     "  -t|--gap <uint>                   Interpacket gap in us (approx)\n"
	     "  -S|--ring-size <size>             Manually set mmap size (KB/MB/GB): e.g.\'10MB\'\n"
	     "  -k|--kernel-pull <uint>           Kernel batch interval in us (def: 10us)\n"
	     "  -E|--seed <uint>                  Manually set srand(3) seed\n"
	     "  -u|--user <userid>                Drop privileges and change to userid\n"
	     "  -g|--group <groupid>              Drop privileges and change to groupid\n"
	     "  -V|--verbose                      Be more verbose\n"
	     "  -v|--version                      Show version\n"
	     "  -e|--example                      Show built-in packet config example\n"
	     "  -h|--help                         Guess what?!\n\n"
	     "Examples:\n"
	     "  See trafgen.txf for configuration file examples.\n"
	     "  trafgen --dev eth0 --conf trafgen.cfg\n"
	     "  trafgen -e | trafgen -i - -o eth0 --cpp -n 1\n"
	     "  trafgen --dev eth0 --conf trafgen.cfg --smoke-test 10.0.0.1\n"
	     "  trafgen --dev wlan0 --rfraw --conf beacon-test.txf -V --cpus 2\n"
	     "  trafgen --dev eth0 --conf trafgen.cfg --rand --gap 1000\n"
	     "  trafgen --dev eth0 --conf trafgen.cfg --rand --num 1400000 -k1000\n"
	     "  trafgen --dev eth0 --conf trafgen.cfg -u `id -u bob` -g `id -g bob`\n\n"
	     "Arbitrary packet config examples (e.g. trafgen -e > trafgen.cfg):\n"
	     "  Run packet on  all CPUs:              { fill(0xff, 64) csum16(0, 64) }\n"
	     "  Run packet only on CPU1:    cpu(1):   { rnd(64), 0b11001100, 0xaa }\n"
	     "  Run packet only on CPU1-2:  cpu(1:2): { drnd(64),'a',csum16(1, 8),'b',42 }\n\n"
	     "Note:\n"
	     "  Smoke test example: machine A, 10.0.0.2 (trafgen) is directly\n"
	     "  connected to machine B (test kernel), 10.0.0.1. If ICMP reply fails\n"
	     "  we assume the kernel crashed, thus we print the packet and quit.\n"
	     "  In case you find a ping-of-death, please mention trafgen in your\n"
	     "  commit message of the fix!\n\n"
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

static void example(void)
{
	const char *e =
	"/* Note: dynamic elements make trafgen slower! */\n\n"
	"#define ETH_P_IP	0x0800\n\n"
	"#define SYN		(1 << 1)\n"
	"#define ECN		(1 << 6)\n\n"
	"{\n"
	"  /* MAC Destination */\n"
	"  fill(0xff, 6),\n"
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
	"  c16((0x8 << 12) | SYN | ECN)\n"
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

static void apply_counter(int counter_id)
{
	int j, i = counter_id;
	size_t counter_max = packet_dyn[i].clen;

	for (j = 0; j < counter_max; ++j) {
		uint8_t val;
		struct counter *counter = &packet_dyn[i].cnt[j];

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
		packets[i].payload[counter->off] = val;
	}
}

static void apply_randomizer(int rand_id)
{
	int j, i = rand_id;
	size_t rand_max = packet_dyn[i].rlen;

	for (j = 0; j < rand_max; ++j) {
		uint8_t val = (uint8_t) rand();
		struct randomizer *randomizer = &packet_dyn[i].rnd[j];

		packets[i].payload[randomizer->off] = val;
	}
}

/* Taken and modified from tcpdump, Copyright belongs to them! */

struct cksum_vec {
	const u8 *ptr;
	int len;
};

#define ADDCARRY(x)		\
	do { if ((x) > 65535)	\
		(x) -= 65535;	\
	} while (0)

#define REDUCE						\
	do {						\
		l_util.l = sum;				\
		sum = l_util.s[0] + l_util.s[1];	\
		ADDCARRY(sum);				\
	} while (0)

static u16 __in_cksum(const struct cksum_vec *vec, int veclen)
{
	register const u16 *w;
	register int sum = 0, mlen = 0;
	int byte_swapped = 0;
	union {
		u8 c[2];
		u16 s;
	} s_util;
	union {
		u16 s[2];
		u32 l;
	} l_util;

	for (; veclen != 0; vec++, veclen--) {
		if (vec->len == 0)
			continue;

		w = (const u16 *) (void *) vec->ptr;

		if (mlen == -1) {
			s_util.c[1] = *(const u8 *) w;
			sum += s_util.s;
			w = (const u16 *) (void *) ((const u8 *) w + 1);
			mlen = vec->len - 1;
		} else
			mlen = vec->len;

		if ((1 & (unsigned long) w) && (mlen > 0)) {
			REDUCE;
			sum <<= 8;
			s_util.c[0] = *(const u8 *) w;
			w = (const u16 *) (void *) ((const u8 *) w + 1);
			mlen--;
			byte_swapped = 1;
		}

		while ((mlen -= 32) >= 0) {
			sum +=  w[0]; sum +=  w[1]; sum +=  w[2]; sum +=  w[3];
			sum +=  w[4]; sum +=  w[5]; sum +=  w[6]; sum +=  w[7];
			sum +=  w[8]; sum +=  w[9]; sum += w[10]; sum += w[11];
			sum += w[12]; sum += w[13]; sum += w[14]; sum += w[15];
			w += 16;
		}

		mlen += 32;

		while ((mlen -= 8) >= 0) {
			sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3];
			w += 4;
		}

		mlen += 8;

		if (mlen == 0 && byte_swapped == 0)
			continue;

		REDUCE;

		while ((mlen -= 2) >= 0) {
			sum += *w++;
		}

		if (byte_swapped) {
			REDUCE;
			sum <<= 8;
			byte_swapped = 0;

			if (mlen == -1) {
				s_util.c[1] = *(const u8 *) w;
				sum += s_util.s;
				mlen = 0;
			} else
				mlen = -1;
		} else if (mlen == -1)
			s_util.c[0] = *(const u8 *) w;
	}

	if (mlen == -1) {
		s_util.c[1] = 0;
		sum += s_util.s;
	}

	REDUCE;

	return (~sum & 0xffff);
}

static u16 p4_csum(const struct ip *ip, const u8 *data, u16 len,
		   u8 next_proto)
{
	struct cksum_vec vec[2];
	struct pseudo_hdr {
		u32 src;
		u32 dst;
		u8 mbz;
		u8 proto;
		u16 len;
	} ph;

	memset(&ph, 0, sizeof(ph));
	ph.len = htons(len);
	ph.mbz = 0;
	ph.proto = next_proto;
	ph.src = ip->ip_src.s_addr;
	ph.dst = ip->ip_dst.s_addr;

	vec[0].ptr = (const u8 *) (void *) &ph;
	vec[0].len = sizeof(ph);

	vec[1].ptr = data;
	vec[1].len = len;

	return __in_cksum(vec, 2);
}

static void apply_csum16(int csum_id)
{
	int j, i = csum_id;
	size_t csum_max = packet_dyn[i].slen;

	for (j = 0; j < csum_max; ++j) {
		uint16_t sum = 0;
		struct csum16 *csum = &packet_dyn[i].csum[j];

		fmemset(&packets[i].payload[csum->off], 0, sizeof(sum));

		switch (csum->which) {
		case CSUM_IP:
			if (csum->to >= packets[i].len)
				csum->to = packets[i].len - 1;
			sum = calc_csum(packets[i].payload + csum->from,
					csum->to - csum->from + 1, 0);
			break;
		case CSUM_UDP:
			sum = p4_csum((void *) packets[i].payload + csum->from,
				      packets[i].payload + csum->to,
				      (packets[i].len - csum->to),
				      IPPROTO_UDP);
			break;
		case CSUM_TCP:
			sum = p4_csum((void *) packets[i].payload + csum->from,
				      packets[i].payload + csum->to,
				      (packets[i].len - csum->to),
				      IPPROTO_TCP);
			break;
		}

		fmemcpy(&packets[i].payload[csum->off], &sum, sizeof(sum));
	}
}

static struct cpu_stats *setup_shared_var(unsigned long cpus)
{
	int fd;
	char zbuff[cpus * sizeof(struct cpu_stats)], file[256];
	struct cpu_stats *buff;

	fmemset(zbuff, 0, sizeof(zbuff));
	slprintf(file, sizeof(file), ".tmp_mmap.%u", (unsigned int) rand());

	fd = creat(file, S_IRUSR | S_IWUSR);
	bug_on(fd < 0);
	close(fd);

	fd = open_or_die_m(file, O_RDWR | O_CREAT | O_TRUNC,
			   S_IRUSR | S_IWUSR);
	write_or_die(fd, zbuff, sizeof(zbuff));

	buff = (void *) mmap(0, sizeof(zbuff), PROT_READ | PROT_WRITE,
			     MAP_SHARED, fd, 0);
	if (buff == (void *) -1)
		panic("Cannot setup shared variable!\n");

	close(fd);
	unlink(file);

	memset(buff, 0, sizeof(zbuff));

	return buff;
}

static void destroy_shared_var(void *buff, unsigned long cpus)
{
	munmap(buff, cpus * sizeof(struct cpu_stats));
}

static void dump_trafgen_snippet(uint8_t *payload, size_t len)
{
	int i;

	printf("{");
	for (i = 0; i < len; ++i) {
		if (i % 15 == 0)
			printf("\n  ");
		printf("0x%02x, ", payload[i]);
	}
	printf("\n}\n");
	fflush(stdout);
}

static inline unsigned short csum(unsigned short *buf, int nwords)
{
	unsigned long sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);

	return ~sum;
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
	int ret, i, probes = 5;
	short ident, cnt = 1;
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

	while (probes-- > 0) {
		ident = htons((short) rand());

		memset(outpack, 0, sizeof(outpack));
		icmp = (void *) outpack;
		icmp->type = ICMP_ECHO;
		icmp->code = 0;
		icmp->checksum = 0;
		icmp->un.echo.id = ident;
		icmp->un.echo.sequence = htons(cnt++);

		data = ((uint8_t *) outpack + sizeof(*icmp));
		for (i = 0; i < 56; ++i)
			data[i] = (uint8_t) rand();

		icmp->checksum = csum((unsigned short *) outpack,
				      len / sizeof(unsigned short));

		ret = sendto(icmp_sock, outpack, len, MSG_DONTWAIT,
			     (struct sockaddr *) &ctx->dest, sizeof(ctx->dest));
		if (unlikely(ret != len))
			panic("Cannot send out probe: %s!\n", strerror(errno));

		ret = poll(&fds, 1, 500);
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
			if (unlikely(ret < sizeof(*ip) + sizeof(*icmp)))
				continue;
			ip = (void *) outpack;
			if (unlikely(ip->ihl * 4 + sizeof(*icmp) > ret))
				continue;
			icmp = (void *) outpack + ip->ihl * 4;
			if (unlikely(icmp->un.echo.id != ident))
				continue;

			return 0;
		}
	}

	return -1;
}

static void xmit_slowpath_or_die(struct ctx *ctx, int cpu)
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

	if (ctx->smoke_test)
		icmp_sock = xmit_smoke_setup(ctx);

	drop_privileges(ctx->enforce, ctx->uid, ctx->gid);

	bug_on(gettimeofday(&start, NULL));

	while (likely(sigint == 0) && likely(num > 0)) {
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

			panic("Sendto error: %s!\n", strerror(errno));
		}

		tx_bytes += packets[i].len;
		tx_packets++;

		if (ctx->smoke_test) {
			ret = xmit_smoke_probe(icmp_sock, ctx);
			if (unlikely(ret < 0)) {
				printf("%sSmoke test alert:%s\n", colorize_start(bold), colorize_end());
				printf("  Remote host seems to be unresponsive to ICMP pings!\n");
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

		if (ctx->gap > 0)
			usleep(ctx->gap);
	}

	bug_on(gettimeofday(&end, NULL));
	diff = tv_subtract(end, start);

	if (ctx->smoke_test)
		close(icmp_sock);

	stats[cpu].tx_packets = tx_packets;
	stats[cpu].tx_bytes = tx_bytes;
	stats[cpu].tv_sec = diff.tv_sec;
	stats[cpu].tv_usec = diff.tv_usec;

	stats[cpu].state |= CPU_STATS_STATE_RES;
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
	struct packet_dyn *pktd;
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

	drop_privileges(ctx->enforce, ctx->uid, ctx->gid);

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

	stats[cpu].state |= CPU_STATS_STATE_RES;
}

static inline void __set_state(int cpu, sig_atomic_t s)
{
	stats[cpu].state = s;
}

static inline sig_atomic_t __get_state(int cpu)
{
	return stats[cpu].state;
}

static unsigned long __wait_and_sum_others(struct ctx *ctx, int cpu)
{
	int i;
	unsigned long total;

	for (i = 0, total = plen; i < ctx->cpus; i++) {
		if (i == cpu)
			continue;

		while ((__get_state(i) & CPU_STATS_STATE_CFG) == 0 &&
		       sigint == 0)
			sched_yield();

		total += stats[i].cf_packets;
	}

	return total;
}

static void __correct_global_delta(struct ctx *ctx, int cpu, unsigned long orig)
{
	int i, cpu_sel;
	unsigned long total;
	long long delta_correction = 0;

	for (i = 0, total = ctx->num; i < ctx->cpus; i++) {
		if (i == cpu)
			continue;

		while ((__get_state(i) & CPU_STATS_STATE_CHK) == 0 &&
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
			    delta_correction > 0) {
				cpu_sel = i;
				break;
			}
		}
	}

	if (cpu == cpu_sel)
		ctx->num += delta_correction;
}

static void __set_state_cf(int cpu, unsigned long p, unsigned long b,
			   sig_atomic_t s)
{
	stats[cpu].cf_packets = p;
	stats[cpu].cf_bytes = b;
	stats[cpu].state = s;
}

static void __set_state_cd(int cpu, unsigned long p, sig_atomic_t s)
{
	stats[cpu].cd_packets = p;
	stats[cpu].state = s;
}

static int xmit_packet_precheck(struct ctx *ctx, int cpu)
{
	int i;
	unsigned long plen_total, orig = ctx->num;
	size_t mtu, total_len = 0;

	bug_on(plen != dlen);

	for (i = 0; i < plen; ++i)
		total_len += packets[i].len;

	__set_state_cf(cpu, plen, total_len, CPU_STATS_STATE_CFG);
	plen_total = __wait_and_sum_others(ctx, cpu);

	if (orig > 0) {
		ctx->num = (unsigned long) nearbyint((1.0 * plen / plen_total) * orig);

		__set_state_cd(cpu, ctx->num, CPU_STATS_STATE_CHK |
			       CPU_STATS_STATE_CFG);
		__correct_global_delta(ctx, cpu, orig);
	}

	if (plen == 0) {
		__set_state(cpu, CPU_STATS_STATE_RES);
		return -1;
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
		      int cpu, bool invoke_cpp)
{
	compile_packets(confname, ctx->verbose, cpu, invoke_cpp);
	if (xmit_packet_precheck(ctx, cpu) < 0)
		return;

	if (cpu == 0) {
		int i;
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

	if (slow)
		xmit_slowpath_or_die(ctx, cpu);
	else
		xmit_fastpath_or_die(ctx, cpu);

	close(sock);

	cleanup_packets();
}

static unsigned int generate_srand_seed(void)
{
	int fd;
	unsigned int seed;

	fd = open("/dev/random", O_RDONLY);
	if (fd < 0)
		return time(0);

	read_or_die(fd, &seed, sizeof(seed));

	close(fd);
	return seed;
}

int main(int argc, char **argv)
{
	bool slow = false, invoke_cpp = false;
	int c, opt_index, i, j, vals[4] = {0}, irq;
	char *confname = NULL, *ptr;
	unsigned long cpus_tmp;
	unsigned long long tx_packets, tx_bytes;
	struct ctx ctx;

	fmemset(&ctx, 0, sizeof(ctx));
	ctx.cpus = get_number_cpus_online();
	ctx.uid = getuid();
	ctx.gid = getgid();

	while ((c = getopt_long(argc, argv, short_options, long_options,
				&opt_index)) != EOF) {
		switch (c) {
		case 'h':
			help();
			break;
		case 'v':
			version();
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
			ctx.kpull = strtoul(optarg, NULL, 0);
			break;
		case 'E':
			seed = strtoul(optarg, NULL, 0);
			break;
		case 'n':
			ctx.num = strtoul(optarg, NULL, 0);
			break;
		case 't':
			slow = true;
			ctx.gap = strtoul(optarg, NULL, 0);
			if (ctx.gap > 0)
				/* Fall back to single core to not
				 * mess up correct timing. We are slow
				 * anyway!
				 */
				ctx.cpus = 1;
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

	set_system_socket_memory(vals);

	if (ctx.rfraw) {
		ctx.device_trans = xstrdup(ctx.device);
		xfree(ctx.device);

		enter_rfmon_mac80211(ctx.device_trans, &ctx.device);
		sleep(0);
	}

	irq = device_irq_number(ctx.device);
	device_set_irq_affinity_list(irq, 0, ctx.cpus - 1);

	if (ctx.num > 0 && ctx.num <= ctx.cpus)
		ctx.cpus = 1;

	stats = setup_shared_var(ctx.cpus);

	for (i = 0; i < ctx.cpus; i++) {
		pid_t pid = fork();

		switch (pid) {
		case 0:
			seed = generate_srand_seed();
			srand(seed);

			cpu_affinity(i);
			main_loop(&ctx, confname, slow, i, invoke_cpp);

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
		leave_rfmon_mac80211(ctx.device_trans, ctx.device);

	reset_system_socket_memory(vals);

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
	for (i = 0; i < ctx.cpus; i++) {
		printf("\r%12lu sec, %lu usec on CPU%d (%llu packets)\n",
		       stats[i].tv_sec, stats[i].tv_usec, i,
		       stats[i].tx_packets);
	}

thread_out:
	destroy_shared_var(stats, ctx.cpus);

	free(ctx.device);
	free(ctx.device_trans);
	free(ctx.rhost);
	free(confname);

	return 0;
}

/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2011 - 2013 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#define _BSD_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <ctype.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/fsuid.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <asm/byteorder.h>
#include <linux/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include "bpf.h"
#include "die.h"
#include "dev.h"
#include "sig.h"
#include "config.h"
#include "tprintf.h"
#include "pkt_buff.h"
#include "proto.h"
#include "xmalloc.h"
#include "ioops.h"
#include "csum.h"
#include "sock.h"
#include "geoip.h"
#include "ring_rx.h"
#include "built_in.h"

struct ctx {
	char *host, *port, *dev, *payload, *bind_addr;
	size_t totlen, rcvlen;
	int init_ttl, max_ttl, dns_resolv, queries, timeout;
	int syn, ack, ecn, fin, psh, rst, urg, tos, nofrag, proto, show;
	int sd_len, dport, latitude;
};

struct proto_ops {
	int (*assembler)(uint8_t *packet, size_t len, int ttl, int proto,
			 const struct ctx *ctx, const struct sockaddr *dst,
			 const struct sockaddr *src);
	const struct sock_filter *filter;
	unsigned int flen;
	size_t min_len_tcp, min_len_icmp;
	int (*check)(uint8_t *packet, size_t len, int ttl, int id,
		     const struct sockaddr *src);
	void (*handler)(uint8_t *packet, size_t len, int dns_resolv,
			int latitude);
};

static sig_atomic_t sigint = 0;

static int assemble_ipv4(uint8_t *packet, size_t len, int ttl, int proto,
			 const struct ctx *ctx, const struct sockaddr *dst,
			 const struct sockaddr *src);
static int assemble_ipv6(uint8_t *packet, size_t len, int ttl, int proto,
			 const struct ctx *ctx, const struct sockaddr *dst,
			 const struct sockaddr *src);
static int check_ipv4(uint8_t *packet, size_t len, int ttl, int id,
                      const struct sockaddr *ss);
static void handle_ipv4(uint8_t *packet, size_t len, int dns_resolv,
		        int latitude);
static int check_ipv6(uint8_t *packet, size_t len, int ttl, int id,
                      const struct sockaddr *ss);
static void handle_ipv6(uint8_t *packet, size_t len, int dns_resolv,
		        int latitude);

static const char *short_options = "H:p:nNf:m:b:i:d:q:x:SAEFPURt:Gl:hv46X:ZuL";
static const struct option long_options[] = {
	{"host",	required_argument,	NULL, 'H'},
	{"port",	required_argument,	NULL, 'p'},
	{"init-ttl",	required_argument,	NULL, 'f'},
	{"max-ttl",	required_argument,	NULL, 'm'},
	{"bind",	required_argument,	NULL, 'b'},
	{"dev",		required_argument,	NULL, 'd'},
	{"num-probes",	required_argument,	NULL, 'q'},
	{"timeout",	required_argument,	NULL, 'x'},
	{"tos",		required_argument,	NULL, 't'},
	{"payload",	required_argument,	NULL, 'X'},
	{"totlen",	required_argument,	NULL, 'l'},
	{"numeric",	no_argument,		NULL, 'n'},
	{"latitude",	no_argument,		NULL, 'L'},
	{"update",	no_argument,		NULL, 'u'},
	{"dns",		no_argument,		NULL, 'N'},
	{"ipv4",	no_argument,		NULL, '4'},
	{"ipv6",	no_argument,		NULL, '6'},
	{"syn",		no_argument,		NULL, 'S'},
	{"ack",		no_argument,		NULL, 'A'},
	{"urg",		no_argument,		NULL, 'U'},
	{"fin",		no_argument,		NULL, 'F'},
	{"psh",		no_argument,		NULL, 'P'},
	{"rst",		no_argument,		NULL, 'R'},
	{"ecn-syn",	no_argument,		NULL, 'E'},
	{"show-packet",	no_argument,		NULL, 'Z'},
	{"nofrag",	no_argument,		NULL, 'G'},
	{"version",	no_argument,		NULL, 'v'},
	{"help",	no_argument,		NULL, 'h'},
	{NULL, 0, NULL, 0}
};

static const struct sock_filter ipv4_icmp_type_11[] = {
	{ 0x28, 0, 0, 0x0000000c },	/* ldh [12]		*/
	{ 0x15, 0, 8, 0x00000800 },	/* jneq #0x800, drop	*/
	{ 0x30, 0, 0, 0x00000017 },	/* ldb [23]		*/
	{ 0x15, 0, 6, 0x00000001 },	/* jneq #0x1, drop	*/
	{ 0x28, 0, 0, 0x00000014 },	/* ldh [20]		*/
	{ 0x45, 4, 0, 0x00001fff },	/* jset #0x1fff, drop	*/
	{ 0xb1, 0, 0, 0x0000000e },	/* ldxb 4*([14]&0xf)	*/
	{ 0x50, 0, 0, 0x0000000e },	/* ldb [x + 14]		*/
	{ 0x15, 0, 1, 0x0000000b },	/* jneq #0xb, drop	*/
	{ 0x06, 0, 0, 0xffffffff },	/* ret #-1		*/
	{ 0x06, 0, 0, 0x00000000 },	/* drop: ret #0		*/
};

static const struct sock_filter ipv6_icmp6_type_3[] = {
	{ 0x28, 0, 0, 0x0000000c },	/* ldh [12]		*/
	{ 0x15, 0, 5, 0x000086dd },	/* jneq #0x86dd, drop	*/
	{ 0x30, 0, 0, 0x00000014 },	/* ldb [20]		*/
	{ 0x15, 0, 3, 0x0000003a },	/* jneq #0x3a, drop	*/
	{ 0x30, 0, 0, 0x00000036 },	/* ldb [54]		*/
	{ 0x15, 0, 1, 0x00000003 },	/* jneq #0x3, drop	*/
	{ 0x06, 0, 0, 0xffffffff },	/* ret #-1		*/
	{ 0x06, 0, 0, 0x00000000 },	/* drop: ret #0		*/
};

static const struct proto_ops af_ops[] = {
	[IPPROTO_IP]	=	{
			.assembler	=	assemble_ipv4,
			.handler	=	handle_ipv4,
			.check		=	check_ipv4,
			.filter		=	ipv4_icmp_type_11,
			.flen		=	array_size(ipv4_icmp_type_11),
			.min_len_tcp	=	sizeof(struct iphdr) + sizeof(struct tcphdr),
			.min_len_icmp	=	sizeof(struct iphdr) + sizeof(struct icmphdr),
		},
	[IPPROTO_IPV6]	= 	{
			.assembler	=	assemble_ipv6,
			.handler	=	handle_ipv6,
			.check		=	check_ipv6,
			.filter		=	ipv6_icmp6_type_3,
			.flen		=	array_size(ipv6_icmp6_type_3),
			.min_len_tcp	=	sizeof(struct ip6_hdr) + sizeof(struct tcphdr),
			.min_len_icmp	=	sizeof(struct ip6_hdr) + sizeof(struct icmp6hdr),
		},
};

static void signal_handler(int number)
{
	switch (number) {
	case SIGINT:
		sigint = 1;
	default:
		break;
	}
}

static void __noreturn help(void)
{
	printf("\nastraceroute %s, autonomous system trace route utility\n", VERSION_STRING);
	puts("http://www.netsniff-ng.org\n\n"
	     "Usage: astraceroute [options]\n"
	     "Options:\n"
	     " -H|--host <host>        Host/IPv4/IPv6 to lookup AS route to\n"
	     " -p|--port <port>        Hosts port to lookup AS route to\n"
	     " -i|-d|--dev <device>    Networking device, e.g. eth0\n"
	     " -b|--bind <IP>          IP address to bind to, Must specify -6 for an IPv6 address\n"
	     " -f|--init-ttl <ttl>     Set initial TTL\n"
	     " -m|--max-ttl <ttl>      Set maximum TTL (def: 30)\n"
	     " -q|--num-probes <num>   Number of max probes for each hop (def: 2)\n"
	     " -x|--timeout <sec>      Probe response timeout in sec (def: 3)\n"
	     " -X|--payload <string>   Specify a payload string to test DPIs\n"
	     " -l|--totlen <len>       Specify total packet len\n"
	     " -4|--ipv4               Use IPv4-only requests\n"
	     " -6|--ipv6               Use IPv6-only requests\n"
	     " -n|--numeric            Do not do reverse DNS lookup for hops\n"
	     " -u|--update             Update GeoIP databases\n"
	     " -L|--latitude           Show latitude and longtitude\n"
	     " -N|--dns                Do a reverse DNS lookup for hops\n"
	     " -S|--syn                Set TCP SYN flag\n"
	     " -A|--ack                Set TCP ACK flag\n"
	     " -F|--fin                Set TCP FIN flag\n"
	     " -P|--psh                Set TCP PSH flag\n"
	     " -U|--urg                Set TCP URG flag\n"
	     " -R|--rst                Set TCP RST flag\n"
	     " -E|--ecn-syn            Send ECN SYN packets (RFC3168)\n"
	     " -t|--tos <tos>          Set the IP TOS field\n"
	     " -G|--nofrag             Set do not fragment bit\n"
	     " -Z|--show-packet        Show returned packet on each hop\n"
	     " -v|--version            Print version and exit\n"
	     " -h|--help               Print this help and exit\n\n"
	     "Examples:\n"
	     "  IPv4 trace of AS with TCP SYN probe (this will most-likely pass):\n"
	     "    astraceroute -i eth0 -N -S -H netsniff-ng.org\n"
	     "  IPv4 trace of AS with TCP ECN SYN probe:\n"
	     "    astraceroute -i eth0 -N -E -H netsniff-ng.org\n"
	     "  IPv4 trace of AS with TCP FIN probe:\n"
	     "    astraceroute -i eth0 -N -F -H netsniff-ng.org\n"
	     "  IPv4 trace of AS with Xmas probe:\n"
	     "    astraceroute -i eth0 -N -FPU -H netsniff-ng.org\n"
	     "  IPv4 trace of AS with Null probe with ASCII payload:\n"
	     "    astraceroute -i eth0 -N -H netsniff-ng.org -X \"censor-me\" -Z\n"
	     "  IPv6 trace of AS up to www.6bone.net:\n"
	     "    astraceroute -6 -i eth0 -S -E -N -H www.6bone.net\n\n"
	     "Note:\n"
	     "  If the TCP probe did not give any results, then astraceroute will\n"
	     "  automatically probe for classic ICMP packets! To gather more\n"
	     "  information about astraceroute's fetched AS numbers, see e.g.\n"
	     "  http://bgp.he.net/AS<number>!\n\n"
	     "Please report bugs to <bugs@netsniff-ng.org>\n"
	     "Copyright (C) 2011-2013 Daniel Borkmann <dborkma@tik.ee.ethz.ch>\n"
	     "Swiss federal institute of technology (ETH Zurich)\n"
	     "License: GNU GPL version 2.0\n"
	     "This is free software: you are free to change and redistribute it.\n"
	     "There is NO WARRANTY, to the extent permitted by law.\n");
	die();
}

static void __noreturn version(void)
{
	printf("\nastraceroute %s, Git id: %s\n", VERSION_LONG, GITVERSION);
	puts("autonomous system trace route utility\n"
	     "http://www.netsniff-ng.org\n\n"
	     "Please report bugs to <bugs@netsniff-ng.org>\n"
	     "Copyright (C) 2011-2013 Daniel Borkmann <dborkma@tik.ee.ethz.ch>\n"
	     "Swiss federal institute of technology (ETH Zurich)\n"
	     "License: GNU GPL version 2.0\n"
	     "This is free software: you are free to change and redistribute it.\n"
	     "There is NO WARRANTY, to the extent permitted by law.\n");
	die();
}

static void __assemble_data(uint8_t *packet, size_t len, const char *payload)
{
	size_t i;

	if (payload == NULL) {
		for (i = 0; i < len; ++i)
			packet[i] = (uint8_t) rand();
	} else {
		size_t lmin = min(len, strlen(payload));

		for (i = 0; i < lmin; ++i)
			packet[i] = (uint8_t) payload[i];
		for (i = lmin; i < len; ++i)
			packet[i] = (uint8_t) rand();
	}
}

static void __assemble_icmp4(uint8_t *packet, size_t len)
{
	struct icmphdr *icmph = (struct icmphdr *) packet;

	bug_on(len < sizeof(struct icmphdr));

	icmph->type = ICMP_ECHO;
	icmph->code = 0;
	icmph->checksum = 0;
}

static void __assemble_icmp6(uint8_t *packet, size_t len)
{
	struct icmp6hdr *icmp6h = (struct icmp6hdr *) packet;

	bug_on(len < sizeof(struct icmp6hdr));

	icmp6h->icmp6_type = ICMPV6_ECHO_REQUEST;
	icmp6h->icmp6_code = 0;
	icmp6h->icmp6_cksum = 0;
}

static void __assemble_tcp(uint8_t *packet, size_t len, int syn, int ack,
			   int urg, int fin, int rst, int psh, int ecn,
			   int dport)
{
	struct tcphdr *tcph = (struct tcphdr *) packet;

	bug_on(len < sizeof(struct tcphdr));

	tcph->source = htons((uint16_t) rand());
	tcph->dest = htons((uint16_t) dport);

	tcph->seq = htonl(rand());
	tcph->ack_seq = (!!ack ? htonl(rand()) : 0);

	tcph->doff = 5;

	tcph->syn = !!syn;
	tcph->ack = !!ack;
	tcph->urg = !!urg;
	tcph->fin = !!fin;
	tcph->rst = !!rst;
	tcph->psh = !!psh;
	tcph->ece = !!ecn;
	tcph->cwr = !!ecn;

	tcph->window = htons((uint16_t) (100 + (rand() % 65435)));
	tcph->urg_ptr = (!!urg ? htons((uint16_t) rand()) :  0);
	tcph->check = 0;
}

static int assemble_ipv4(uint8_t *packet, size_t len, int ttl, int proto,
			 const struct ctx *ctx, const struct sockaddr *dst,
			 const struct sockaddr *src)
{
	uint8_t *data;
	size_t data_len, off_next = 0;
	struct iphdr *iph = (struct iphdr *) packet;

	bug_on(!src || !dst);
	bug_on(src->sa_family != PF_INET || dst->sa_family != PF_INET);
	bug_on(len < sizeof(*iph) + min(sizeof(struct tcphdr),
					sizeof(struct icmphdr)));

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = (uint8_t) ctx->tos;

	iph->tot_len = htons((uint16_t) len);
	iph->id = htons((uint16_t) rand());

	iph->frag_off = ctx->nofrag ? IP_DF : 0;
	iph->ttl = (uint8_t) ttl;

	iph->saddr = ((const struct sockaddr_in *) src)->sin_addr.s_addr;
	iph->daddr = ((const struct sockaddr_in *) dst)->sin_addr.s_addr;

	iph->protocol = (uint8_t) proto;

	data = packet + sizeof(*iph);
	data_len = len - sizeof(*iph);

	switch (proto) {
	case IPPROTO_TCP:
		__assemble_tcp(data, data_len, ctx->syn, ctx->ack, ctx->urg,
			       ctx->fin, ctx->rst, ctx->psh, ctx->ecn, ctx->dport);
		off_next = sizeof(struct tcphdr);
		break;
	case IPPROTO_ICMP:
		__assemble_icmp4(data, data_len);
		off_next = sizeof(struct icmphdr);
		break;
	default:
		bug();
	}

	data = packet + sizeof(*iph) + off_next;
	data_len = len - sizeof(*iph) - off_next;

	__assemble_data(data, data_len, ctx->payload);

	iph->check = csum((unsigned short *) packet, ntohs(iph->tot_len) >> 1);

	return ntohs(iph->id);
}

static int assemble_ipv6(uint8_t *packet, size_t len, int ttl, int proto,
			 const struct ctx *ctx, const struct sockaddr *dst,
			 const struct sockaddr *src)
{
	uint8_t *data;
	size_t data_len, off_next = 0;
	struct ip6_hdr *ip6h = (struct ip6_hdr *) packet;

	bug_on(!src || !dst);
	bug_on(src->sa_family != PF_INET6 || dst->sa_family != PF_INET6);
	bug_on(len < sizeof(*ip6h) + min(sizeof(struct tcphdr),
					 sizeof(struct icmp6hdr)));

	ip6h->ip6_flow = htonl(rand() & 0x000fffff);
	ip6h->ip6_vfc = 0x60;

	ip6h->ip6_plen = htons((uint16_t) len - sizeof(*ip6h));
	ip6h->ip6_nxt = (uint8_t) proto;
	ip6h->ip6_hlim = (uint8_t) ttl;

	memcpy(&ip6h->ip6_src, &(((const struct sockaddr_in6 *)
	       src)->sin6_addr), sizeof(ip6h->ip6_src));
	memcpy(&ip6h->ip6_dst, &(((const struct sockaddr_in6 *)
	       dst)->sin6_addr), sizeof(ip6h->ip6_dst));

	data = packet + sizeof(*ip6h);
	data_len = len - sizeof(*ip6h);

	switch (proto) {
	case IPPROTO_TCP:
		__assemble_tcp(data, data_len, ctx->syn, ctx->ack, ctx->urg,
			       ctx->fin, ctx->rst, ctx->psh, ctx->ecn, ctx->dport);
		off_next = sizeof(struct tcphdr);
		break;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		__assemble_icmp6(data, data_len);
		off_next = sizeof(struct icmp6hdr);
		break;
	default:
		bug();
	}

	data = packet + sizeof(*ip6h) + off_next;
	data_len = len - sizeof(*ip6h) - off_next;

	__assemble_data(data, data_len, ctx->payload);

	return ntohl(ip6h->ip6_flow) & 0x000fffff;
}

static int check_ipv4(uint8_t *packet, size_t len, int ttl __maybe_unused,
		      int id, const struct sockaddr *ss)
{
	struct iphdr *iph = (struct iphdr *) packet;
	struct iphdr *iph_inner;
	struct icmphdr *icmph;

	if (iph->protocol != IPPROTO_ICMP)
		return -EINVAL;
	if (iph->daddr != ((const struct sockaddr_in *) ss)->sin_addr.s_addr)
		return -EINVAL;

	icmph = (struct icmphdr *) (packet + sizeof(struct iphdr));
	if (icmph->type != ICMP_TIME_EXCEEDED)
		return -EINVAL;
	if (icmph->code != ICMP_EXC_TTL)
		return -EINVAL;

	iph_inner = (struct iphdr *) (packet + sizeof(struct iphdr) +
				      sizeof(struct icmphdr));
	if (ntohs(iph_inner->id) != id)
		return -EINVAL;

	return len;
}

static void handle_ipv4(uint8_t *packet, size_t len __maybe_unused,
			int dns_resolv, int latitude)
{
	char hbuff[NI_MAXHOST];
	struct iphdr *iph = (struct iphdr *) packet;
	struct sockaddr_in sd;
	struct hostent *hent;
	const char *as, *country, *city;

	memset(hbuff, 0, sizeof(hbuff));
	memset(&sd, 0, sizeof(sd));
	sd.sin_family = PF_INET;
	sd.sin_addr.s_addr = iph->saddr;

	getnameinfo((struct sockaddr *) &sd, sizeof(sd),
		    hbuff, sizeof(hbuff), NULL, 0, NI_NUMERICHOST);

	as = geoip4_as_name(sd);
	country = geoip4_country_name(sd);
	city = geoip4_city_name(sd);

	if (dns_resolv) {
		hent = gethostbyaddr(&sd.sin_addr, sizeof(sd.sin_addr), PF_INET);
		if (hent)
			printf(" %s (%s)", hent->h_name, hbuff);
		else
			printf(" %s", hbuff);
	} else {
		printf(" %s", hbuff);
	}
	if (as)
		printf(" in %s", as);
	if (country) {
		printf(" in %s", country);
		if (city)
			printf(", %s", city);
	}
	if (latitude)
		printf(" (%f/%f)", geoip4_latitude(sd), geoip4_longitude(sd));
}

static int check_ipv6(uint8_t *packet, size_t len, int ttl __maybe_unused,
		      int id, const struct sockaddr *ss)
{
	struct ip6_hdr *ip6h = (struct ip6_hdr *) packet;
	struct ip6_hdr *ip6h_inner;
	struct icmp6hdr *icmp6h;

	if (ip6h->ip6_nxt != 0x3a)
		return -EINVAL;
	if (memcmp(&ip6h->ip6_dst, &(((const struct sockaddr_in6 *)
		   ss)->sin6_addr), sizeof(ip6h->ip6_dst)))
		return -EINVAL;

	icmp6h = (struct icmp6hdr *) (packet + sizeof(*ip6h));
	if (icmp6h->icmp6_type != ICMPV6_TIME_EXCEED)
		return -EINVAL;
	if (icmp6h->icmp6_code != ICMPV6_EXC_HOPLIMIT)
		return -EINVAL;

	ip6h_inner = (struct ip6_hdr *) (packet + sizeof(*ip6h) + sizeof(*icmp6h));
	if ((ntohl(ip6h_inner->ip6_flow) & 0x000fffff) != (uint32_t) id)
		return -EINVAL;

	return len;
}

static void handle_ipv6(uint8_t *packet, size_t len __maybe_unused,
			int dns_resolv, int latitude)
{
	char hbuff[NI_MAXHOST];
	struct ip6_hdr *ip6h = (struct ip6_hdr *) packet;
	struct sockaddr_in6 sd;
	struct hostent *hent;
	const char *as, *country, *city;

	memset(hbuff, 0, sizeof(hbuff));
	memset(&sd, 0, sizeof(sd));
	sd.sin6_family = PF_INET6;
	memcpy(&sd.sin6_addr, &ip6h->ip6_src, sizeof(ip6h->ip6_src));

	getnameinfo((struct sockaddr *) &sd, sizeof(sd),
		    hbuff, sizeof(hbuff), NULL, 0, NI_NUMERICHOST);

	as = geoip6_as_name(sd);
	country = geoip6_country_name(sd);
	city = geoip6_city_name(sd);

	if (dns_resolv) {
		hent = gethostbyaddr(&sd.sin6_addr, sizeof(sd.sin6_addr), PF_INET6);
		if (hent)
			printf(" %s (%s)", hent->h_name, hbuff);
		else
			printf(" %s", hbuff);
	} else {
		printf(" %s", hbuff);
	}
	if (as)
		printf(" in %s", as);
	if (country) {
		printf(" in %s", country);
		if (city)
			printf(", %s", city);
	}
	if (latitude)
		printf(" (%f/%f)", geoip6_latitude(sd), geoip6_longitude(sd));
}

static void show_trace_info(struct ctx *ctx, const struct sockaddr_storage *ss,
			    const struct sockaddr_storage *sd)
{
	char hbuffs[256], hbuffd[256];

	memset(hbuffd, 0, sizeof(hbuffd));
	getnameinfo((struct sockaddr *) sd, sizeof(*sd),
		    hbuffd, sizeof(hbuffd), NULL, 0, NI_NUMERICHOST);

	memset(hbuffs, 0, sizeof(hbuffs));
	getnameinfo((struct sockaddr *) ss, sizeof(*ss),
		    hbuffs, sizeof(hbuffs), NULL, 0, NI_NUMERICHOST);

	printf("AS path IPv%d TCP trace from %s to %s:%s (%s) with len %zu "
	       "Bytes, %u max hops\n", ctx->proto == IPPROTO_IP ? 4 : 6,
	       hbuffs, hbuffd, ctx->port, ctx->host, ctx->totlen, ctx->max_ttl);

	printf("Using flags SYN:%d,ACK:%d,ECN:%d,FIN:%d,PSH:%d,RST:%d,URG:%d\n",
	       ctx->syn, ctx->ack, ctx->ecn, ctx->fin, ctx->psh, ctx->rst, ctx->urg);

	if (ctx->payload)
		printf("With payload: \'%s\'\n", ctx->payload);
}

static int get_remote_fd(struct ctx *ctx, struct sockaddr_storage *ss,
			 struct sockaddr_storage *sd)
{
	int fd = -1, ret, one = 1, af = AF_INET;
	struct addrinfo hints, *ahead, *ai;
	unsigned char bind_ip[sizeof(struct in6_addr)];

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_NUMERICSERV;

	ret = getaddrinfo(ctx->host, ctx->port, &hints, &ahead);
	if (ret < 0)
		panic("Cannot get address info!\n");

	for (ai = ahead; ai != NULL && fd < 0; ai = ai->ai_next) {
		if (!((ai->ai_family == PF_INET6 && ctx->proto == IPPROTO_IPV6) ||
		      (ai->ai_family == PF_INET  && ctx->proto == IPPROTO_IP)))
			continue;

		fd = socket(ai->ai_family, SOCK_RAW, IPPROTO_RAW);
		if (fd < 0)
			continue;

		memset(ss, 0, sizeof(*ss));
		ret = device_address(ctx->dev, ai->ai_family, ss);
		if (ret < 0 && !ctx->bind_addr)
			panic("Cannot get own device address!\n");

		if (ctx->bind_addr) {
			if (ctx->proto == IPPROTO_IPV6)
				af = AF_INET6;

			if (inet_pton(af, ctx->bind_addr, &bind_ip) != 1)
				panic("Address is invalid!\n");

			if (af == AF_INET6) {
				struct sockaddr_in6 *ss6 = (struct sockaddr_in6 *) ss;
				memcpy(&ss6->sin6_addr.s6_addr, &bind_ip, sizeof(struct in6_addr));
			} else {
				struct sockaddr_in *ss4 = (struct sockaddr_in *) ss;
				memcpy(&ss4->sin_addr.s_addr, &bind_ip, sizeof(struct in_addr));
			}
		}

		ret = bind(fd, (struct sockaddr *) ss, sizeof(*ss));
		if (ret < 0)
			panic("Cannot bind socket!\n");

		memset(sd, 0, sizeof(*sd));
		memcpy(sd, ai->ai_addr, ai->ai_addrlen);

		ctx->sd_len = ai->ai_addrlen;
		ctx->dport = strtoul(ctx->port, NULL, 10);

		ret = setsockopt(fd, ctx->proto, IP_HDRINCL, &one, sizeof(one));
		if (ret < 0)
			panic("Kernel does not support IP_HDRINCL!\n");

		if (ai->ai_family == PF_INET6) {
			struct sockaddr_in6 *sd6 = (struct sockaddr_in6 *) sd;

			sd6->sin6_port = 0;
		}

		break;
	}

	freeaddrinfo(ahead);

	if (fd < 0)
		panic("Cannot create socket! Does remote "
		      "support IPv%d?!\n",
		      ctx->proto == IPPROTO_IP ? 4 : 6);

	return fd;
}

static void inject_filter(struct ctx *ctx, int fd)
{
	struct sock_fprog bpf_ops;

	enable_kernel_bpf_jit_compiler();

	memset(&bpf_ops, 0, sizeof(bpf_ops));
	bpf_ops.filter = (struct sock_filter *) af_ops[ctx->proto].filter;
	bpf_ops.len = af_ops[ctx->proto].flen;

	bpf_attach_to_sock(fd, &bpf_ops);
}

static int __process_node(struct ctx *ctx, int fd, int fd_cap, int ttl,
			  int inner_proto, uint8_t *pkt_snd, uint8_t *pkt_rcv,
			  const struct sockaddr_storage *ss,
			  const struct sockaddr_storage *sd, struct timeval *diff)
{
	int pkt_id, ret, timeout;
	struct pollfd pfd;
	struct timeval start, end;

	prepare_polling(fd_cap, &pfd);

	memset(pkt_snd, 0, ctx->totlen);
	pkt_id = af_ops[ctx->proto].assembler(pkt_snd, ctx->totlen, ttl,
					      inner_proto, ctx,
					      (const struct sockaddr *) sd,
					      (const struct sockaddr *) ss);

	ret = sendto(fd, pkt_snd, ctx->totlen, 0, (struct sockaddr *) sd,
		     ctx->sd_len);
	if (ret < 0)
		panic("sendto failed: %s\n", strerror(errno));

	bug_on(gettimeofday(&start, NULL));

	timeout = (ctx->timeout > 0 ? ctx->timeout : 2) * 1000;

	ret = poll(&pfd, 1, timeout);
	if (ret > 0 && pfd.revents & POLLIN && sigint == 0) {
		bug_on(gettimeofday(&end, NULL));
		if (diff)
			timersub(&end, &start, diff);

		ret = recvfrom(fd_cap, pkt_rcv, ctx->rcvlen, 0, NULL, NULL);
		if (ret < (int) (sizeof(struct ethhdr) + af_ops[ctx->proto].min_len_icmp))
			return -EIO;

		return af_ops[ctx->proto].check(pkt_rcv + sizeof(struct ethhdr),
						ret - sizeof(struct ethhdr), ttl,
						pkt_id, (const struct sockaddr *) ss);
	} else {
		return -EIO;
	}

	return 0;
}

static void timerdiv(const unsigned long divisor, const struct timeval *tv,
		     struct timeval *result)
{
	uint64_t x = ((uint64_t) tv->tv_sec * 1000 * 1000 + tv->tv_usec) / divisor;

	result->tv_sec = x / 1000 / 1000;
	result->tv_usec = x % (1000 * 1000);
}

static int timevalcmp(const void *t1, const void *t2)
{
	if (timercmp((struct timeval *) t1, (struct timeval *) t2, <))
		return -1;
	if (timercmp((struct timeval *) t1, (struct timeval *) t2, >))
		return  1;

	return 0;
}

static int __process_time(struct ctx *ctx, int fd, int fd_cap, int ttl,
			  int inner_proto, uint8_t *pkt_snd, uint8_t *pkt_rcv,
			  const struct sockaddr_storage *ss,
			  const struct sockaddr_storage *sd)
{
	size_t i, j = 0;
	int good = 0, ret = -EIO, idx, ret_good = -EIO;
	struct timeval probes[9], *tmp, sum, res;
	uint8_t *trash = xmalloc(ctx->rcvlen);
	char *cwait[] = { "-", "\\", "|", "/" };
	const char *proto_short[] = {
		[IPPROTO_TCP]		=	"t",
		[IPPROTO_ICMP]		=	"i",
		[IPPROTO_ICMPV6]	=	"i",
	};

	memset(probes, 0, sizeof(probes));
	for (i = 0; i < array_size(probes) && sigint == 0; ++i) {
		ret = __process_node(ctx, fd, fd_cap, ttl, inner_proto,
				     pkt_snd, good == 0 ? pkt_rcv : trash,
				     ss, sd, &probes[i]);
		if (ret > 0) {
			if (good == 0)
				ret_good = ret;
			good++;
		}

		if (good == 0 && ctx->queries == (int) i)
			break;

		usleep(50000);

		printf("\r%2d: %s", ttl, cwait[j++]);
		fflush(stdout);
		if (j >= array_size(cwait))
			j = 0;
	}

	if (good == 0) {
		xfree(trash);
		return -EIO;
	}

	tmp = xmalloc(sizeof(struct timeval) * good);
	for (i = j = 0; i < array_size(probes); ++i) {
		if (probes[i].tv_sec == 0 && probes[i].tv_usec == 0)
			continue;
		tmp[j].tv_sec = probes[i].tv_sec;
		tmp[j].tv_usec = probes[i].tv_usec;
		j++;
	}

	qsort(tmp, j, sizeof(struct timeval), timevalcmp);

	printf("\r%2d: %s[", ttl, proto_short[inner_proto]);
	idx = j / 2;
	switch (j % 2) {
	case 0:
		timeradd(&tmp[idx], &tmp[idx - 1], &sum);
		timerdiv(2, &sum, &res);
		if (res.tv_sec > 0)
			printf("%lu sec ", res.tv_sec);
		printf("%7lu us", res.tv_usec);
		break;
	case 1:
		if (tmp[idx].tv_sec > 0)
			printf("%lu sec ", tmp[idx].tv_sec);
		printf("%7lu us", tmp[idx].tv_usec);
		break;
	}
	printf("]");

	xfree(tmp);
	xfree(trash);

	return ret_good;
}

static int __probe_remote(struct ctx *ctx, int fd, int fd_cap, int ttl,
			  uint8_t *pkt_snd, uint8_t *pkt_rcv,
			  const struct sockaddr_storage *ss,
			  const struct sockaddr_storage *sd,
			  int inner_proto)
{
	int ret = -EIO, tries = ctx->queries;

	while (tries-- > 0 && sigint == 0) {
		ret = __process_time(ctx, fd, fd_cap, ttl, inner_proto,
				     pkt_snd, pkt_rcv, ss, sd);
		if (ret < 0)
			continue;

		af_ops[ctx->proto].handler(pkt_rcv + sizeof(struct ethhdr),
					   ret - sizeof(struct ethhdr),
					   ctx->dns_resolv, ctx->latitude);
		if (ctx->show) {
			struct pkt_buff *pkt;

			printf("\n");
			pkt = pkt_alloc(pkt_rcv, ret);
			hex_ascii(pkt);
			tprintf_flush();
			pkt_free(pkt);
		}

		break;
	}

	return ret;
}

static int __process_ttl(struct ctx *ctx, int fd, int fd_cap, int ttl,
			 uint8_t *pkt_snd, uint8_t *pkt_rcv,
			 const struct sockaddr_storage *ss,
			 const struct sockaddr_storage *sd)
{
	int ret = -EIO;
	size_t i;
	const int inner_protos[] = {
		IPPROTO_TCP,
		IPPROTO_ICMP,
	};

	printf("%2d: ", ttl);
	fflush(stdout);

	for (i = 0; i < array_size(inner_protos) && sigint == 0; ++i) {
		ret = __probe_remote(ctx, fd, fd_cap, ttl, pkt_snd, pkt_rcv, ss, sd,
				     inner_protos[i]);
		if (ret > 0)
			break;
	}

	if (ret <= 0)
		printf("\r%2d: ?[ no answer]", ttl);
	if (ctx->show == 0)
		printf("\n");
	if (ctx->show && ret <= 0)
		printf("\n\n");

	fflush(stdout);
	return 0;
}

static int main_trace(struct ctx *ctx)
{
	int fd, fd_cap, ifindex, ttl;
	struct ring dummy_ring;
	struct sockaddr_storage ss, sd;
	uint8_t *pkt_snd, *pkt_rcv;

	fd = get_remote_fd(ctx, &ss, &sd);
	fd_cap = pf_socket();

	inject_filter(ctx, fd_cap);

	ifindex = device_ifindex(ctx->dev);
	bind_rx_ring(fd_cap, &dummy_ring, ifindex);

	if (ctx->totlen < af_ops[ctx->proto].min_len_tcp) {
		ctx->totlen = af_ops[ctx->proto].min_len_tcp;
		if (ctx->payload)
			ctx->totlen += strlen(ctx->payload);
	}

	ctx->rcvlen = device_mtu(ctx->dev) - sizeof(struct ethhdr);
	if (ctx->totlen >= ctx->rcvlen)
		panic("Packet len exceeds device MTU!\n");

	pkt_snd = xmalloc(ctx->totlen);
	pkt_rcv = xmalloc(ctx->rcvlen);

	show_trace_info(ctx, &ss, &sd);

	for (ttl = ctx->init_ttl; ttl <= ctx->max_ttl && sigint == 0; ++ttl)
		__process_ttl(ctx, fd, fd_cap, ttl, pkt_snd, pkt_rcv,
			      &ss, &sd);

	xfree(pkt_snd);
	xfree(pkt_rcv);

	close(fd_cap);
	close(fd);

	return 0;
}

int main(int argc, char **argv)
{
	int c, opt_index, ret;
	struct ctx ctx;

	setfsuid(getuid());
	setfsgid(getgid());

	srand(time(NULL));

	memset(&ctx, 0, sizeof(ctx));
	ctx.init_ttl = 1;
	ctx.max_ttl = 30;
	ctx.queries = 2;
	ctx.timeout = 2;
	ctx.proto = IPPROTO_IP;
	ctx.payload = NULL;
	ctx.dev = xstrdup("eth0");
	ctx.port = xstrdup("80");
	ctx.bind_addr = NULL;

	while ((c = getopt_long(argc, argv, short_options, long_options,
		&opt_index)) != EOF) {
		switch (c) {
		case 'h':
			help();
			break;
		case 'v':
			version();
			break;
		case 'u':
			update_geoip();
			die();
			break;
		case 'H':
			ctx.host = xstrdup(optarg);
			break;
		case 'p':
			if (ctx.port)
				xfree(ctx.port);
			ctx.port = xstrdup(optarg);
			break;
		case 'n':
			ctx.dns_resolv = 0;
			break;
		case '4':
			ctx.proto = IPPROTO_IP;
			break;
		case '6':
			ctx.proto = IPPROTO_IPV6;
			break;
		case 'Z':
			ctx.show = 1;
			break;
		case 'N':
			ctx.dns_resolv = 1;
			break;
		case 'f':
			ctx.init_ttl = atoi(optarg);
			if (ctx.init_ttl <= 0)
				help();
			break;
		case 'm':
			ctx.max_ttl = atoi(optarg);
			if (ctx.max_ttl <= 0)
				help();
			break;
		case 'b':
			ctx.bind_addr = xstrdup(optarg);
			break;
		case 'i':
		case 'd':
			free(ctx.dev);
			ctx.dev = xstrdup(optarg);
			break;
		case 'q':
			ctx.queries = atoi(optarg);
			if (ctx.queries <= 0)
				help();
			break;
		case 'x':
			ctx.timeout = atoi(optarg);
			if (ctx.timeout <= 0)
				help();
			break;
		case 'L':
			ctx.latitude = 1;
			break;
		case 'S':
			ctx.syn = 1;
			break;
		case 'A':
			ctx.ack = 1;
			break;
		case 'F':
			ctx.fin = 1;
			break;
		case 'U':
			ctx.urg = 1;
			break;
		case 'P':
			ctx.psh = 1;
			break;
		case 'R':
			ctx.rst = 1;
			break;
		case 'E':
			ctx.syn = 1;
			ctx.ecn = 1;
			break;
		case 't':
			ctx.tos = atoi(optarg);
			if (ctx.tos < 0)
				help();
			break;
		case 'G':
			ctx.nofrag = 1;
			break;
		case 'X':
			ctx.payload = xstrdup(optarg);
			break;
		case 'l':
			ctx.totlen = strtoul(optarg, NULL, 10);
			if (ctx.totlen == 0)
				help();
			break;
		case '?':
			switch (optopt) {
			case 'H':
			case 'p':
			case 'f':
			case 'm':
			case 'i':
			case 'd':
			case 'q':
			case 'x':
			case 'X':
			case 't':
			case 'l':
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

	if (argc < 3 || !ctx.host || !ctx.port || ctx.init_ttl > ctx.max_ttl ||
	    ctx.init_ttl > MAXTTL || ctx.max_ttl > MAXTTL)
		help();

	if (!device_up_and_running(ctx.dev))
		panic("Networking device not up and running!\n");
	if (device_mtu(ctx.dev) <= ctx.totlen)
		panic("Packet larger than device MTU!\n");

	register_signal(SIGHUP, signal_handler);
	register_signal(SIGINT, signal_handler);

	tprintf_init();
	init_geoip(1);

	ret = main_trace(&ctx);

	destroy_geoip();
	tprintf_cleanup();

	free(ctx.dev);
	free(ctx.host);
	free(ctx.port);
	free(ctx.bind_addr);
	free(ctx.payload);

	return ret;
}

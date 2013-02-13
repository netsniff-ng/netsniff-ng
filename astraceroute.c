/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL, version 2.
 *
 * An Autonomous System trace route utility based on TCP instead of ICMP for
 * a better passing of firewalls. Supports IPv4 and IPv6. Based on the idea
 * of tcptraceroute (http://michael.toren.net/code/tcptraceroute/), but hacked
 * for Autonomous Systems tracing, thus you will know an approximate path of
 * your curvetun tunneled packets, for instance. However, astraceroute was
 * written from scratch and does not use any libraries. Special thanks to
 * Team CYMRU!
 *
 *   The road must be trod, but it will be very hard. And neither strength nor
 *   wisdom will carry us far upon it. This quest may be attempted by the weak
 *   with as much hope as the strong. Yet such is oft the course of deeds that
 *   move the wheels of the world: small hands do them because they must,
 *   while the eyes of the great are elsewhere.
 *
 *     -- The Lord of the Rings, Elrond, Chapter 'The Council of Elrond'.
 */

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
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <GeoIP.h>
#include <GeoIPCity.h>

#include "bpf.h"
#include "die.h"
#include "tprintf.h"
#include "pkt_buff.h"
#include "proto.h"
#include "xmalloc.h"
#include "xio.h"
#include "aslookup.h"
#include "xutils.h"
#include "ring_rx.h"
#include "built_in.h"

#define WHOIS_SERVER_SOURCE "/etc/netsniff-ng/whois.conf"

struct ash_cfg {
	char *host;
	char *port;
	int init_ttl;
	int max_ttl;
	int dns_resolv;
	char *dev;
	int queries;
	int timeout;
	int syn, ack, ecn, fin, psh, rst, urg;
	int tos, nofrag;
	int totlen;
	char *whois;
	char *whois_port;
	int ip;
	char *payload;
};

volatile sig_atomic_t sigint = 0;

static int show_pkt = 0;

static GeoIP *gi_country = NULL;
static GeoIP *gi_city = NULL;

static const char *short_options = "H:p:nNf:m:i:d:q:x:SAEFPURt:Gl:w:W:hv46X:ZLK";
static const struct option long_options[] = {
	{"host",	required_argument,	NULL, 'H'},
	{"port",	required_argument,	NULL, 'p'},
	{"init-ttl",	required_argument,	NULL, 'f'},
	{"max-ttl",	required_argument,	NULL, 'm'},
	{"dev",		required_argument,	NULL, 'd'},
	{"num-probes",	required_argument,	NULL, 'q'},
	{"timeout",	required_argument,	NULL, 'x'},
	{"tos",		required_argument,	NULL, 't'},
	{"payload",	required_argument,	NULL, 'X'},
	{"totlen",	required_argument,	NULL, 'l'},
	{"whois",	required_argument,	NULL, 'w'},
	{"wport",	required_argument,	NULL, 'W'},
	{"city-db",	required_argument,	NULL, 'L'},
	{"country-db",	required_argument,	NULL, 'K'},
	{"numeric",	no_argument,		NULL, 'n'},
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

static struct sock_filter ipv4_icmp_type_11[] = {
	/* (000) ldh  [12] */
	{ 0x28, 0, 0, 0x0000000c },
	/* (001) jeq  #0x800 jt 2 jf 10 */
	{ 0x15, 0, 8, 0x00000800 },
	/* (002) ldb  [23] */
	{ 0x30, 0, 0, 0x00000017 },
	/* (003) jeq  #0x1 jt 4 jf 10 */
	{ 0x15, 0, 6, 0x00000001 },
	/* (004) ldh  [20] */
	{ 0x28, 0, 0, 0x00000014 },
	/* (005) jset #0x1fff jt 10 jf 6 */
	{ 0x45, 4, 0, 0x00001fff },
	/* (006) ldxb 4*([14]&0xf) */
	{ 0xb1, 0, 0, 0x0000000e },
	/* (007) ldb  [x + 14] */
	{ 0x50, 0, 0, 0x0000000e },
	/* (008) jeq  #0xb jt 9 jf 10 */
	{ 0x15, 0, 1, 0x0000000b },
	/* (009) ret  #65535 */
	{ 0x06, 0, 0, 0xffffffff },
	/* (010) ret  #0 */
	{ 0x06, 0, 0, 0x00000000 },
};

static struct sock_filter ipv6_icmp6_type_3[] = {
	/* (000) ldh [12] */
	{ 0x28, 0, 0, 0x0000000c },
	/* (001) jeq  #0x86dd jt 2 jf 7 */
	{ 0x15, 0, 5, 0x000086dd },
	/* (002) ldb  [20] */
	{ 0x30, 0, 0, 0x00000014 },
	/* (003) jeq  #0x3a jt 4 jf 7 */
	{ 0x15, 0, 3, 0x0000003a },
	/* (004) ldb  [54] */
	{ 0x30, 0, 0, 0x00000036 },
	/* (005) jeq  #0x3 jt 6 jf 7 */
	{ 0x15, 0, 1, 0x00000003 },
	/* (006) ret  #65535 */
	{ 0x06, 0, 0, 0xffffffff },
	/* (007) ret  #0 */
	{ 0x06, 0, 0, 0x00000000 },
};

#define PKT_NOT_FOR_US	0
#define PKT_GOOD	1

static inline const char *make_n_a(const char *p)
{
	return p ? : "N/A";
}

static void signal_handler(int number)
{
	switch (number) {
	case SIGINT:
		sigint = 1;
		break;
	default:
		break;
	}
}

static void help(void)
{

	printf("\nastraceroute %s, autonomous system trace route utility\n",
	       VERSION_STRING);
	puts("http://www.netsniff-ng.org\n\n"
	     "Usage: astraceroute [options]\n"
	     "Options:\n"
	     " -H|--host <host>        Host/IPv4/IPv6 to lookup AS route to\n"
	     " -p|--port <port>        Hosts port to lookup AS route to\n"
	     " -i|-d|--dev <device>    Networking device, i.e. eth0\n"
	     " -4|--ipv4               Use IPv4 requests (default)\n"
	     " -6|--ipv6               Use IPv6 requests\n"
	     " -n|--numeric            Do not do reverse DNS lookup for hops\n"
	     " -N|--dns                Do a reverse DNS lookup for hops\n"
	     " -f|--init-ttl <ttl>     Set initial TTL\n"
	     " -m|--max-ttl <ttl>      Set maximum TTL (default: 30)\n"
	     " -q|--num-probes <num>   Number of max probes for each hop (default: 3)\n"
	     " -x|--timeout <sec>      Probe response timeout in sec (default: 3)\n"
	     " -S|--syn                Set TCP SYN flag in packets\n"
	     " -A|--ack                Set TCP ACK flag in packets\n"
	     " -F|--fin                Set TCP FIN flag in packets\n"
	     " -P|--psh                Set TCP PSH flag in packets\n"
	     " -U|--urg                Set TCP URG flag in packets\n"
	     " -R|--rst                Set TCP RST flag in packets\n"
	     " -E|--ecn-syn            Send ECN SYN packets (RFC3168)\n"
	     " -t|--tos <tos>          Set the IP TOS field\n"
	     " -G|--nofrag             Set do not fragment bit\n"
	     " -X|--payload <string>   Specify a payload string to test DPIs\n"
	     " -Z|--show-packet        Show returned packet on each hop\n"
	     " -l|--totlen <len>       Specify total packet len\n"
	     " -w|--whois <server>     Use a different AS whois DB server\n"
	     "                         (default: /etc/netsniff-ng/whois.conf)\n"
	     " -W|--wport <port>       Use a different port to AS whois server\n"
	     "                         (default: /etc/netsniff-ng/whois.conf)\n"
	     " --city-db <path>        Specifiy path for geoip city database\n"
	     " --country-db <path>     Specifiy path for geoip country database\n"
	     " -v|--version            Print version\n"
	     " -h|--help               Print this help\n\n"
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
	     "  information about astraceroute's fetched AS numbers, see i.e.\n"
	     "  http://bgp.he.net/AS<number>!\n\n"
	     "Please report bugs to <bugs@netsniff-ng.org>\n"
	     "Copyright (C) 2011-2012 Daniel Borkmann <daniel@netsniff-ng.org>\n"
	     "Swiss federal institute of technology (ETH Zurich)\n"
	     "License: GNU GPL version 2.0\n"
	     "This is free software: you are free to change and redistribute it.\n"
	     "There is NO WARRANTY, to the extent permitted by law.\n");
	die();
}

static void version(void)
{
	printf("\nastraceroute %s, autonomous system trace route utility\n",
	       VERSION_STRING);
	puts("http://www.netsniff-ng.org\n\n"
	     "Please report bugs to <bugs@netsniff-ng.org>\n"
	     "Copyright (C) 2011-2012 Daniel Borkmann <daniel@netsniff-ng.org>\n"
	     "Swiss federal institute of technology (ETH Zurich)\n"
	     "License: GNU GPL version 2.0\n"
	     "This is free software: you are free to change and redistribute it.\n"
	     "There is NO WARRANTY, to the extent permitted by law.\n");
	die();
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

static void assemble_data(uint8_t *packet, size_t len, const char *payload)
{
	int i;

	if (payload == NULL) {
		for (i = 0; i < len; ++i)
			packet[i] = (uint8_t) rand();
	} else {
		int lmin = min(len, strlen(payload));
		for (i = 0; i < lmin; ++i)
			packet[i] = (uint8_t) payload[i];
		for (i = lmin; i < len; ++i)
			packet[i] = (uint8_t) rand();
	}
}

static void assemble_icmp4(uint8_t *packet, size_t len)
{
	struct icmphdr *icmph = (struct icmphdr *) packet;

	bug_on(len < sizeof(struct icmphdr));

	icmph->type = ICMP_ECHO;
	icmph->code = 0;
	icmph->checksum = 0;
}

static void assemble_icmp6(uint8_t *packet, size_t len)
{
	struct icmp6hdr *icmp6h = (struct icmp6hdr *) packet;

	bug_on(len < sizeof(struct icmp6hdr));

	icmp6h->icmp6_type = ICMPV6_ECHO_REQUEST;
	icmp6h->icmp6_code = 0;
	icmp6h->icmp6_cksum = 0;
}

static void assemble_tcp(uint8_t *packet, size_t len, int syn, int ack,
			 int urg, int fin, int rst, int psh, int ecn, int dport)
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
	tcph->check = 0;
	tcph->urg_ptr = (!!urg ? htons((uint16_t) rand()) :  0);
}

static int assemble_ipv4_tcp(uint8_t *packet, size_t len, int ttl,
			     int tos, const struct sockaddr *dst,
			     const struct sockaddr *src, int syn, int ack,
			     int urg, int fin, int rst, int psh, int ecn,
			     int nofrag, int dport, const char *payload)
{
	struct iphdr *iph = (struct iphdr *) packet;
	uint8_t *data;
	size_t data_len;

	bug_on(!src || !dst);
	bug_on(src->sa_family != PF_INET || dst->sa_family != PF_INET);
	bug_on(len < sizeof(*iph) + sizeof(struct tcphdr));

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = (uint8_t) tos;
	iph->tot_len = htons((uint16_t) len);
	iph->id = htons((uint16_t) rand());
	iph->frag_off = nofrag ? IP_DF : 0;
	iph->ttl = (uint8_t) ttl;
	iph->protocol = IPPROTO_TCP;
	iph->saddr = ((const struct sockaddr_in *) src)->sin_addr.s_addr;
	iph->daddr = ((const struct sockaddr_in *) dst)->sin_addr.s_addr;

	data = packet + sizeof(*iph);
	data_len = len - sizeof(*iph);
	assemble_tcp(data, data_len, syn, ack, urg, fin, rst, psh, ecn, dport);

	data = packet + sizeof(*iph) + sizeof(struct tcphdr);
	data_len = len - sizeof(*iph) - sizeof(struct tcphdr);
	assemble_data(data, data_len, payload);

	iph->check = csum((unsigned short *) packet, ntohs(iph->tot_len) >> 1);

	return ntohs(iph->id);
}

static int assemble_ipv6_tcp(uint8_t *packet, size_t len, int ttl,
			     const struct sockaddr *dst,
			     const struct sockaddr *src, int syn, int ack,
			     int urg, int fin, int rst, int psh, int ecn,
			     int dport, const char *payload)
{
	struct ip6_hdr *ip6h = (struct ip6_hdr *) packet;
	uint8_t *data;
	size_t data_len;

	bug_on(!src || !dst);
	bug_on(src->sa_family != PF_INET6 || dst->sa_family != PF_INET6);
	bug_on(len < sizeof(*ip6h) + sizeof(struct tcphdr));

	ip6h->ip6_flow = htonl(rand() & 0x000fffff);
	ip6h->ip6_vfc = 0x60;
	ip6h->ip6_plen = htons((uint16_t) len - sizeof(*ip6h));
	ip6h->ip6_nxt = 6; /* TCP */
	ip6h->ip6_hlim = (uint8_t) ttl;
	memcpy(&ip6h->ip6_src, &(((const struct sockaddr_in6 *)
	       src)->sin6_addr), sizeof(ip6h->ip6_src));
	memcpy(&ip6h->ip6_dst, &(((const struct sockaddr_in6 *)
	       dst)->sin6_addr), sizeof(ip6h->ip6_dst));

	data = packet + sizeof(*ip6h);
	data_len = len - sizeof(*ip6h);
	assemble_tcp(data, data_len, syn, ack, urg, fin, rst, psh, ecn, dport);

	data = packet + sizeof(*ip6h) + sizeof(struct tcphdr);
	data_len = len - sizeof(*ip6h) - sizeof(struct tcphdr);
	assemble_data(data, data_len, payload);

	return ntohl(ip6h->ip6_flow) & 0x000fffff;
}

static int assemble_ipv6_icmp6(uint8_t *packet, size_t len, int ttl,
			       const struct sockaddr *dst,
			       const struct sockaddr *src,
			       const char *payload)
{
	struct ip6_hdr *ip6h = (struct ip6_hdr *) packet;
	uint8_t *data;
	size_t data_len;

	bug_on(!src || !dst);
	bug_on(src->sa_family != PF_INET6 || dst->sa_family != PF_INET6);
	bug_on(len < sizeof(*ip6h) + sizeof(struct icmp6hdr));

	ip6h->ip6_flow = htonl(rand() & 0x000fffff);
	ip6h->ip6_vfc = 0x60;
	ip6h->ip6_plen = htons((uint16_t) len - sizeof(*ip6h));
	ip6h->ip6_nxt = 0x3a; /* ICMP6 */
	ip6h->ip6_hlim = (uint8_t) ttl;
	memcpy(&ip6h->ip6_src, &(((const struct sockaddr_in6 *)
	       src)->sin6_addr), sizeof(ip6h->ip6_src));
	memcpy(&ip6h->ip6_dst, &(((const struct sockaddr_in6 *)
	       dst)->sin6_addr), sizeof(ip6h->ip6_dst));

	data = packet + sizeof(*ip6h);
	data_len = len - sizeof(*ip6h);
	assemble_icmp6(data, data_len);

	data = packet + sizeof(*ip6h) + sizeof(struct icmp6hdr);
	data_len = len - sizeof(*ip6h) - sizeof(struct icmp6hdr);
	assemble_data(data, data_len, payload);

	return ntohl(ip6h->ip6_flow) & 0x000fffff;
}

static int assemble_ipv4_icmp4(uint8_t *packet, size_t len, int ttl,
			       int tos, const struct sockaddr *dst,
			       const struct sockaddr *src, int nofrag,
			       const char *payload)
{
	struct iphdr *iph = (struct iphdr *) packet;
	uint8_t *data;
	size_t data_len;

	bug_on(!src || !dst);
	bug_on(src->sa_family != PF_INET || dst->sa_family != PF_INET);
	bug_on(len < sizeof(struct iphdr) + sizeof(struct icmphdr));

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = htons((uint16_t) len);
	iph->id = htons((uint16_t) rand());
	iph->frag_off = nofrag ? IP_DF : 0;
	iph->ttl = (uint8_t) ttl;
	iph->protocol = IPPROTO_ICMP;
	iph->saddr = ((const struct sockaddr_in *) src)->sin_addr.s_addr;
	iph->daddr = ((const struct sockaddr_in *) dst)->sin_addr.s_addr;

	data = packet + sizeof(*iph);
	data_len = len - sizeof(*iph);
	assemble_icmp4(data, data_len);

	data = packet + sizeof(*iph) + sizeof(struct icmphdr);
	data_len = len - sizeof(*iph) - sizeof(struct icmphdr);
	assemble_data(data, data_len, payload);

	iph->check = csum((unsigned short *) packet, ntohs(iph->tot_len) >> 1);

	return ntohs(iph->id);
}

static int assemble_packet_or_die(uint8_t *packet, size_t len,
				  int ttl, int icmp,
				  const struct ash_cfg *cfg,
				  const struct sockaddr *dst,
				  const struct sockaddr *src)
{
	if (icmp) {
		if (cfg->ip == 4) {
			return assemble_ipv4_icmp4(packet, len, ttl, cfg->tos,
						   dst, src, cfg->nofrag,
						   cfg->payload);
		} else {
			return assemble_ipv6_icmp6(packet, len, ttl, dst, src,
						   cfg->payload);
		}
	} else {
		if (cfg->ip == 4) {
			return assemble_ipv4_tcp(packet, len, ttl, cfg->tos,
						 dst, src, cfg->syn, cfg->ack,
						 cfg->urg, cfg->fin, cfg->rst,
						 cfg->psh, cfg->ecn,
						 cfg->nofrag, atoi(cfg->port),
						 cfg->payload);
		} else {
			return assemble_ipv6_tcp(packet, len, ttl, dst, src,
						 cfg->syn, cfg->ack, cfg->urg,
						 cfg->fin, cfg->rst, cfg->psh,
						 cfg->ecn, atoi(cfg->port),
						 cfg->payload);
		}
	}

	return -EIO;
}

static int handle_ipv4_icmp(uint8_t *packet, size_t len, int ttl, int id,
			    const struct sockaddr *own, int dns_resolv)
{
	int ret;
	struct iphdr *iph = (struct iphdr *) packet;
	struct iphdr *iph_inner;
	struct icmphdr *icmph;
	char *hbuff;
	struct sockaddr_in sa;
	struct asrecord rec;
	GeoIPRecord *gir;

	if (iph->protocol != 1)
		return PKT_NOT_FOR_US;
	if (iph->daddr != ((const struct sockaddr_in *) own)->sin_addr.s_addr)
		return PKT_NOT_FOR_US;

	icmph = (struct icmphdr *) (packet + sizeof(struct iphdr));
	if (icmph->type != ICMP_TIME_EXCEEDED)
		return PKT_NOT_FOR_US;
	if (icmph->code != ICMP_EXC_TTL)
		return PKT_NOT_FOR_US;

	iph_inner = (struct iphdr *) (packet + sizeof(struct iphdr) +
				      sizeof(struct icmphdr));
	if (ntohs(iph_inner->id) != id)
		return PKT_NOT_FOR_US;

	hbuff = xzmalloc(NI_MAXHOST);

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = PF_INET;
	sa.sin_addr.s_addr = iph->saddr;

	getnameinfo((struct sockaddr *) &sa, sizeof(sa), hbuff, NI_MAXHOST,
		    NULL, 0, NI_NUMERICHOST);

	memset(&rec, 0, sizeof(rec));
	ret = aslookup(hbuff, &rec);
	if (ret < 0)
		panic("AS lookup error %d!\n", ret);

	gir = GeoIP_record_by_ipnum(gi_city, ntohl(iph->saddr));
	if (!dns_resolv) {
		if (strlen(rec.country) > 0 && gir) {
			const char *city = make_n_a(gir->city);

			printf("%s in AS%s (%s, %s, %s, %f, %f), %s %s (%s), %s", hbuff,
			       rec.number, rec.country,
			       GeoIP_country_name_by_ipnum(gi_country, ntohl(iph->saddr)),
			       city, gir->latitude, gir->longitude,
			       rec.prefix, rec.registry, rec.since, rec.name);
		} else if (strlen(rec.country) > 0 && !gir) {
			printf("%s in AS%s (%s, %s), %s %s (%s), %s", hbuff,
			       rec.number, rec.country,
			       GeoIP_country_name_by_ipnum(gi_country, ntohl(iph->saddr)),
			       rec.prefix, rec.registry, rec.since, rec.name);
		} else {
			printf("%s in unknown AS", hbuff);
		}
	} else {
		struct hostent *hent = gethostbyaddr(&sa.sin_addr,
						     sizeof(sa.sin_addr),
						     PF_INET);

		if (strlen(rec.country) > 0 && gir) {
			const char *city = make_n_a(gir->city);
			printf("%s (%s) in AS%s (%s, %s, %s, %f, %f), %s %s (%s), %s",
			       (hent ? hent->h_name : hbuff), hbuff,
			       rec.number, rec.country,
			       GeoIP_country_name_by_ipnum(gi_country, ntohl(iph->saddr)),
			       city, gir->latitude, gir->longitude,
			       rec.prefix, rec.registry,
			       rec.since, rec.name);
		} else if (strlen(rec.country) > 0 && !gir) {
			printf("%s (%s) in AS%s (%s, %s), %s %s (%s), %s",
			       (hent ? hent->h_name : hbuff), hbuff,
			       rec.number, rec.country,
			       GeoIP_country_name_by_ipnum(gi_country, ntohl(iph->saddr)),
			       rec.prefix, rec.registry,
			       rec.since, rec.name);
		} else {
			printf("%s (%s) in unknown AS",
			       (hent ? hent->h_name : hbuff), hbuff);
		}
	}

	xfree(hbuff);

	return PKT_GOOD;
}

static int handle_ipv6_icmp(uint8_t *packet, size_t len, int ttl, int id,
			    const struct sockaddr *own, int dns_resolv)
{
	int ret;
	struct ip6_hdr *ip6h = (struct ip6_hdr *) packet;
	struct ip6_hdr *ip6h_inner;
	struct icmp6hdr *icmp6h;
	char *hbuff;
	struct sockaddr_in6 sa;
	struct asrecord rec;
	GeoIPRecord *gir;

	if (ip6h->ip6_nxt != 0x3a)
		return PKT_NOT_FOR_US;
	if (memcmp(&ip6h->ip6_dst, &(((const struct sockaddr_in6 *)
		   own)->sin6_addr), sizeof(ip6h->ip6_dst)))
		return PKT_NOT_FOR_US;

	icmp6h = (struct icmp6hdr *) (packet + sizeof(*ip6h));
	if (icmp6h->icmp6_type != ICMPV6_TIME_EXCEED)
		return PKT_NOT_FOR_US;
	if (icmp6h->icmp6_code != ICMPV6_EXC_HOPLIMIT)
		return PKT_NOT_FOR_US;

	ip6h_inner = (struct ip6_hdr *) (packet + sizeof(*ip6h) + sizeof(*icmp6h));
	if ((ntohl(ip6h_inner->ip6_flow) & 0x000fffff) != id)
		return PKT_NOT_FOR_US;

	hbuff = xzmalloc(NI_MAXHOST);

	memset(&sa, 0, sizeof(sa));
	sa.sin6_family = PF_INET6;
	memcpy(&sa.sin6_addr, &ip6h->ip6_src, sizeof(ip6h->ip6_src));

	getnameinfo((struct sockaddr *) &sa, sizeof(sa), hbuff, NI_MAXHOST,
		    NULL, 0, NI_NUMERICHOST);

	memset(&rec, 0, sizeof(rec));
	ret = aslookup(hbuff, &rec);
	if (ret < 0)
		panic("AS lookup error %d!\n", ret);

	gir = GeoIP_record_by_ipnum_v6(gi_city, sa.sin6_addr);
	if (!dns_resolv) {
		if (strlen(rec.country) > 0 && gir) {
			const char *city = make_n_a(gir->city);

			printf("%s in AS%s (%s, %s, %s, %f, %f), %s %s (%s), %s", hbuff,
			       rec.number, rec.country,
			       GeoIP_country_name_by_ipnum_v6(gi_country, sa.sin6_addr),
			       city, gir->latitude, gir->longitude,
			       rec.prefix, rec.registry, rec.since, rec.name);
		} else if (strlen(rec.country) > 0 && !gir) {
			printf("%s in AS%s (%s, %s), %s %s (%s), %s", hbuff,
			       rec.number, rec.country,
			       GeoIP_country_name_by_ipnum_v6(gi_country, sa.sin6_addr),
			       rec.prefix, rec.registry, rec.since, rec.name);
		} else {
			printf("%s in unknown AS", hbuff);
		}
	} else {
		struct hostent *hent = gethostbyaddr(&sa.sin6_addr,
						     sizeof(sa.sin6_addr),
						     PF_INET6);

		if (strlen(rec.country) > 0 && gir) {
			const char *city = make_n_a(gir->city);
			printf("%s (%s) in AS%s (%s, %s, %s, %f, %f), %s %s (%s), %s",
			       (hent ? hent->h_name : hbuff), hbuff,
			       rec.number, rec.country,
			       GeoIP_country_name_by_ipnum_v6(gi_country, sa.sin6_addr),
			       city, gir->latitude, gir->longitude,
			       rec.prefix, rec.registry,
			       rec.since, rec.name);
		} else if (strlen(rec.country) > 0 && !gir) {
			printf("%s (%s) in AS%s (%s, %s), %s %s (%s), %s",
			       (hent ? hent->h_name : hbuff), hbuff,
			       rec.number, rec.country,
			       GeoIP_country_name_by_ipnum_v6(gi_country, sa.sin6_addr),
			       rec.prefix, rec.registry,
			       rec.since, rec.name);
		} else {
			printf("%s (%s) in unknown AS",
			       (hent ? hent->h_name : hbuff), hbuff);
		}
	}

	xfree(hbuff);

	return PKT_GOOD;
}

static int handle_packet(uint8_t *packet, size_t len, int ip, int ttl, int id,
			 struct sockaddr *own, int dns_resolv)
{
	if (ip == 4)
		return handle_ipv4_icmp(packet, len, ttl, id, own, dns_resolv);
	else
		return handle_ipv6_icmp(packet, len, ttl, id, own, dns_resolv);
}

static int do_trace(const struct ash_cfg *cfg)
{
	int ttl, query, fd = -1, one = 1, ret, fd_cap, ifindex;
	int is_okay = 0, id, timeout_poll;
	uint8_t *packet, *packet_rcv;
	ssize_t err, real_len, sd_len;
	size_t len, len_rcv;
	struct addrinfo hints, *ahead, *ai;
	char *hbuff1, *hbuff2;
	struct sockaddr_storage ss, sd;
	struct sock_fprog bpf_ops;
	struct ring dummy_ring;
	struct pollfd pfd;

	srand(time(NULL));

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_NUMERICSERV;

	ret = getaddrinfo(cfg->host, cfg->port, &hints, &ahead);
	if (ret < 0) {
		printf("Cannot get address info!\n");
		return -EIO;
	}

	for (ai = ahead; ai != NULL && fd < 0; ai = ai->ai_next) {
		if (!((ai->ai_family == PF_INET6 && cfg->ip == 6) ||
		      (ai->ai_family == PF_INET && cfg->ip == 4)))
			continue;
		fd = socket(ai->ai_family, SOCK_RAW, IPPROTO_RAW);
		if (fd < 0)
			continue;
		fd_cap = pf_socket();

		memset(&ss, 0, sizeof(ss));
		ret = device_address(cfg->dev, ai->ai_family, &ss);
		if (ret < 0)
			panic("Cannot get own device address!\n");

		ret = bind(fd, (struct sockaddr *) &ss, sizeof(ss));
		if (ret < 0)
			panic("Cannot bind socket!\n");

		memset(&sd, 0, sizeof(sd));
		memcpy(&sd, ai->ai_addr, ai->ai_addrlen);
		if (ai->ai_family == PF_INET6) {
			struct sockaddr_in6 *sd6 = (struct sockaddr_in6 *) &sd;
			sd6->sin6_port = htons(0);
		}
		sd_len = ai->ai_addrlen;

		break;
	}

	freeaddrinfo(ahead);

	if (fd < 0) {
		printf("Cannot create socket! Does remote support IPv%d?!\n",
		      cfg->ip);
		return -EIO;
	}

	len = cfg->totlen;
	if (cfg->ip == 4) {
		if (len < sizeof(struct iphdr) + sizeof(struct tcphdr)) {
			len = sizeof(struct iphdr) + sizeof(struct tcphdr);
			if (cfg->payload)
				len += strlen(cfg->payload);
		}
	} else {
		if (len < sizeof(struct ip6_hdr) + sizeof(struct tcphdr)) {
			len = sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
			if (cfg->payload)
				len += strlen(cfg->payload);
		}
	}

	len_rcv = device_mtu(cfg->dev);
	if (len >= len_rcv)
		panic("Packet len exceeds device MTU!\n");

	packet = xmalloc(len);
	packet_rcv = xmalloc(len_rcv);

	hbuff1 = xzmalloc(256);
	getnameinfo((struct sockaddr *) &sd, sizeof(sd), hbuff1, 256,
		    NULL, 0, NI_NUMERICHOST);

	hbuff2 = xzmalloc(256);
	getnameinfo((struct sockaddr *) &ss, sizeof(ss), hbuff2, 256,
		    NULL, 0, NI_NUMERICHOST);

	ret = setsockopt(fd, cfg->ip == 4 ? IPPROTO_IP : IPPROTO_IPV6,
			 IP_HDRINCL, &one, sizeof(one));
	if (ret < 0)
		panic("Kernel does not support IP_HDRINCL!\n");

	printf("AS path IPv%d TCP trace from %s to %s:%s (%s) with len %zu "
	       "Bytes, %u max hops\n", cfg->ip, hbuff2, hbuff1, cfg->port,
	       cfg->host, len, cfg->max_ttl);

	printf("Using flags SYN:%d,ACK:%d,ECN:%d,FIN:%d,PSH:%d,RST:%d,URG:%d\n",
	       cfg->syn, cfg->ack, cfg->ecn, cfg->fin, cfg->psh, cfg->rst,
	       cfg->urg);

	if (cfg->payload)
		printf("With payload: \'%s\'\n", cfg->payload);

	fflush(stdout);

	xfree(hbuff1);
	xfree(hbuff2);

	hbuff1 = hbuff2 = NULL;

	enable_kernel_bpf_jit_compiler();

	memset(&bpf_ops, 0, sizeof(bpf_ops));
	if (cfg->ip == 4) {
		bpf_ops.filter = ipv4_icmp_type_11;
		bpf_ops.len = (sizeof(ipv4_icmp_type_11) /
			       sizeof(ipv4_icmp_type_11[0]));
	} else {
		bpf_ops.filter = ipv6_icmp6_type_3;
		bpf_ops.len = (sizeof(ipv6_icmp6_type_3) /
			       sizeof(ipv6_icmp6_type_3[0]));
	}

	bpf_attach_to_sock(fd_cap, &bpf_ops);
	ifindex = device_ifindex(cfg->dev);
	bind_rx_ring(fd_cap, &dummy_ring, ifindex);
	prepare_polling(fd_cap, &pfd);

	timeout_poll = (cfg->timeout > 0 ? cfg->timeout : 3) * 1000;

	for (ttl = cfg->init_ttl; ttl <= cfg->max_ttl; ++ttl) {
		int icmp = 0;
		is_okay = 0;

		if ((ttl == cfg->init_ttl && !show_pkt) ||
		    (ttl > cfg->init_ttl)) {
			printf("%2d: ", ttl);
			fflush(stdout);
		}
retry:
		for (query = 0; query < cfg->queries && !is_okay; ++query) {
			id = assemble_packet_or_die(packet, len, ttl, icmp, cfg,
						    (struct sockaddr *) &sd,
						    (struct sockaddr *) &ss);
			if (ttl == cfg->init_ttl && query == 0 && show_pkt) {
				struct pkt_buff *pkt;

				printf("Original packet:\n");

				pkt = pkt_alloc(packet, len);
				hex_ascii(pkt);
				tprintf_flush();
				pkt_free(pkt);

				printf("\n%2d: ", ttl);
				fflush(stdout);
			}

			err = sendto(fd, packet, len, 0, (struct sockaddr *) &sd,
				     sd_len);
			if (err < 0)
				panic("sendto failed: %s\n", strerror(errno));

			err = poll(&pfd, 1, timeout_poll);
			if (err > 0 && pfd.revents & POLLIN) {
				real_len = recvfrom(fd_cap, packet_rcv, len_rcv,
						    0, NULL, NULL);
				if (real_len < sizeof(struct ethhdr) +
				    (cfg->ip ? sizeof(struct iphdr) +
					       sizeof(struct icmphdr) :
					       sizeof(struct ip6_hdr) +
					       sizeof(struct icmp6hdr)))
					continue;

				is_okay = handle_packet(packet_rcv + sizeof(struct ethhdr),
							real_len - sizeof(struct ethhdr),
							cfg->ip, ttl, id,
							(struct sockaddr *) &ss,
							cfg->dns_resolv);
				if (is_okay && show_pkt) {
					struct pkt_buff *pkt;

					printf("\n  Received packet:\n");

					pkt = pkt_alloc(packet_rcv, real_len);
					hex_ascii(pkt);
					tprintf_flush();
					pkt_free(pkt);
				}
			} else {
				printf("* ");
				fflush(stdout);
				is_okay = 0;
			}
		}

		if (is_okay == 0 && icmp == 0) {
			icmp = 1;
			goto retry;
		}

		printf("\n");
		fflush(stdout);
	}

	close(fd_cap);
	close(fd);

	xfree(packet);
	xfree(packet_rcv);

	return 0;
}

static void parse_whois_or_die(struct ash_cfg *cfg)
{
	int fd;
	ssize_t ret;
	char tmp[512], *ptr, *ptr2;

	fd = open_or_die(WHOIS_SERVER_SOURCE, O_RDONLY);

	memset(tmp, 0, sizeof(tmp));
	while ((ret = read(fd, tmp, sizeof(tmp))) > 0) {
		tmp[sizeof(tmp) - 1] = 0;
		ptr = skips(tmp);
		ptr2 = ptr;
		while (*ptr2 != ' ' && ptr2 < &tmp[sizeof(tmp) - 1])
			ptr2++;
		if (*ptr2 != ' ')
			panic("Parser error!\n");
		*ptr2 = 0;
		cfg->whois = xstrdup(ptr);
		ptr = ptr2 + 1;
		if (ptr >= &tmp[sizeof(tmp) - 1])
			panic("Parser error!\n");
		ptr = skips(ptr);
		ptr[strlen(ptr) - 1] = 0;
		cfg->whois_port = xstrdup(ptr);
		break;
	}

	close(fd);
}

int main(int argc, char **argv)
{
	int c, opt_index, ret;
	struct ash_cfg cfg;
	char *path_city_db = NULL, *path_country_db = NULL;

	setfsuid(getuid());
	setfsgid(getgid());

	memset(&cfg, 0, sizeof(cfg));
	cfg.init_ttl = 1;
	cfg.max_ttl = 30;
	cfg.queries = 3;
	cfg.timeout = 3;
	cfg.ip = 4;
	cfg.payload = NULL;
	cfg.dev = xstrdup("eth0");
	cfg.port = xstrdup("80");

	while ((c = getopt_long(argc, argv, short_options, long_options,
		&opt_index)) != EOF) {
		switch (c) {
		case 'h':
			help();
			break;
		case 'v':
			version();
			break;
		case 'H':
			cfg.host = xstrdup(optarg);
			break;
		case 'p':
			if (cfg.port)
				xfree(cfg.port);
			cfg.port = xstrdup(optarg);
			break;
		case 'n':
			cfg.dns_resolv = 0;
			break;
		case '4':
			cfg.ip = 4;
			break;
		case '6':
			cfg.ip = 6;
			break;
		case 'Z':
			show_pkt = 1;
			break;
		case 'N':
			cfg.dns_resolv = 1;
			break;
		case 'f':
			cfg.init_ttl = atoi(optarg);
			if (cfg.init_ttl <= 0)
				help();
			break;
		case 'm':
			cfg.max_ttl = atoi(optarg);
			if (cfg.max_ttl <= 0)
				help();
			break;
		case 'i':
		case 'd':
			if (cfg.dev)
				xfree(cfg.dev);
			cfg.dev = xstrdup(optarg);
			break;
		case 'q':
			cfg.queries = atoi(optarg);
			if (cfg.queries <= 0)
				help();
			break;
		case 'x':
			cfg.timeout = atoi(optarg);
			if (cfg.timeout <= 0)
				help();
			break;
		case 'S':
			cfg.syn = 1;
			break;
		case 'A':
			cfg.ack = 1;
			break;
		case 'F':
			cfg.fin = 1;
			break;
		case 'U':
			cfg.urg = 1;
			break;
		case 'P':
			cfg.psh = 1;
			break;
		case 'R':
			cfg.rst = 1;
			break;
		case 'E':
			cfg.syn = 1;
			cfg.ecn = 1;
			break;
		case 't':
			cfg.tos = atoi(optarg);
			if (cfg.tos < 0)
				help();
			break;
		case 'G':
			cfg.nofrag = 1;
			break;
		case 'X':
			cfg.payload = xstrdup(optarg);
			break;
		case 'l':
			cfg.totlen = atoi(optarg);
			if (cfg.totlen <= 0)
				help();
			break;
		case 'w':
			cfg.whois = xstrdup(optarg);
			break;
		case 'W':
			cfg.whois_port = xstrdup(optarg);
			break;
		case 'L':
			path_city_db = xstrdup(optarg);
			break;
		case 'K':
			path_country_db = xstrdup(optarg);
			break;
		case '?':
			switch (optopt) {
			case 'H':
			case 'p':
			case 'L':
			case 'K':
			case 'f':
			case 'm':
			case 'i':
			case 'd':
			case 'q':
			case 'x':
			case 'X':
			case 't':
			case 'l':
			case 'w':
			case 'W':
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

	if (argc < 3 ||
	    !cfg.host || !cfg.port ||
	    cfg.init_ttl > cfg.max_ttl ||
	    cfg.init_ttl > MAXTTL ||
	    cfg.max_ttl > MAXTTL)
		help();

	if (!device_up_and_running(cfg.dev))
		panic("Networking device not up and running!\n");
	if (!cfg.whois || !cfg.whois_port)
		parse_whois_or_die(&cfg);
	if (device_mtu(cfg.dev) <= cfg.totlen)
		panic("Packet larger than device MTU!\n");

	register_signal(SIGHUP, signal_handler);

	tprintf_init();

	ret = aslookup_prepare(cfg.whois, cfg.whois_port);
	if (ret < 0)
		panic("Cannot resolve whois server!\n");

	if (path_country_db)
		gi_country = GeoIP_open(path_country_db, GEOIP_MMAP_CACHE);
	else
		gi_country = GeoIP_open_type(cfg.ip == 4 ?
					     GEOIP_COUNTRY_EDITION :
					     GEOIP_COUNTRY_EDITION_V6,
					     GEOIP_MMAP_CACHE);

	if (path_city_db)
		gi_city = GeoIP_open(path_city_db, GEOIP_MMAP_CACHE);
	else
		gi_city = GeoIP_open_type(cfg.ip == 4 ?
					  GEOIP_CITY_EDITION_REV1 :
					  GEOIP_CITY_EDITION_REV1_V6,
					  GEOIP_MMAP_CACHE);

	if (!gi_country || !gi_city)
		panic("Cannot open GeoIP database! Wrong path?!\n");

	GeoIP_set_charset(gi_country, GEOIP_CHARSET_UTF8);
	GeoIP_set_charset(gi_city, GEOIP_CHARSET_UTF8);

	ret = do_trace(&cfg);

	GeoIP_delete(gi_city);
	GeoIP_delete(gi_country);

	tprintf_cleanup();

	free(cfg.whois_port);
	free(cfg.whois);
	free(cfg.dev);
	free(cfg.host);
	free(cfg.port);
	free(cfg.payload);
	free(path_city_db);
	free(path_country_db);

	return ret;
}

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
 * your curvetun tunneled packets, for instance. However, ashunt was written
 * from scratch and does not use any libraries. Special thanks to Team CYMRU!
 *
 *   The road must be trod, but it will be very hard. And neither strength nor
 *   wisdom will carry us far upon it. This quest may be attempted by the weak
 *   with as much hope as the strong. Yet such is oft the course of deeds that
 *   move the wheels of the world: small hands do them because they must,
 *   while the eyes of the great are elsewhere.
 *
 *     -- The Lord of the Rings, Elrond, Chapter 'The Council of Elrond'.
 *
 * ashunt includes GeoLite data created by MaxMind, available from
 * http://www.maxmind.com/. On Debian you need libgeoip-dev, libgeoip1 and
 * geoip-database-contrib.
 */

/*

=head1 NAME

ashunt - Autonomous System (AS) trace route utility

=head1 SYNOPSIS

ashunt	-H|--host <host> -i|-d|--dev <dev> [-6|--ipv6]
	[-n|--numeric] [-N|--dns] [-f|--init-ttl <ttl>]
	[-m|--max-ttl <ttl>] [-q|--num-probes] [-x|--timeout <sec>]
	[-S|--syn] [-A|--ack] [-F|--fin] [-P|--psh] [-U|--urg]
	[-R|--rst] [-E|--ecn-syn] [-t|--tos <tos>] [-G|--nofrag]
	[-X|--payload <string>] [-Z|--show-packet] [-l|--totlen <len>]
	[-w|--whois <server>] [-W|--wport <port>] [--city-db <path>]
	[--country-db <path>] [-v|--version] [-h|--help]

=head1 DESCRIPTION

This program provides AS information on each hop between the client
and the target host.

=head1 OPTIONS

=over

=item ashunt -i eth0 -N -E -H netsniff-ng.org

IPv4 trace of AS with TCP ECN SYN probe

=item ashunt -i eth0 -N -S -H netsniff-ng.org

IPv4 trace of AS with TCP SYN probe

=item ashunt -i eth0 -N -F -H netsniff-ng.org

IPv4 trace of AS with TCP FIN probe

=item ashunt -i eth0 -N -FPU -H netsniff-ng.org

IPv4 trace of AS with Xmas probe

=item ashunt -i eth0 -N -H netsniff-ng.org -X "censor-me" -Z

IPv4 trace of AS with Null probe with ASCII payload

=item ashunt -6 -S -i eth0 -H netsniff-ng.org

IPv6 trace of AS up to netsniff-ng.org

=back

=head1 OPTIONS

=over

=item -h|--help

Print help text and lists all options.

=item -v|--version

Print version.

=item -H|--host <host>

Host/IPv4/IPv6 to lookup AS route to

=item i-|-d|--dev <netdev>

Networking device, i.e. eth0

=item -p|--port <port>

Hosts port to lookup AS route to

=item -4|--ipv4

Use IPv4 requests (default)

=item -6|--ipv6

Use IPv6 requests

=item -n|--numeric

Do not do reverse DNS lookup for hops

=item -N|--dns

Do a reverse DNS lookup for hops

=item -f|--init-ttl <ttl>

Set initial TTL

=item -m|--max-ttl <ttl>

Set maximum TTL (default: 30)

=item -q|--num-probes <num>

Number of max probes for each hop (default: 3)

=item -x|--timeout <sec>

Probe response timeout in sec (default: 3)

=item -S|--syn

Set TCP SYN flag in packets

=item -A|--ack

Set TCP ACK flag in packets

=item -F|--fin

Set TCP FIN flag in packets

=item -P|--psh

Set TCP PSH flag in packets

=item -U|--urg

Set TCP URG flag in packets

=item -R|--rst

Set TCP RST flag in packets

=item -E|--ecn-syn

Send ECN SYN packets (RFC3168)

=item -t|--tos <tos>

Set the IP TOS field

=item -w|--whois <server>

Use a different AS whois DB server
(default: /etc/netsniff-ng/whois.conf)

=item -W|--wport <port>

Use a different port to AS whois server
(default: /etc/netsniff-ng/whois.conf)

=item --city-db <path>

Specifiy path for geoip city database

=item --country-db <path>

Specifiy path for geoip country database

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
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <ctype.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
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
#include "mtrand.h"
#include "ring_rx.h"
#include "built_in.h"

#define WHOIS_SERVER_SOURCE "/etc/netsniff-ng/whois.conf"

static int assemble_ipv6_tcp(uint8_t *packet, size_t len, int ttl,
			     struct sockaddr_in *sin) __attribute__ ((unused));

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

static struct option long_options[] = {
	{"host", required_argument, 0, 'H'},
	{"port", required_argument, 0, 'p'},
	{"init-ttl", required_argument, 0, 'f'},
	{"max-ttl", required_argument, 0, 'm'},
	{"numeric", no_argument, 0, 'n'},
	{"dns", no_argument, 0, 'N'},
	{"ipv4", no_argument, 0, '4'},
	{"ipv6", no_argument, 0, '6'},
	{"dev", required_argument, 0, 'd'},
	{"num-probes", required_argument, 0, 'q'},
	{"timeout", required_argument, 0, 'x'},
	{"syn", no_argument, 0, 'S'},
	{"ack", no_argument, 0, 'A'},
	{"urg", no_argument, 0, 'U'},
	{"fin", no_argument, 0, 'F'},
	{"psh", no_argument, 0, 'P'},
	{"rst", no_argument, 0, 'R'},
	{"ecn-syn", no_argument, 0, 'E'},
	{"tos", required_argument, 0, 't'},
	{"payload", required_argument, 0, 'X'},
	{"show-packet", no_argument, 0, 'Z'},
	{"nofrag", no_argument, 0, 'G'},
	{"totlen", required_argument, 0, 'l'},
	{"whois", required_argument, 0, 'w'},
	{"wport", required_argument, 0, 'W'},
	{"city-db", required_argument, 0, 'L'},
	{"country-db", required_argument, 0, 'K'},
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
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

static void header(void)
{
	printf("%s%s%s\n", colorize_start(bold), "ashunt "
	       VERSION_STRING, colorize_end());
}

static void help(void)
{

	printf("\nashunt %s, Autonomous System (AS) trace route utility\n",
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Usage: ashunt [options]\n");
	printf("Options:\n");
	printf(" -H|--host <host>        Host/IPv4/IPv6 to lookup AS route to\n");
	printf(" -p|--port <port>        Hosts port to lookup AS route to\n");
	printf(" -i|-d|--dev <device>    Networking device, i.e. eth0\n");
	printf(" -4|--ipv4               Use IPv4 requests (default)\n");
	printf(" -6|--ipv6               Use IPv6 requests\n");
	printf(" -n|--numeric            Do not do reverse DNS lookup for hops\n");
	printf(" -N|--dns                Do a reverse DNS lookup for hops\n");
	printf(" -f|--init-ttl <ttl>     Set initial TTL\n");
	printf(" -m|--max-ttl <ttl>      Set maximum TTL (default: 30)\n");
	printf(" -q|--num-probes <num>   Number of max probes for each hop (default: 3)\n");
	printf(" -x|--timeout <sec>      Probe response timeout in sec (default: 3)\n");
	printf(" -S|--syn                Set TCP SYN flag in packets\n");
	printf(" -A|--ack                Set TCP ACK flag in packets\n");
	printf(" -F|--fin                Set TCP FIN flag in packets\n");
	printf(" -P|--psh                Set TCP PSH flag in packets\n");
	printf(" -U|--urg                Set TCP URG flag in packets\n");
	printf(" -R|--rst                Set TCP RST flag in packets\n");
	printf(" -E|--ecn-syn            Send ECN SYN packets (RFC3168)\n");
	printf(" -t|--tos <tos>          Set the IP TOS field\n");
	printf(" -G|--nofrag             Set do not fragment bit\n");
	printf(" -X|--payload <string>   Specify a payload string to test DPIs\n");
	printf(" -Z|--show-packet        Show returned packet on each hop\n");
	printf(" -l|--totlen <len>       Specify total packet len\n");
	printf(" -w|--whois <server>     Use a different AS whois DB server\n");
	printf("                         (default: /etc/netsniff-ng/whois.conf)\n");
	printf(" -W|--wport <port>       Use a different port to AS whois server\n");
	printf("                         (default: /etc/netsniff-ng/whois.conf)\n");
	printf(" --city-db <path>        Specifiy path for geoip city database\n");
	printf(" --country-db <path>     Specifiy path for geoip country database\n");
	printf(" -v|--version            Print version\n");
	printf(" -h|--help               Print this help\n");
	printf("\n");
	printf("Examples:\n");
	printf("  IPv4 trace of AS with TCP ECN SYN probe:\n");
	printf("    ashunt -i eth0 -N -E -H netsniff-ng.org\n");
	printf("  IPv4 trace of AS with TCP SYN probe (this will most-likely pass):\n");
	printf("    ashunt -i eth0 -N -S -H netsniff-ng.org\n");
	printf("  IPv4 trace of AS with TCP FIN probe:\n");
	printf("    ashunt -i eth0 -N -F -H netsniff-ng.org\n");
	printf("  IPv4 trace of AS with Xmas probe:\n");
	printf("    ashunt -i eth0 -N -FPU -H netsniff-ng.org\n");
	printf("  IPv4 trace of AS with Null probe with ASCII payload:\n");
	printf("    ashunt -i eth0 -N -H netsniff-ng.org -X \"censor-me\" -Z\n");
	printf("  IPv6 trace of AS up to netsniff-ng.org:\n");
	printf("    ashunt -6 -S -i eth0 -H netsniff-ng.org\n");
	printf("\n");
	printf("Note:\n");
	printf("  If the TCP probe did not give any results, then ashunt will\n");
	printf("  automatically probe for classic ICMP packets! To gather more\n");
	printf("  information about ashunt's fetched AS numbers, see i.e.\n");
	printf("  http://bgp.he.net/AS<number>!\n");
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
	printf("\nashunt %s, AS trace route utility\n",
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
			packet[i] = (uint8_t) mt_rand_int32();
	} else {
		int lmin = min(len, strlen(payload));
		for (i = 0; i < lmin; ++i)
			packet[i] = (uint8_t) payload[i];
		for (i = lmin; i < len; ++i)
			packet[i] = (uint8_t) mt_rand_int32();
	}
}

static void assemble_tcp(uint8_t *packet, size_t len, int syn, int ack,
			 int urg, int fin, int rst, int psh, int ecn, int dport)
{
	struct tcphdr *tcph = (struct tcphdr *) packet;

	bug_on(len < sizeof(struct tcphdr));

	tcph->source = htons((uint16_t) mt_rand_int32());
	tcph->dest = htons((uint16_t) dport);
	tcph->seq = htonl(mt_rand_int32());
	tcph->ack_seq = (!!ack ? htonl(mt_rand_int32()) : 0);
	tcph->doff = 5;
	tcph->syn = !!syn;
	tcph->ack = !!ack;
	tcph->urg = !!urg;
	tcph->fin = !!fin;
	tcph->rst = !!rst;
	tcph->psh = !!psh;
	tcph->ece = !!ecn;
	tcph->cwr = !!ecn;
	tcph->window = htons((uint16_t) (100 + (mt_rand_int32() % 65435)));
	tcph->check = 0;
	tcph->urg_ptr = (!!urg ? htons((uint16_t) mt_rand_int32()) :  0);
}

/* returns: ipv4 id */
static int assemble_ipv4_tcp(uint8_t *packet, size_t len, int ttl,
			     int tos, const struct sockaddr *dst,
			     const struct sockaddr *src, int syn, int ack,
			     int urg, int fin, int rst, int psh, int ecn,
			     int nofrag, int dport, const char *payload)
{
	struct iphdr *iph = (struct iphdr *) packet;

	bug_on(!src || !dst);
	bug_on(src->sa_family != PF_INET || dst->sa_family != PF_INET);
	bug_on(len < sizeof(struct iphdr) + sizeof(struct tcphdr));

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = (uint8_t) tos;
	iph->tot_len = htons((uint16_t) len);
	iph->id = htons((uint16_t) mt_rand_int32());
	iph->frag_off = nofrag ? IP_DF : 0;
	iph->ttl = (uint8_t) ttl;
	iph->protocol = 6; /* TCP */
	iph->saddr = ((const struct sockaddr_in *) src)->sin_addr.s_addr;
	iph->daddr = ((const struct sockaddr_in *) dst)->sin_addr.s_addr;

	assemble_tcp(packet + sizeof(struct iphdr),
		     len - sizeof(struct iphdr), syn, ack, urg, fin, rst,
		     psh, ecn, dport);

	assemble_data(packet + sizeof(struct iphdr) + sizeof(struct tcphdr),
		      len - sizeof(struct iphdr) - sizeof(struct tcphdr),
		      payload);

	iph->check = csum((unsigned short *) packet,
			  ntohs(iph->tot_len) >> 1);

	return ntohs(iph->id);
}

/* returns: ipv6 flow label */
static int assemble_ipv6_tcp(uint8_t *packet, size_t len, int ttl,
			     struct sockaddr_in *sin)
{
	return 0;
}

static void assemble_icmp4(uint8_t *packet, size_t len)
{
	struct icmphdr *icmph = (struct icmphdr *) packet;

	bug_on(len < sizeof(struct icmphdr));

	icmph->type = ICMP_ECHO;
	icmph->code = 0;
	icmph->checksum = 0;
}

/* returns: ipv4 id */
static int assemble_ipv4_icmp4(uint8_t *packet, size_t len, int ttl,
			       int tos, const struct sockaddr *dst,
			       const struct sockaddr *src, int nofrag,
			       const char *payload)
{
	struct iphdr *iph = (struct iphdr *) packet;

	bug_on(!src || !dst);
	bug_on(src->sa_family != PF_INET || dst->sa_family != PF_INET);
	bug_on(len < sizeof(struct iphdr) + sizeof(struct tcphdr));

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = htons((uint16_t) len);
	iph->id = htons((uint16_t) mt_rand_int32());
	iph->frag_off = nofrag ? IP_DF : 0;
	iph->ttl = (uint8_t) ttl;
	iph->protocol = 1; /* ICMP4 */
	iph->saddr = ((const struct sockaddr_in *) src)->sin_addr.s_addr;
	iph->daddr = ((const struct sockaddr_in *) dst)->sin_addr.s_addr;

	assemble_icmp4(packet + sizeof(struct iphdr),
		       len - sizeof(struct iphdr));

	assemble_data(packet + sizeof(struct iphdr) + sizeof(struct icmphdr),
		      len - sizeof(struct iphdr) - sizeof(struct icmphdr),
		      payload);

	iph->check = csum((unsigned short *) packet,
			  ntohs(iph->tot_len) >> 1);

	return ntohs(iph->id);
}

static int assemble_packet_or_die(uint8_t *packet, size_t len, int ttl, int icmp,
				  const struct ash_cfg *cfg,
				  const struct sockaddr *dst,
				  const struct sockaddr *src)
{
	if (icmp)
		return assemble_ipv4_icmp4(packet, len, ttl, cfg->tos, dst, src,
					   cfg->nofrag, cfg->payload);
	else
		return assemble_ipv4_tcp(packet, len, ttl, cfg->tos, dst, src,
					 cfg->syn, cfg->ack, cfg->urg, cfg->fin,
					 cfg->rst, cfg->psh, cfg->ecn,
					 cfg->nofrag, atoi(cfg->port),
					 cfg->payload);
}

#define PKT_NOT_FOR_US	0
#define PKT_GOOD	1

static inline const char *make_n_a(const char *p)
{
	return p ? : "N/A";
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
			printf("%s in unkown AS", hbuff);
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
			printf("%s (%s) in unkown AS",
			       (hent ? hent->h_name : hbuff), hbuff);
		}
	}

	xfree(hbuff);

	return PKT_GOOD;
}

static int handle_packet(uint8_t *packet, size_t len, int ip, int ttl, int id,
			 struct sockaddr *own, int dns_resolv)
{
	return handle_ipv4_icmp(packet, len, ttl, id, own, dns_resolv);
}

static int do_trace(const struct ash_cfg *cfg)
{
	int ttl, query, fd = -1, one = 1, ret, fd_cap, ifindex;
	int is_okay = 0, id, timeout_poll;
	uint8_t *packet, *packet_rcv;
	ssize_t err, real_len;
	size_t len, len_rcv;
	struct addrinfo hints, *ahead, *ai;
	char *hbuff1, *hbuff2;
	struct sockaddr_storage ss, sd;
	struct sock_fprog bpf_ops;
	struct ring dummy_ring;
	struct pollfd pfd;

	mt_init_by_random_device();

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_NUMERICSERV;

	ret = getaddrinfo(cfg->host, cfg->port, &hints, &ahead);
	if (ret < 0) {
		whine("Cannot get address info!\n");
		return -EIO;
	}

	for (ai = ahead; ai != NULL && fd < 0; ai = ai->ai_next) {
		if (!((ai->ai_family == PF_INET6 && cfg->ip == 6) ||
		      (ai->ai_family == PF_INET && cfg->ip == 4)))
			continue;
		fd = socket(ai->ai_family, SOCK_RAW, ai->ai_protocol);
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

		break;
	}

	freeaddrinfo(ahead);

	if (fd < 0) {
		whine("Cannot create socket! Does remote support IPv%d?!\n",
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

	if (len >= device_mtu(cfg->dev))
		panic("Packet len exceeds device MTU!\n");

	packet = xmalloc(len);
	len_rcv = device_mtu(cfg->dev);
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
				     sizeof(sd));
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

	check_for_root_maybe_die();

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
					whine("Unknown option character "
					      "`0x%X\'!\n", optopt);
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

	header();

	tprintf_init();

	ret = aslookup_prepare(cfg.whois, cfg.whois_port);
	if (ret < 0)
		panic("Cannot resolve whois server!\n");

	if (path_country_db)
		gi_country = GeoIP_open(path_country_db, GEOIP_MMAP_CACHE);
	else
		gi_country = GeoIP_open_type(GEOIP_COUNTRY_EDITION,
					     GEOIP_MMAP_CACHE);

	if (path_city_db)
		gi_city = GeoIP_open(path_city_db, GEOIP_MMAP_CACHE);
	else
		gi_city = GeoIP_open_type(GEOIP_CITY_EDITION_REV1,
					  GEOIP_MMAP_CACHE);

	if (!gi_country || !gi_city)
		panic("Cannot open GeoIP database! Wrong path?!\n");

	GeoIP_set_charset(gi_country, GEOIP_CHARSET_UTF8);
	GeoIP_set_charset(gi_city, GEOIP_CHARSET_UTF8);

	ret = do_trace(&cfg);

	GeoIP_delete(gi_city);
	GeoIP_delete(gi_country);

	tprintf_cleanup();

	if (cfg.whois_port)
		xfree(cfg.whois_port);
	if (cfg.whois)
		xfree(cfg.whois);
	if (cfg.dev)
		xfree(cfg.dev);
	if (cfg.host)
		xfree(cfg.host);
	if (cfg.port)
		xfree(cfg.port);
	if (cfg.payload)
		xfree(cfg.payload);
	if (path_city_db)
		xfree(path_city_db);
	if (path_country_db)
		xfree(path_country_db);

	return ret;
}

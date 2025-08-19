/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2011 - 2013 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#define _BSD_SOURCE
#define _DEFAULT_SOURCE
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
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <sys/time.h>
#include <arpa/inet.h>
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
#include "csum.h"
#include "sock.h"
#include "geoip.h"
#include "ring.h"
#include "built_in.h"

/* ======== macros ======== */
#define CTX_DEFAULT_DEV "eth0"
#define CTX_DEFAULT_PORTSTR "80"
#define CTX_DEFAULT_INIT_TTL 1
#define CTX_DEFAULT_MAX_TTL 30
#define CTX_DEFAULT_DO_DNS_RESOLUTION false
#define CTX_DEFAULT_NUM_PROBES 2
#define CTX_DEFAULT_NUM_PACKETS 3
#define CTX_DEFAULT_TIMEOUT 2
#define CTX_DEFAULT_IPV4_TOS 0
#define CTX_DEFAULT_PROTO IPPROTO_IP
#define CTX_DEFAULT_DO_GEO_LOOKUP false
#define CTX_DEFAULT_DO_SHOW_PACKET false

#define QUOTE(X) #X
#define STRINGIFY(X) QUOTE(X)


/* ======== type definitions ======== */
typedef enum {
	TRACEROUTE_NO_REPLY,
	TRACEROUTE_OK_REPLY,
	TRACEROUTE_DST_REACHED,
} traceroute_result;

struct tcp_pkt_id {
	uint32_t seq;
	uint16_t src_port, dst_port;
};

struct icmp_pkt_id {
	uint16_t id;
	uint16_t seq;
};

struct pkt_id {
	uint32_t ip_id;
	int inner_proto;
	
	union {
		struct tcp_pkt_id tcp;
		struct icmp_pkt_id icmp; 
	} inner;
};

struct ctx {
	char *host, *port, *dev, *payload, *bind_addr;
	size_t totlen, rcvlen;
	socklen_t sd_len;
	int init_ttl, max_ttl, dport, num_probes, num_packets, timeout;
	int syn, ack, ecn, fin, psh, rst, urg, tos, nofrag, proto;
	bool do_geo_lookup, do_dns_resolution, do_show_packet;
};

struct proto_ops {
	void (*assembler)(uint8_t *packet, size_t len, int ttl, int proto,
			          const struct ctx *ctx,
			          const struct sockaddr *dst, const struct sockaddr *src,
			          struct pkt_id *id);
	const struct sock_filter *filter;
	unsigned int flen;
	size_t min_len_tcp, min_len_icmp;
	traceroute_result (*check)(uint8_t *packet, size_t len, int ttl,
	                           const struct pkt_id *id,
		                       const struct sockaddr *ss, const struct sockaddr *sd);
	void (*handler)(uint8_t *packet, size_t len,
	                bool do_dns_resolution, bool do_geo_lookup);
};





/* ======== protocol handler functions ======== */
/* IPv4 */
static void assemble_ipv4(uint8_t *packet, size_t len, int ttl, int proto,
			              const struct ctx *ctx,
			              const struct sockaddr *dst, const struct sockaddr *src,
			              struct pkt_id *pkt_id);

static traceroute_result check_ipv4(uint8_t *packet, size_t len, int ttl,
                                    const struct pkt_id *pkt_id,
                                    const struct sockaddr *ss, const struct sockaddr *sd);

static void handle_ipv4(uint8_t *packet, size_t len, bool do_dns_resolution, bool do_geo_lookup);


/* IPv6 */	 
static void assemble_ipv6(uint8_t *packet, size_t len, int ttl, int proto,
			              const struct ctx *ctx,
			              const struct sockaddr *dst, const struct sockaddr *src,
			              struct pkt_id *pkt_id);
			         
static traceroute_result check_ipv6(uint8_t *packet, size_t len, int ttl,
                                    const struct pkt_id *pkt_id,
                                    const struct sockaddr *ss, const struct sockaddr *sd);

static void handle_ipv6(uint8_t *packet, size_t len, bool do_dns_resolution, bool do_geo_lookup);



/* ======== static variables ======== */
static sig_atomic_t sigint = 0;
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

static const char *copyright =
	"Please report bugs at https://github.com/netsniff-ng/netsniff-ng/issues\n"
	"Copyright (C) 2011-2013 Daniel Borkmann <dborkma@tik.ee.ethz.ch>\n"
	"Swiss federal institute of technology (ETH Zurich)\n"
	"License: GNU GPL version 2.0\n"
	"This is free software: you are free to change and redistribute it.\n"
	"There is NO WARRANTY, to the extent permitted by law.";

/*
 * generated with tcpdump;
 *
 * ip and ( ( icmp[icmptype] == 0 ) or ( icmp[icmptype] == 3 ) or ( icmp[icmptype] == 11 ) or ( ((tcp[13:1] & 4) == 4) or ((tcp[13:1] & 18) == 18) ))
 *
 * allows
 *   ICMP echo reply
 *   OR
 *   ICMP destination unreachable
 *   OR
 *   ICMP time exceeded
 *   OR
 *   TCP with RST OR SYN+ACK flags set
 */
static const struct sock_filter ipv4_filter[] = {
	{ 0x28,  0,  0, 0x0000000c },
	{ 0x15,  0, 20, 0x00000800 },
	{ 0x30,  0,  0, 0x00000017 },
	{ 0x15,  0,  7, 0x00000001 },
	{ 0x28,  0,  0, 0x00000014 },
	{ 0x45, 16,  0, 0x00001fff },
	{ 0xb1,  0,  0, 0x0000000e },
	{ 0x50,  0,  0, 0x0000000e },
	{ 0x15, 12,  0, 0x00000000 },
	{ 0x15, 11,  0, 0x00000003 },
	{ 0x15, 10, 11, 0x0000000b },
	{ 0x15,  0, 10, 0x00000006 },
	{ 0x28,  0,  0, 0x00000014 },
	{ 0x45,  8,  0, 0x00001fff },
	{ 0xb1,  0,  0, 0x0000000e },
	{ 0x50,  0,  0, 0x0000001b },
	{ 0x54,  0,  0, 0x00000004 },
	{ 0x15,  3,  0, 0x00000004 },
	{ 0x50,  0,  0, 0x0000001b },
	{ 0x54,  0,  0, 0x00000012 },
	{ 0x15,  0,  1, 0x00000012 },
	{ 0x06,  0,  0, 0x00040000 },
	{ 0x06,  0,  0, 0x00000000 },
};

/*
 * generated with tcpdump;
 *
 * ip6 and (((ip6[6] == 58) and (( ip6[40] == 129 ) or ( ip6[40] == 3 ) or ( ip6[40] == 3 ))) or ((ip6[6] == 6) and ( ((ip6[40+13] & 4) == 4) or ((ip6[40+13] & 18) == 18) )))
 *
 * allows
 *   ICMPv6 echo reply
 *   OR
 *   ICMPv6 destination unreachable
 *   OR
 *   ICMPv6 time exceeded
 *   OR
 *   TCP with RST OR SYN+ACK flags set
 */
static const struct sock_filter ipv6_filter[] = {
	{ 0x28,  0,  0, 0x0000000c },
	{ 0x15,  0, 13, 0x000086dd },
	{ 0x30,  0,  0, 0x00000014 },
	{ 0x15,  0,  3, 0x0000003a },
	{ 0x30,  0,  0, 0x00000036 },
	{ 0x15,  8,  0, 0x00000081 },
	{ 0x15,  7,  8, 0x00000003 },
	{ 0x15,  0,  7, 0x00000006 },
	{ 0x30,  0,  0, 0x00000043 },
	{ 0x54,  0,  0, 0x00000004 },
	{ 0x15,  3,  0, 0x00000004 },
	{ 0x30,  0,  0, 0x00000043 },
	{ 0x54,  0,  0, 0x00000012 },
	{ 0x15,  0,  1, 0x00000012 },
	{ 0x06,  0,  0, 0x00040000 },
	{ 0x06,  0,  0, 0x00000000 },
};

static const struct proto_ops af_ops[] = {
	[IPPROTO_IP]	=	{
			.assembler	=	assemble_ipv4,
			.handler	=	handle_ipv4,
			.check		=	check_ipv4,
			.filter		=	ipv4_filter,
			.flen		=	array_size(ipv4_filter),
			.min_len_tcp	=	sizeof(struct iphdr) + sizeof(struct tcphdr),
			.min_len_icmp	=	sizeof(struct iphdr) + sizeof(struct icmphdr),
		},
	[IPPROTO_IPV6]	= 	{
			.assembler	=	assemble_ipv6,
			.handler	=	handle_ipv6,
			.check		=	check_ipv6,
			.filter		=	ipv6_filter,
			.flen		=	array_size(ipv6_filter),
			.min_len_tcp	=	sizeof(struct ip6_hdr) + sizeof(struct tcphdr),
			.min_len_icmp	=	sizeof(struct ip6_hdr) + sizeof(struct icmp6hdr),
		},
};

static void signal_handler(int number)
{
	switch (number) {
	case SIGINT:
	case SIGQUIT:
	case SIGTERM:
		sigint = 1;
	default:
		break;
	}
}

static void __noreturn help(void)
{
	printf("astraceroute %s, autonomous system trace route utility\n", VERSION_STRING);
	puts("http://www.netsniff-ng.org\n\n"
	     "Usage: astraceroute [options]\n"
	     "Options:\n"
	     " -H|--host <host>        Host/IPv4/IPv6 to lookup AS route to (required)\n"
	     " -p|--port <port>        Destination port used in the TCP packet (default: " CTX_DEFAULT_PORTSTR ")\n"
	     " -i|-d|--dev <device>    Networking device, e.g. eth0 (default: " CTX_DEFAULT_DEV ")\n"
	     " -b|--bind <IP>          IP address to bind to, Must specify -6 for an IPv6 address\n"
	     " -f|--init-ttl <ttl>     Set initial TTL (default: " STRINGIFY(CTX_DEFAULT_INIT_TTL) ")\n"
	     " -m|--max-ttl <ttl>      Set maximum TTL (default: " STRINGIFY(CTX_DEFAULT_MAX_TTL) ")\n"
	     " -q|--num-probes <num>   Number of max probes for each hop (default: " STRINGIFY(CTX_DEFAULT_NUM_PROBES) ")\n"
	     " -s|--num-packets <num>  Number of packets to be sent in each probe (default: " STRINGIFY(CTX_DEFAULT_NUM_PACKETS) ")\n"
	     " -x|--timeout <sec>      Packet response timeout in sec (default: " STRINGIFY(CTX_DEFAULT_TIMEOUT) ")\n"
	     " -X|--payload <string>   Specify a payload string to test DPIs\n"
	     " -l|--totlen <len>       Specify total packet len\n"
	     " -4|--ipv4               Use IPv4-only requests\n"
	     " -6|--ipv6               Use IPv6-only requests\n"
	     " -n|--numeric            Do not do reverse DNS lookup for hops (default)\n"
	     " -u|--update             Update GeoIP databases\n"
	     " -L|--latitude           Show latitude and longitude\n"
	     " -N|--dns                Do a reverse DNS lookup for hops\n"
	     " -S|--syn                Set TCP SYN flag\n"
	     " -A|--ack                Set TCP ACK flag\n"
	     " -F|--fin                Set TCP FIN flag\n"
	     " -P|--psh                Set TCP PSH flag\n"
	     " -U|--urg                Set TCP URG flag\n"
	     " -R|--rst                Set TCP RST flag\n"
	     " -E|--ecn-syn            Send ECN SYN packets (RFC3168)\n"
	     " -t|--tos <tos>          Set the IP TOS field (IPv4 only, default: " STRINGIFY(CTX_DEFAULT_IPV4_TOS) ")\n"
	     " -G|--nofrag             Set do not fragment bit (IPv4 only)\n"
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
	     "  http://bgp.he.net/AS<number>!\n");
	puts(copyright);
	die();
}

static void __noreturn version(void)
{
	printf("astraceroute %s, Git id: %s\n", VERSION_LONG, GITVERSION);
	puts("autonomous system trace route utility\n"
	     "http://www.netsniff-ng.org\n");
	puts(copyright);
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

static void __assemble_icmp4(uint8_t *packet, size_t len, const struct ctx *ctx,
			                 struct pkt_id *pkt_id)
{
	uint8_t *data;
	size_t data_len;
	struct icmphdr *icmph = (struct icmphdr *) packet;

	bug_on(len < sizeof(*icmph));

	icmph->type = ICMP_ECHO;
	icmph->code = 0;
	icmph->checksum = 0;
	
	pkt_id->inner.icmp.id = (uint16_t)rand();
	pkt_id->inner.icmp.seq = (uint16_t)rand();
	
	icmph->un.echo.id = htons(pkt_id->inner.icmp.id);
	icmph->un.echo.sequence = htons(pkt_id->inner.icmp.seq);

	data = packet + sizeof(*icmph);
	data_len = len - sizeof(*icmph);

	__assemble_data(data, data_len, ctx->payload);

	icmph->checksum = csum((unsigned short *)packet, len / 2);
}

static void __assemble_icmp6(uint8_t *packet, size_t len, const struct ctx *ctx,
			                 const struct sockaddr *dst, const struct sockaddr *src,
			                 struct pkt_id *pkt_id)
{
	uint8_t *data;
	size_t data_len;
	struct ip6_hdr ip6hdr;
	struct icmp6hdr *icmp6h = (struct icmp6hdr *) packet;

	bug_on(len < sizeof(*icmp6h));

	icmp6h->icmp6_type = ICMPV6_ECHO_REQUEST;
	icmp6h->icmp6_code = 0;
	icmp6h->icmp6_cksum = 0;
	
	pkt_id->inner.icmp.id = (uint16_t)rand();
	pkt_id->inner.icmp.seq = (uint16_t)rand();
	
	icmp6h->icmp6_identifier = htons(pkt_id->inner.icmp.id);
	icmp6h->icmp6_sequence = htons(pkt_id->inner.icmp.seq);

	data = packet + sizeof(*icmp6h);
	data_len = len - sizeof(*icmp6h);

	__assemble_data(data, data_len, ctx->payload);

	memcpy(&ip6hdr.ip6_src, &((const struct sockaddr_in6 *) src)->sin6_addr,
	       sizeof(ip6hdr.ip6_src));
	       
	memcpy(&ip6hdr.ip6_dst, &((const struct sockaddr_in6 *) dst)->sin6_addr,
	       sizeof(ip6hdr.ip6_dst));


	icmp6h->icmp6_cksum =
		p6_csum(&ip6hdr, packet, sizeof(*icmp6h) + data_len, IPPROTO_ICMPV6);
}

static size_t __assemble_tcp_header(struct tcphdr *tcph, const struct ctx *ctx,
				                    struct pkt_id *pkt_id)
{

	pkt_id->inner.tcp.seq = (uint32_t) rand();
	pkt_id->inner.tcp.src_port = (uint16_t) rand();
	pkt_id->inner.tcp.dst_port = ctx->dport;

	tcph->source = htons(pkt_id->inner.tcp.src_port);
	tcph->dest = htons((uint16_t) ctx->dport);

	tcph->seq = htonl(pkt_id->inner.tcp.seq);
	tcph->ack_seq = (!!ctx->ack ? htonl(rand()) : 0);

	tcph->doff = 5;

	tcph->syn = !!ctx->syn;
	tcph->ack = !!ctx->ack;
	tcph->urg = !!ctx->urg;
	tcph->fin = !!ctx->fin;
	tcph->rst = !!ctx->rst;
	tcph->psh = !!ctx->psh;
	tcph->ece = !!ctx->ecn;
	tcph->cwr = !!ctx->ecn;

	tcph->window = htons((uint16_t) (100 + (rand() % 65435)));
	tcph->check = 0;
	tcph->urg_ptr = (!!ctx->urg ? htons((uint16_t) rand()) :  0);

	return tcph->doff * 4;
}

static void __assemble_tcp(uint8_t *packet, size_t len, const struct ctx *ctx,
			               const struct sockaddr *dst, const struct sockaddr *src,
			               struct pkt_id *pkt_id)
{
	uint8_t *data;
	size_t tcp_len, data_len;
	struct ip iphdr;
	struct tcphdr *tcph = (struct tcphdr *) packet;

	bug_on(len < sizeof(*tcph));

	tcp_len = __assemble_tcp_header(tcph, ctx, pkt_id);

	data = packet + tcp_len;
	data_len = len - tcp_len;

	__assemble_data(data, data_len, ctx->payload);

	memcpy(&iphdr.ip_src, &((const struct sockaddr_in *) src)->sin_addr.s_addr,
	       sizeof(iphdr.ip_src));
	memcpy(&iphdr.ip_dst, &((const struct sockaddr_in *) dst)->sin_addr.s_addr,
	       sizeof(iphdr.ip_dst));

	tcph->check = p4_csum(&iphdr, packet, tcp_len + data_len, IPPROTO_TCP);
}

static void __assemble_tcp6(uint8_t *packet, size_t len, const struct ctx *ctx,
			                const struct sockaddr *dst, const struct sockaddr *src,
			                struct pkt_id *pkt_id)
{
	uint8_t *data;
	size_t tcp_len, data_len;
	struct ip6_hdr ip6hdr;
	struct tcphdr *tcph = (struct tcphdr *) packet;

	bug_on(len < sizeof(*tcph));

	tcp_len = __assemble_tcp_header(tcph, ctx, pkt_id);

	data = packet + tcp_len;
	data_len = len - tcp_len;

	__assemble_data(data, data_len, ctx->payload);


	memcpy(&ip6hdr.ip6_src, &((const struct sockaddr_in6 *) src)->sin6_addr,
	       sizeof(ip6hdr.ip6_src));
	       
	memcpy(&ip6hdr.ip6_dst, &((const struct sockaddr_in6 *) dst)->sin6_addr,
	       sizeof(ip6hdr.ip6_dst));


	tcph->check =
		p6_csum(&ip6hdr, packet, tcp_len + data_len, IPPROTO_TCP);
}

static void assemble_ipv4(uint8_t *packet, size_t len, int ttl, int proto,
			              const struct ctx *ctx,
			              const struct sockaddr *dst, const struct sockaddr *src,
			              struct pkt_id *pkt_id)
{
	uint8_t *data;
	size_t data_len;
	struct iphdr *iph = (struct iphdr *) packet;

	bug_on(!src || !dst);
	bug_on(src->sa_family != AF_INET || dst->sa_family != AF_INET);
	bug_on(len < sizeof(*iph) + min(sizeof(struct tcphdr),
					sizeof(struct icmphdr)));

	pkt_id->ip_id = (uint16_t) rand();

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = (uint8_t) ctx->tos;

	iph->tot_len = htons((uint16_t) len);
	iph->id = htons(pkt_id->ip_id);

	iph->frag_off = ctx->nofrag ? IP_DF : 0;
	iph->ttl = (uint8_t) ttl;

	iph->saddr = ((const struct sockaddr_in *) src)->sin_addr.s_addr;
	iph->daddr = ((const struct sockaddr_in *) dst)->sin_addr.s_addr;

	iph->protocol = (uint8_t) proto;
	iph->check = 0;

	data = packet + sizeof(*iph);
	data_len = len - sizeof(*iph);
	
	pkt_id->inner_proto = proto;
	
	switch (proto) {
	case IPPROTO_TCP:
		__assemble_tcp(data, data_len, ctx, dst, src, pkt_id);
		break;
	case IPPROTO_ICMP:
		__assemble_icmp4(data, data_len, ctx, pkt_id);
		break;
	default:
		bug();
	}

	iph->check = csum((unsigned short *) packet, len / 2);
}

static void assemble_ipv6(uint8_t *packet, size_t len, int ttl, int proto,
			              const struct ctx *ctx,
			              const struct sockaddr *dst, const struct sockaddr *src,
			              struct pkt_id *pkt_id)
{
	uint8_t *data;
	size_t data_len;
	struct ip6_hdr *ip6h = (struct ip6_hdr *) packet;

	bug_on(!src || !dst);
	bug_on(src->sa_family != AF_INET6 || dst->sa_family != AF_INET6);
	bug_on(len < sizeof(*ip6h) + min(sizeof(struct tcphdr),
					 sizeof(struct icmp6hdr)));
	
	pkt_id->ip_id = rand() & 0x000fffff;
	
	ip6h->ip6_flow = htonl(pkt_id->ip_id);
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
	
	pkt_id->inner_proto = proto;

	switch (proto) {
	case IPPROTO_TCP:
		__assemble_tcp6(data, data_len, ctx, dst, src, pkt_id);
		break;
	case IPPROTO_ICMPV6:
		__assemble_icmp6(data, data_len, ctx, dst, src, pkt_id);
		break;
	default:
		bug();
	}
}

static bool __tcp_header_is_ours(const struct tcphdr *tcph, const struct pkt_id *pkt_id)
{
	if (ntohs(tcph->source) != pkt_id->inner.tcp.src_port)
		return false;
			
	if (ntohs(tcph->dest) != pkt_id->inner.tcp.dst_port)
		return false;
		
	if (ntohl(tcph->seq) != pkt_id->inner.tcp.seq)
		return false;
			
	return true;
}

static bool __tcp_reply_is_ok(const struct tcphdr *tcph, const struct pkt_id *pkt_id)
{
	
	if (ntohs(tcph->source) != pkt_id->inner.tcp.dst_port)
		return false;
			
	if (ntohs(tcph->dest) != pkt_id->inner.tcp.src_port)
		return false;
		
	if (ntohl(tcph->ack_seq) != pkt_id->inner.tcp.seq+1)
		return false;
		
	if (!(tcph->rst) && !(tcph->syn && tcph->ack))
		return false;
	
	return true;
}

static traceroute_result check_ipv4(uint8_t *packet, size_t len, int ttl __maybe_unused,
		                            const struct pkt_id *pkt_id,
		                            const struct sockaddr *ss, const struct sockaddr *sd)
{	
	
	struct iphdr *iph = (struct iphdr *) packet;

	if (len < sizeof(*iph))
		return TRACEROUTE_NO_REPLY;

	if (iph->daddr != ((const struct sockaddr_in *) ss)->sin_addr.s_addr)
		return TRACEROUTE_NO_REPLY;	
	
	if (iph->protocol == IPPROTO_ICMP) {
	
		struct icmphdr *icmph = (struct icmphdr *) (packet + sizeof(*iph));
		struct iphdr *iph_inner = (struct iphdr *) (packet + sizeof(*iph) + sizeof(*icmph));
		
		if (len < sizeof(*iph) + sizeof(*icmph) + sizeof(*iph_inner))
			return TRACEROUTE_NO_REPLY;
		
		if (icmph->type == ICMP_TIME_EXCEEDED) {
			
			if (icmph->code != ICMP_EXC_TTL)
				return TRACEROUTE_NO_REPLY;

			if (ntohs(iph_inner->id) != pkt_id->ip_id)
				return TRACEROUTE_NO_REPLY;
				
			if (iph_inner->protocol != pkt_id->inner_proto)
				return TRACEROUTE_NO_REPLY;
				
			return TRACEROUTE_OK_REPLY;
							
		} else if (icmph->type == ICMP_ECHOREPLY) {
			
			if (pkt_id->inner_proto != IPPROTO_ICMP) 
				return TRACEROUTE_NO_REPLY;
		
			if (iph->saddr != ((const struct sockaddr_in *) sd)->sin_addr.s_addr)
				return TRACEROUTE_NO_REPLY;

			if (ntohs(icmph->un.echo.id) != pkt_id->inner.icmp.id
			    || ntohs(icmph->un.echo.sequence) != pkt_id->inner.icmp.seq)
				return TRACEROUTE_NO_REPLY;
			
			return TRACEROUTE_DST_REACHED;
			
		} else if (icmph->type == ICMP_DEST_UNREACH) {
			
			if (icmph->code == ICMP_PORT_UNREACH) {
				
				if (pkt_id->inner_proto != IPPROTO_TCP)
					return TRACEROUTE_NO_REPLY;
				
				if (iph->saddr != ((const struct sockaddr_in *) sd)->sin_addr.s_addr)
					return TRACEROUTE_NO_REPLY;
					
				if (iph_inner->protocol != pkt_id->inner_proto)
					return TRACEROUTE_NO_REPLY;
				
				/*
				 * RFC1122 requires at least 8 bytes after the IP header (section 3.2.2)
				 * to be sent back with ICMP errors, so it should be fine
				 * only source port, destination port, and sequence number are checked;
				 * which is exactly the first 8 bytes of the TCP header;
				 * this check should not even be here, but who knows?
				 */
				if (len < sizeof(*iph) + sizeof(*icmph) + sizeof(*iph_inner) + 8)
					return TRACEROUTE_NO_REPLY; 
				 
				struct tcphdr *tcph
					= (struct tcphdr *) (packet + sizeof(*iph) + sizeof(*icmph) + sizeof(*iph_inner));
				
				if (__tcp_header_is_ours(tcph, pkt_id))
					return TRACEROUTE_DST_REACHED;
					
			}
		}

	} else if (iph->protocol == IPPROTO_TCP) {
	
		if (pkt_id->inner_proto != IPPROTO_TCP)
			return TRACEROUTE_NO_REPLY;
		
		if (iph->saddr != ((const struct sockaddr_in *) sd)->sin_addr.s_addr)
			return TRACEROUTE_NO_REPLY;
		
		struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof(*iph));
		if (len < sizeof(*iph) + sizeof(*tcph))
			return TRACEROUTE_NO_REPLY;

		if (__tcp_reply_is_ok(tcph, pkt_id))
			return TRACEROUTE_DST_REACHED;
	}
	
	
	return TRACEROUTE_NO_REPLY;
}

static void handle_ipv4(uint8_t *packet, size_t len __maybe_unused,
			            bool do_dns_resolution, bool do_geo_lookup)
{
	char hbuff[NI_MAXHOST];
	struct iphdr *iph = (struct iphdr *) packet;
	struct sockaddr_in sd;
	const char *as = NULL, *country = NULL;
	char *city = NULL;

	memset(hbuff, 0, sizeof(hbuff));
	memset(&sd, 0, sizeof(sd));
	sd.sin_family = AF_INET;
	sd.sin_addr.s_addr = iph->saddr;

	getnameinfo((struct sockaddr *) &sd, sizeof(sd),
		    hbuff, sizeof(hbuff), NULL, 0, NI_NUMERICHOST);

	as = geoip4_as_name(&sd);
	country = geoip4_country_name(&sd);
	city = geoip4_city_name(&sd);

	if (do_dns_resolution) {
		struct hostent *hent = gethostbyaddr(&sd.sin_addr, sizeof(sd.sin_addr), AF_INET);
		
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
	
	if (do_geo_lookup)
		printf(" (%f/%f)", geoip4_latitude(&sd), geoip4_longitude(&sd));

	free(city);
}

static traceroute_result check_ipv6(uint8_t *packet, size_t len, int ttl __maybe_unused,
				                    const struct pkt_id *pkt_id,
				                    const struct sockaddr *ss, const struct sockaddr *sd)
{
	struct ip6_hdr *ip6h = (struct ip6_hdr *) packet;
	
	if (len < sizeof(*ip6h))
		return TRACEROUTE_NO_REPLY;

	if (memcmp(&ip6h->ip6_dst, &(((const struct sockaddr_in6 *)ss)->sin6_addr), sizeof(ip6h->ip6_dst)))
		return TRACEROUTE_NO_REPLY;
		
	
	if (ip6h->ip6_nxt == IPPROTO_ICMPV6) {
	
		struct icmp6hdr *icmp6h = (struct icmp6hdr *) (packet + sizeof(*ip6h));
		struct ip6_hdr *ip6h_inner = (struct ip6_hdr *) (packet + sizeof(*ip6h) + sizeof(*icmp6h));
		
		if (len < sizeof(*ip6h) + sizeof(*icmp6h) + sizeof(*ip6h_inner))
			return TRACEROUTE_NO_REPLY;
		
		if (icmp6h->icmp6_type == ICMPV6_TIME_EXCEED) {
			
			if (icmp6h->icmp6_code != ICMPV6_EXC_HOPLIMIT)
				return TRACEROUTE_NO_REPLY;
		
			if ((ntohl(ip6h_inner->ip6_flow) & 0x000fffff) != pkt_id->ip_id)
				return TRACEROUTE_NO_REPLY;
				
			if (ip6h_inner->ip6_nxt != pkt_id->inner_proto)
				return TRACEROUTE_NO_REPLY;
				
			return TRACEROUTE_OK_REPLY;
				
		} else if (icmp6h->icmp6_type == ICMPV6_ECHO_REPLY) {
				
			if (pkt_id->inner_proto != IPPROTO_ICMPV6)
				return TRACEROUTE_NO_REPLY;
		
			if (memcmp(&ip6h->ip6_src, &(((const struct sockaddr_in6 *)sd)->sin6_addr), sizeof(ip6h->ip6_src)))
				return TRACEROUTE_NO_REPLY;

			if (ntohs(icmp6h->icmp6_identifier) != pkt_id->inner.icmp.id
			    || ntohs(icmp6h->icmp6_sequence) != pkt_id->inner.icmp.seq)
				return TRACEROUTE_NO_REPLY;
			
			return TRACEROUTE_DST_REACHED;
			
		} else if (icmp6h->icmp6_type == ICMPV6_DEST_UNREACH) {
			
			if (icmp6h->icmp6_code == ICMPV6_PORT_UNREACH) {
				
				if (pkt_id->inner_proto != IPPROTO_TCP)
					return TRACEROUTE_NO_REPLY;
				
				if (memcmp(&ip6h->ip6_src, &(((const struct sockaddr_in6 *)sd)->sin6_addr), sizeof(ip6h->ip6_src)))
					return TRACEROUTE_NO_REPLY;
					
				if (ip6h->ip6_nxt != pkt_id->inner_proto)
					return TRACEROUTE_NO_REPLY;
				
				 /*
				 * RFC4443 (Internet Control Message Protocol (ICMPv6))
				 * states (section 3.1) that ICMP error message should include
				 * 	"as much of invoking packet as possible
				 	without the ICMPv6 packet exceeding the minimum IPv6 MTU"
				 * only source port, destination port, and sequence number are checked;
				 * which is exactly the first 8 bytes of the TCP header;
				 * this check should not even be here, but who knows?
				 */
				 if (len < sizeof(*ip6h) + sizeof(*icmp6h) + sizeof(*ip6h_inner) + 8)
					return TRACEROUTE_NO_REPLY;
				 
				struct tcphdr *tcph
					= (struct tcphdr *) (packet + sizeof(*ip6h) + sizeof(*icmp6h) + sizeof(*ip6h_inner));
				
				if (__tcp_header_is_ours(tcph, pkt_id))
					return TRACEROUTE_DST_REACHED;	
			}
		}
		
	}
	else if (ip6h->ip6_nxt == IPPROTO_TCP) {
		
		if (pkt_id->inner_proto != IPPROTO_TCP)
			return TRACEROUTE_NO_REPLY;
		
		if (memcmp(&ip6h->ip6_src, &(((const struct sockaddr_in6 *)sd)->sin6_addr), sizeof(ip6h->ip6_src)))
			return TRACEROUTE_NO_REPLY;
		
		struct tcphdr *tcph = (struct tcphdr *) (packet + sizeof(*ip6h));
		if (len < sizeof(*ip6h) + sizeof(*tcph))
			return TRACEROUTE_NO_REPLY;
		
		if (__tcp_reply_is_ok(tcph, pkt_id))
			return TRACEROUTE_DST_REACHED;
	}

	return TRACEROUTE_NO_REPLY;
}

static void handle_ipv6(uint8_t *packet, size_t len __maybe_unused,
			            bool do_dns_resolution, bool do_geo_lookup)
{
	char hbuff[NI_MAXHOST];
	struct ip6_hdr *ip6h = (struct ip6_hdr *) packet;
	struct sockaddr_in6 sd;
	const char *as = NULL, *country = NULL;
	char *city = NULL;

	memset(hbuff, 0, sizeof(hbuff));
	memset(&sd, 0, sizeof(sd));
	sd.sin6_family = AF_INET6;
	memcpy(&sd.sin6_addr, &ip6h->ip6_src, sizeof(ip6h->ip6_src));

	getnameinfo((struct sockaddr *) &sd, sizeof(sd),
		    hbuff, sizeof(hbuff), NULL, 0, NI_NUMERICHOST);

	as = geoip6_as_name(&sd);
	country = geoip6_country_name(&sd);
	city = geoip6_city_name(&sd);

	if (do_dns_resolution) {
		struct hostent *hent = gethostbyaddr(&sd.sin6_addr, sizeof(sd.sin6_addr), AF_INET6);
		
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
	
	if (do_geo_lookup)
		printf(" (%f/%f)", geoip6_latitude(&sd), geoip6_longitude(&sd));

	free(city);
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

static const char *proto_short(int proto)
{
	switch (proto) {
	case IPPROTO_TCP:
		return "t";
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		return "i";
	default:
		return "?";
	}
}

static int __address_family_for_proto(const int proto)
{
	switch (proto) {
	case IPPROTO_IP:
		return AF_INET;
	case IPPROTO_IPV6:
		return AF_INET6;
	default:
		bug();
	}
}

static int __ip_version_for_proto(const int proto)
{
	switch (proto) {
	case IPPROTO_IP:
		return 4;
	case IPPROTO_IPV6:
		return 6;
	default:
		bug();
	}
}

static int __icmp_proto_for_ip_proto(const int ip_proto)
{
	switch (ip_proto) {
	case IPPROTO_IP:
		return IPPROTO_ICMP;	
	case IPPROTO_IPV6:
		return IPPROTO_ICMPV6;	
	default:
		bug();
	}
}

static int get_remote_fd(struct ctx *ctx, struct sockaddr_storage *ss,
			             struct sockaddr_storage *sd)
{
	int fd = -1, ret, one = 1, af = __address_family_for_proto(ctx->proto);
	struct addrinfo hints, *ahead, *ai;
	unsigned char bind_ip[sizeof(struct in6_addr)];
	int last_errno = 0;
	
	ctx->dport = strtoul(ctx->port, NULL, 10);
	if (ctx->dport < 0 || ctx->dport > 65535)
		panic("destination port not in valid range: %s\n", ctx->port);
	
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = af;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_NUMERICSERV;

	ret = getaddrinfo(ctx->host, ctx->port, &hints, &ahead);
	if (ret < 0)
		panic("could not get address of %s: [%d] %s\n"
		      "does the target support IPv%d?\n",
		      ctx->host, ret, gai_strerror(ret),
		      __ip_version_for_proto(ctx->proto));

	for (ai = ahead; ai != NULL && fd < 0; ai = ai->ai_next) {
	
		fd = socket(ai->ai_family, SOCK_RAW, IPPROTO_RAW);
		if (fd < 0) {
			last_errno = errno;
			continue;
		}
		
		memset(ss, 0, sizeof(*ss));
		ret = device_address(ctx->dev, ai->ai_family, ss);
		if (ret < 0 && !ctx->bind_addr)
			panic("could not get address of device %s\n", ctx->dev);

		if (ctx->bind_addr) {
			if (inet_pton(af, ctx->bind_addr, &bind_ip) != 1)
				panic("bind address (%s) is invalid\n", ctx->bind_addr);

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
			panic("could not bind socket to address: [%d] %s\n", errno, strerror(errno));

		memset(sd, 0, sizeof(*sd));
		memcpy(sd, ai->ai_addr, ai->ai_addrlen);

		ctx->sd_len = ai->ai_addrlen;

		ret = setsockopt(fd, ctx->proto, IP_HDRINCL, &one, sizeof(one));
		if (ret < 0)
			panic("could not set socket option IP_HDRINCL: [%d] %s\n", errno, strerror(errno));

		if (ai->ai_family == AF_INET6) {
			struct sockaddr_in6 *sd6 = (struct sockaddr_in6 *) sd;
			sd6->sin6_port = 0;
		}

		break;
	}

	freeaddrinfo(ahead);

	if (fd < 0) {
		if (last_errno)
			panic("could not create socket: [%d] %s\n", last_errno, strerror(last_errno));
		else
			bug();
	}
	
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

static traceroute_result __process_node(struct ctx *ctx, int fd, int fd_cap, int ttl,
			  int inner_proto, uint8_t *pkt_snd, uint8_t *pkt_rcv, size_t *pkt_rcv_size,
			  const struct sockaddr_storage *ss,
			  const struct sockaddr_storage *sd, struct timeval *diff)
{
	struct pollfd pfd;
	struct timeval start, end;
	struct pkt_id pkt_id;

	prepare_polling(fd_cap, &pfd);

	if (pkt_rcv_size)
		*pkt_rcv_size = 0;
		
	memset(pkt_snd, 0, ctx->totlen);
	memset(pkt_rcv, 0, ctx->rcvlen);
	
	af_ops[ctx->proto].assembler(
		pkt_snd, ctx->totlen, ttl,
		inner_proto, ctx,
		(const struct sockaddr *) sd, (const struct sockaddr *) ss,
		&pkt_id
	);

	bug_on(ctx->timeout <= 0);
	int timeout = ctx->timeout * 1000;

	
	bug_on(gettimeofday(&start, NULL));
	ssize_t syscall_ret = sendto(fd, pkt_snd, ctx->totlen, 0, (const struct sockaddr*) sd, ctx->sd_len);
	
	if (syscall_ret < 0)
		panic("could not send packet: [%d] %s\n", errno, strerror(errno));
	
	while (timeout > 0) {

		syscall_ret = poll(&pfd, 1, timeout);
		bug_on(gettimeofday(&end, NULL));
		
		if (syscall_ret < 0 || !(pfd.revents & POLLIN) || sigint)
			return TRACEROUTE_NO_REPLY;
			
		syscall_ret = recvfrom(fd_cap, pkt_rcv, ctx->rcvlen, 0, NULL, NULL);
		
		if (syscall_ret < 0)
			return TRACEROUTE_NO_REPLY;

		if (syscall_ret >= (ssize_t) (sizeof(struct ethhdr) + af_ops[ctx->proto].min_len_icmp)) {
		
			traceroute_result ret = af_ops[ctx->proto].check(
				pkt_rcv + sizeof(struct ethhdr),
				syscall_ret - sizeof(struct ethhdr),
				ttl,
				&pkt_id,
				(const struct sockaddr *) ss,
				(const struct sockaddr *) sd
			);
		
			if (ret != TRACEROUTE_NO_REPLY) {
				
				if (pkt_rcv_size)
					*pkt_rcv_size = (size_t)syscall_ret;
				
				if (diff)
					timersub(&end, &start, diff);
					
				return ret;
			}
		}
		
		int timeout_decrease =
			(end.tv_sec * 1000 + end.tv_usec / 1000) - (start.tv_sec * 1000 + start.tv_usec / 1000);
			
		if (timeout_decrease <= 0)
			timeout_decrease = 10;
			
		timeout -= timeout_decrease;
	}
	
	return TRACEROUTE_NO_REPLY;
}

static traceroute_result __process_time(struct ctx *ctx, int fd, int fd_cap, int ttl,
			  int inner_proto, uint8_t *pkt_snd, uint8_t *pkt_rcv, size_t *pkt_rcv_size,
			  const struct sockaddr_storage *ss, const struct sockaddr_storage *sd)
{
	traceroute_result ret = TRACEROUTE_NO_REPLY, ret_good = TRACEROUTE_NO_REPLY;
	size_t i, j = 0;
	int good = 0, half_idx;
	uint8_t *trash = xmalloc(ctx->rcvlen);
	char *cwait[] = { "-", "\\", "|", "/" };
	struct timeval sum, res;
	struct timeval *pkt_rtt = xcalloc(ctx->num_packets, sizeof(*pkt_rtt));
	
	
	for (i = 0; i < ctx->num_packets && sigint == 0; ++i) {
		ret = __process_node(ctx, fd, fd_cap, ttl, inner_proto, pkt_snd,
				     good == 0 ? pkt_rcv : trash,
				     good == 0 ? pkt_rcv_size : NULL,
				     ss, sd, &pkt_rtt[good]);
				     
		if (ret != TRACEROUTE_NO_REPLY) {
			if (good == 0)
				ret_good = ret;
			good++;
		}

		usleep(50000);

		printf("\r%2d: %s", ttl, cwait[j++]);
		fflush(stdout);
		
		if (j >= array_size(cwait))
			j = 0;
	}

	if (good == 0) {
		xfree(pkt_rtt);
		xfree(trash);
		return TRACEROUTE_NO_REPLY;
	}


	qsort(pkt_rtt, good, sizeof(*pkt_rtt), timevalcmp);

	printf("\r%2d: %s[ ", ttl, proto_short(inner_proto));
	half_idx = good / 2;
	switch (good % 2) {
	case 0:
		timeradd(&pkt_rtt[half_idx], &pkt_rtt[half_idx - 1], &sum);
		timerdiv(2, &sum, &res);
		break;
	case 1:
		res = pkt_rtt[half_idx];
		break;
	}
	
	if (res.tv_sec > 0)
		printf("%lu sec ", res.tv_sec);
	
	printf("%7lu us ]", res.tv_usec);


	xfree(pkt_rtt);
	xfree(trash);

	return ret_good;
}

static traceroute_result __probe_remote(struct ctx *ctx, int fd, int fd_cap, int ttl,
					  uint8_t *pkt_snd, uint8_t *pkt_rcv,
					  const struct sockaddr_storage *ss,
					  const struct sockaddr_storage *sd,
					  int inner_proto)
{

	traceroute_result ret = TRACEROUTE_NO_REPLY;
	int tries = ctx->num_probes;
	size_t pkt_rcv_size;
	
	while (tries-- > 0 && sigint == 0) {
	
		ret = __process_time(ctx, fd, fd_cap, ttl, inner_proto,
				     pkt_snd, pkt_rcv, &pkt_rcv_size, ss, sd);
				     
		if (ret == TRACEROUTE_NO_REPLY)
			continue;

		af_ops[ctx->proto].handler(pkt_rcv + sizeof(struct ethhdr),
					   pkt_rcv_size - sizeof(struct ethhdr),
					   ctx->do_dns_resolution, ctx->do_geo_lookup);
					   
		if (ctx->do_show_packet) {
			struct pkt_buff *pkt;

			printf("\n");
			pkt = pkt_alloc(pkt_rcv, pkt_rcv_size);
			hex_ascii(pkt);
			tprintf_flush();
			pkt_free(pkt);
		}

		break;
	}

	return ret;
}

static traceroute_result __process_ttl(struct ctx *ctx, int fd, int fd_cap, int ttl,
			 		 uint8_t *pkt_snd, uint8_t *pkt_rcv,
			 		 const struct sockaddr_storage *ss,
			 		 const struct sockaddr_storage *sd)
{
	traceroute_result ret = TRACEROUTE_NO_REPLY;
	size_t i;
	const int inner_protos[] = {
		IPPROTO_TCP,
		__icmp_proto_for_ip_proto(ctx->proto),
	};

	printf("%2d: ", ttl);
	fflush(stdout);

	for (i = 0; i < array_size(inner_protos) && sigint == 0; ++i) {

		ret = __probe_remote(ctx, fd, fd_cap, ttl, pkt_snd,
				     pkt_rcv, ss, sd, inner_protos[i]);
		
		if (ret != TRACEROUTE_NO_REPLY)
			break;
	}

	if (ret == TRACEROUTE_NO_REPLY)
		printf("\r%2d: ?[ no answer ]", ttl);
		
	if (!ctx->do_show_packet)
		printf("\n");
		
	if (ctx->do_show_packet && ret == TRACEROUTE_NO_REPLY)
		printf("\n\n");

	fflush(stdout);
	return ret;
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
	bind_ring_generic(fd_cap, &dummy_ring, ifindex, false);

	if (ctx->totlen < af_ops[ctx->proto].min_len_tcp) {
		ctx->totlen = af_ops[ctx->proto].min_len_tcp;
		if (ctx->payload)
			ctx->totlen += strlen(ctx->payload);
	}

	ctx->rcvlen = device_mtu(ctx->dev) - sizeof(struct ethhdr);
	if (ctx->totlen >= ctx->rcvlen)
		panic("packet length (%zu) exceeds device MTU (%zu)\n", ctx->totlen, ctx->rcvlen);

	pkt_snd = xmalloc(ctx->totlen);
	pkt_rcv = xmalloc(ctx->rcvlen);

	show_trace_info(ctx, &ss, &sd);

	for (ttl = ctx->init_ttl; ttl <= ctx->max_ttl && sigint == 0; ++ttl)
		if (__process_ttl(ctx, fd, fd_cap, ttl, pkt_snd, pkt_rcv, &ss, &sd) == TRACEROUTE_DST_REACHED)
			break;

	xfree(pkt_snd);
	xfree(pkt_rcv);

	close(fd_cap);
	close(fd);

	return 0;
}

int main(int argc, char **argv)
{
	int c, ret;
	struct ctx ctx;

	setfsuid(getuid());
	setfsgid(getgid());

	srand(time(NULL));

	memset(&ctx, 0, sizeof(ctx));
	ctx.init_ttl = CTX_DEFAULT_INIT_TTL;
	ctx.max_ttl = CTX_DEFAULT_MAX_TTL;
	ctx.num_probes = CTX_DEFAULT_NUM_PROBES;
	ctx.num_packets = CTX_DEFAULT_NUM_PACKETS;
	ctx.timeout = CTX_DEFAULT_TIMEOUT;
	ctx.proto = CTX_DEFAULT_PROTO;
	ctx.payload = NULL;
	ctx.dev = xstrdup(CTX_DEFAULT_DEV);
	ctx.port = xstrdup(CTX_DEFAULT_PORTSTR);
	ctx.bind_addr = NULL;
	ctx.tos = CTX_DEFAULT_IPV4_TOS;
	ctx.do_dns_resolution = CTX_DEFAULT_DO_DNS_RESOLUTION;
	ctx.do_geo_lookup = CTX_DEFAULT_DO_GEO_LOOKUP;
	ctx.do_show_packet = CTX_DEFAULT_DO_SHOW_PACKET;

	while ((c = getopt_long(argc, argv, short_options, long_options,
				NULL)) != EOF) {
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
			ctx.do_dns_resolution = false;
			break;
		case '4':
			ctx.proto = IPPROTO_IP;
			break;
		case '6':
			ctx.proto = IPPROTO_IPV6;
			break;
		case 'Z':
			ctx.do_show_packet = true;
			break;
		case 'N':
			ctx.do_dns_resolution = true;
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
			ctx.num_probes = atoi(optarg);
			if (ctx.num_probes <= 0)
				help();
			break;
		case 's':
			ctx.num_packets = atoi(optarg);
			if (ctx.num_packets <= 0)
				help();
			break;
		case 'x':
			ctx.timeout = atoi(optarg);
			if (ctx.timeout <= 0)
				help();
			break;
		case 'L':
			ctx.do_geo_lookup = true;
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
				panic("option -%c requires an argument!\n",
				      optopt);
			default:
				if (isprint(optopt))
					printf("unknown option character '0x%X'!\n", optopt);
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
		panic("networking device %s is not up and running\n", ctx.dev);
	if (device_mtu(ctx.dev) <= ctx.totlen)
		panic("packet length (%zu) exceeds device MTU (%zu)\n", ctx.totlen, device_mtu(ctx.dev));

	register_signal(SIGHUP, signal_handler);
	register_signal(SIGINT, signal_handler);
	register_signal(SIGQUIT, signal_handler);
	register_signal(SIGTERM, signal_handler);

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

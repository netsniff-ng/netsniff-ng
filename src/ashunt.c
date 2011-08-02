/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 *
 * An Autonomous System trace route utility based on TCP instead of ICMP for
 * a better passing of firewalls. Supports IPv4 and IPv6. Based on the idea
 * of tcptraceroute (http://michael.toren.net/code/tcptraceroute/), but hacked
 * for Autonomous Systems tracing.
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

#include "misc.h"
#include "die.h"
#include "xmalloc.h"
#include "write_or_die.h"
#include "aslookup.h"
#include "version.h"
#include "signals.h"
#include "netdev.h"
#include "mtrand.h"
#include "parser.h"

#define WHOIS_SERVER_SOURCE "/etc/netsniff-ng/whois.conf"

struct ash_cfg {
	char *host;
	char *port;
	int init_ttl;
	int max_ttl;
	int dns_resolv;
	char *src_ip;
	int src_port;
	char *dev;
	int queries;
	int timeout;
	int syn, ack, ecn;
	int tos, nofrag;
	int totlen;
	char *whois;
	char *whois_port;
	int ip;
};

sig_atomic_t sigint = 0;

static const char *short_options = "H:p:nNf:m:P:s:i:d:q:x:SAEt:Fl:w:W:hv46";

static struct option long_options[] = {
	{"host", required_argument, 0, 'H'},
	{"port", required_argument, 0, 'p'},
	{"init-ttl", required_argument, 0, 'f'},
	{"max-ttl", required_argument, 0, 'm'},
	{"numeric", no_argument, 0, 'n'},
	{"dns", no_argument, 0, 'N'},
	{"ipv4", no_argument, 0, '4'},
	{"ipv6", no_argument, 0, '6'},
	{"src-port", required_argument, 0, 'P'},
	{"src-addr", required_argument, 0, 's'},
	{"dev", required_argument, 0, 'd'},
	{"num-probes", required_argument, 0, 'q'},
	{"timeout", required_argument, 0, 'x'},
	{"syn", no_argument, 0, 'S'},
	{"ack", no_argument, 0, 'A'},
	{"ecn-syn", no_argument, 0, 'E'},
	{"tos", required_argument, 0, 't'},
	{"nofrag", no_argument, 0, 'F'},
	{"totlen", required_argument, 0, 'l'},
	{"whois", required_argument, 0, 'w'},
	{"wport", required_argument, 0, 'W'},
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

	printf("\nashunt %s, AS trace route utility\n",
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
	printf(" -P|--src-port <port>    Specify local source port (default: bind(2))\n");
	printf(" -s|--src-addr <addr>    Specify local source addr\n");
	printf(" -q|--num-probes <num>   Number of probes for each hop (default: 3)\n");
	printf(" -x|--timeout <sec>      Probe response timeout in sec (default: 3)\n");
	printf(" -S|--syn                Set TCP SYN flag in packets\n");
	printf(" -A|--ack                Set TCP ACK flag in packets\n");
	printf(" -E|--ecn-syn            Send ECN SYN packets\n");
	printf(" -t|--tos <tos>          Set the IP TOS field\n");
	printf(" -F|--nofrag             Set do not fragment bit\n");
	printf(" -l|--totlen <len>       Specify total packet len\n");
	printf(" -w|--whois <server>     Use a different AS whois DB server\n");
	printf("                         (default: /etc/netsniff-ng/whois.conf)\n");
	printf(" -W|--wport <port>       Use a different port to AS whois server\n");
	printf("                         (default: /etc/netsniff-ng/whois.conf)\n");
	printf(" -v|--version            Print version\n");
	printf(" -h|--help               Print this help\n");
	printf("\n");
	printf("Examples:\n");
	printf("  IPv4 trace of AS up to netsniff-ng.org:80:\n");
	printf("    ashunt -i eth0 -H netsniff-ng.org -p 80\n");
	printf("  IPv6 trace of AS up to netsniff-ng.org:80:\n");
	printf("    ashunt -6 -i eth0 -H netsniff-ng.org -p 80\n");
	printf("\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,\n");
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
	printf("Copyright (C) 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,\n");
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

static ssize_t assemble_data(uint8_t *packet, size_t len)
{
	int i;
	for (i = 0; i < len; ++i)
		packet[i] = (uint8_t) mt_rand_int32();
	return len;
}

static ssize_t assemble_tcp(uint8_t *packet, size_t len,
			    int syn, int ack, int ecn)
{
	struct tcphdr *tcph = (struct tcphdr *) packet;

	if (len < sizeof(struct tcphdr))
		return -ENOMEM;

	tcph->source = htons(1234);
	tcph->dest = htons(85);
	tcph->seq = random();
	tcph->ack_seq = 0;
	tcph->doff = 0;
	tcph->syn = !!syn;
	tcph->ack = !!ack;
	tcph->urg = 0;
	tcph->fin = 0;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ece = !!ecn;
	tcph->cwr = !!ecn;
	tcph->doff = 0;
	tcph->window = htonl(65535);
	tcph->check = 0;
	tcph->urg_ptr = 0;

	return sizeof(struct tcphdr);
}

static ssize_t assemble_ipv4_tcp(uint8_t *packet, size_t len, int ttl,
				 int tos, struct in_addr *src, struct in_addr *dst,
				 int syn, int ack, int ecn, int nofrag)
{
	struct iphdr *iph = (struct iphdr *) packet;

	if (len < sizeof(struct iphdr) + sizeof(struct tcphdr))
		return -ENOMEM;
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = (uint8_t) tos;
	iph->tot_len = htons((uint16_t) len);
	iph->id = htons((uint16_t) mt_rand_int32());
	iph->frag_off = nofrag ? IP_DF : 0;
	iph->ttl = (uint8_t) ttl;
	iph->protocol = 6; /* TCP */
	iph->saddr = src->s_addr;
	iph->daddr = dst->s_addr;
	assemble_tcp(packet + sizeof(struct iphdr),
		     len - sizeof(struct iphdr),
		     syn, ack, ecn);
	assemble_data(packet + sizeof(struct iphdr) + sizeof(struct tcphdr),
		      len - sizeof(struct iphdr) + sizeof(struct tcphdr));
	iph->check = csum((unsigned short *) packet,
			  ntohs(iph->tot_len) >> 1);
	return len;
}

static ssize_t assemble_ipv6_tcp(uint8_t *packet, size_t len, int ttl,
			 	 struct sockaddr_in *sin)
{
	return 0;
}

static ssize_t assemble_packet(uint8_t *packet, size_t len, int ttl,
			       struct ash_cfg *cfg)
{
//	assemble_ipv4_tcp(packet, len, ttl, cfg->tos,
//			  NULL, NULL, cfg->syn, cfg->ack, cfg->ecn,
//			  cfg->nofrag);
	return 0;
}

static int do_trace(struct ash_cfg *cfg)
{
	int ttl, query, fd = -1, one = 1, ret, fd_cap, last = 0;
	uint8_t *packet;
	ssize_t err;
	size_t len;
	struct addrinfo hints, *ahead, *ai;
	char hbuff[256], sbuff[256];

	mt_init_by_random_device();

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

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
		break;
	}

	freeaddrinfo(ahead);
	if (fd < 0) {
		whine("Cannot create socket! Does remote support IPv%d?!\n",
		      cfg->ip);
		return -EIO;
	}

	len = cfg->totlen ? : cfg->ip == 4 ? 
		sizeof(struct iphdr) + sizeof(struct tcphdr) :
		sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
	if (len >= device_mtu(cfg->dev))
		panic("Packet len exceeds device MTU!\n");
	packet = xmalloc(len);

	memset(hbuff, 0, sizeof(hbuff));
	memset(sbuff, 0, sizeof(sbuff));
	getnameinfo((struct sockaddr *) ai->ai_addr, ai->ai_addrlen,
		    hbuff, sizeof(hbuff),
		    sbuff, sizeof(sbuff),
		    NI_NUMERICHOST | NI_NUMERICSERV);

	ret = setsockopt(fd, cfg->ip == 4 ? IPPROTO_IP : IPPROTO_IPV6,
			 IP_HDRINCL, &one, sizeof(one));
	if (ret < 0)
		panic("Kernel does not support IP_HDRINCL!\n");

	info("AS path IPv%d trace to %s (%s) on TCP port %s with len %u Bytes, "
	     "%u max hops\n", cfg->ip, cfg->host, hbuff, cfg->port, len,
	     cfg->max_ttl);
	fflush(stdout);

	for (ttl = cfg->init_ttl; ttl <= cfg->max_ttl && !sigint && !last;
	     ++ttl) {
		info("hop %02d: ", ttl);
		for (query = 0; query < cfg->queries; ++query) {
			assemble_packet(packet, len, ttl, cfg);
			// setup filter, listen
			err = sendto(fd, packet, len, 0,
				     ai->ai_addr, ai->ai_addrlen);
			if (err < 0)
				panic("sendto failed: %s\n", strerror(errno));
		}
		info("\n");
	}

	close(fd_cap);
	close(fd);
	xfree(packet);
	return 0;
}

void parse_whois_or_die(struct ash_cfg *cfg)
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

	check_for_root_maybe_die();

	memset(&cfg, 0, sizeof(cfg));
	cfg.init_ttl = 1;
	cfg.max_ttl = 30;
	cfg.queries = 3;
	cfg.timeout = 3;
	cfg.ip = 4;
	cfg.dev = xstrdup("eth0");

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
		case 'P':
			cfg.src_port = atoi(optarg);
			if (cfg.max_ttl <= 0)
				help();
			break;
		case 's':
			cfg.src_ip = xstrdup(optarg);
			break;
		case 'i':
		case 'd':
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
		case 'E':
			cfg.ecn = 1;
			break;
		case 't':
			cfg.tos = atoi(optarg);
			if (cfg.tos < 0)
				help();
			break;
		case 'F':
			cfg.nofrag = 1;
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
		case '?':
			switch (optopt) {
			case 'H':
			case 'p':
			case 'f':
			case 'm':
			case 'P':
			case 's':
			case 'i':
			case 'd':
			case 'q':
			case 'x':
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

	if (argc < 5 ||
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

	register_signal(SIGINT, signal_handler);
	register_signal(SIGHUP, signal_handler);

	header();
	ret = do_trace(&cfg);

	if (cfg.whois_port)
		xfree(cfg.whois_port);
	if (cfg.whois)
		xfree(cfg.whois);
	if (cfg.dev)
		xfree(cfg.dev);
	if (cfg.src_ip)
		xfree(cfg.src_ip);
	if (cfg.host)
		xfree(cfg.host);
	if (cfg.port)
		xfree(cfg.port);
	return ret;
}


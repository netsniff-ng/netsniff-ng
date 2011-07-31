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
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <ctype.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include "misc.h"
#include "die.h"
#include "xmalloc.h"
#include "write_or_die.h"
#include "aslookup.h"
#include "version.h"
#include "signals.h"
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
};

sig_atomic_t sigint = 0;

static const char *short_options = "H:p:nNf:m:P:s:i:d:q:x:SAEt:Fl:w:W:hv";

static struct option long_options[] = {
	{"host", required_argument, 0, 'H'},
	{"port", required_argument, 0, 'p'},
	{"init-ttl", required_argument, 0, 'f'},
	{"max-ttl", required_argument, 0, 'm'},
	{"numeric", no_argument, 0, 'n'},
	{"dns", no_argument, 0, 'N'},
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
	printf(" -n|--numeric            Do not do reverse DNS lookup for hops\n");
	printf(" -N|--dns                Do a reverse DNS lookup for hops\n");
	printf(" -f|--init-ttl <ttl>     Set initial TTL\n");
	printf(" -m|--max-ttl <ttl>      Set maximum TTL (default: 30)\n");
	printf(" -P|--src-port <port>    Specify local source port (default: bind(2))\n");
	printf(" -s|--src-addr <addr>    Specify local source addr\n");
	printf(" -i|-d|--dev <device>    Networking device, i.e. eth0\n");
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
	printf("  trace AS up to netsniff-ng.org:80:\n");
	printf("  ashunt -i eth0 -H netsniff-ng.org -p 80\n");
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

static int do_trace(struct ash_cfg *cfg)
{
	info("Autonomous System path trace to %s on TCP port %s, %u max hops\n",
	     cfg->host, cfg->port, cfg->max_ttl);
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

	if (argc < 5 || !cfg.host || !cfg.port || cfg.init_ttl > cfg.max_ttl)
		help();
	if (!cfg.whois || !cfg.whois_port)
		parse_whois_or_die(&cfg);

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


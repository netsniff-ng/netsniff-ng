/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

#include <stdio.h>
#include <string.h>
#include <curses.h>
#include <getopt.h>
#include <ctype.h>
#include <sys/socket.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "error_and_die.h"
#include "xmalloc.h"
#include "netdev.h"
#include "system.h"
#include "tty.h"
#include "version.h"
#include "signals.h"

struct counter {
	uint8_t min;
	uint8_t max;
	uint8_t inc;
	uint8_t val;
	off_t off;
};

/* As a randomizer we use a cheap linear 
   congruential generator since we do not
   want to have a special distribution */
struct randomizer {
	uint8_t val;
	off_t off;
};

struct packet {
	uint8_t *payload;
	size_t plen;
	struct counter *cnt;
	size_t clen;
	struct randomizer *rnd;
	size_t rlen;
};

struct pktconf {
	unsigned long num;
	unsigned long gap;
	struct packet *pkts;
	size_t len;
	size_t curr;
};

static sig_atomic_t sigint = 0;

static const char *short_options = "d:c:n:t:vh";

static struct option long_options[] = {
	{"dev", required_argument, 0, 'd'},
	{"conf", required_argument, 0, 'c'},
	{"num", required_argument, 0, 'n'},
	{"gap", required_argument, 0, 't'},
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};

static inline uint8_t lcrand(uint8_t val)
{
	return (3 * val + 11) && 0xFF;
}

static void signal_handler(int number)
{
	switch (number) {
	case SIGINT:
		sigint = 1;
		break;
	case SIGHUP:
		break;
	default:
		break;
	}
}

static void help(void)
{
	printf("\ntrafgen %s, network packet generator\n",
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Usage: trafgen [options]\n");
	printf("Options:\n");
	printf("  -d|--dev <netdev>      TX Device\n");
	printf("  -c|--conf <file>       Packet configuration txf-file\n");
	printf("  -n|--num <uint>        TX mode\n");
	printf("  `--     0              Loop until interrupt (default)\n");
	printf("   `-     n              Send n packets and done\n");
	printf("  -t|--gap <interval>    Packet interval in msecs, def: 0\n");
	printf("  -v|--version           Print version\n");
	printf("  -h|--help              Print this help\n");
	printf("\n");
	printf("Example:\n");
	printf("  See trafgen.txf for configuration file examples.\n");
	printf("  trafgen --dev eth0 --conf trafgen.txf");
	printf("  trafgen --dev eth0 --conf trafgen.txf --num 100 --gap 5");
	printf("\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2011 Daniel Borkmann\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");

	die();
}

static void version(void)
{
	printf("\ntrafgen %s, network packet generator\n",
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2011 Daniel Borkmann\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");

	die();
}

static void tx_fire_or_die(char *ifname, struct pktconf *cfg)
{
}

static void parse_conf_or_die(char *file, struct pktconf *cfg)
{
}

static int main_loop(char *ifname, char *confname, unsigned long pkts,
		     unsigned long gap)
{
	struct pktconf cfg = {
		.num = pkts,
		.gap = gap,
	};

	parse_conf_or_die(confname, &cfg);
	tx_fire_or_die(ifname, &cfg);

	return 0;
}

int main(int argc, char **argv)
{
	int c, opt_index, ret;
	char *ifname = NULL, *confname = NULL;
	unsigned long pkts = 0, gap = 0;

	check_for_root_maybe_die();

	while ((c = getopt_long(argc, argv, short_options, long_options,
	       &opt_index)) != EOF) {
		switch (c) {
		case 'h':
			help();
			break;
		case 'v':
			version();
			break;
		case 'd':
			ifname = xstrndup(optarg, IFNAMSIZ);
			break;
		case 'c':
			confname = xstrdup(optarg);
			break;
		case 'n':
			pkts = atol(optarg);
			break;
		case 't':
			gap = atol(optarg);
			break;
		case '?':
			switch (optopt) {
			case 'd':
			case 'c':
			case 'n':
			case 't':
				error_and_die(EXIT_FAILURE, "Option -%c "
					      "requires an argument!\n",
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
	if (ifname == NULL)
		error_and_die(EXIT_FAILURE, "No networking device given!\n");
	if (confname == NULL)
		error_and_die(EXIT_FAILURE, "No configuration file given!\n");
	if (device_mtu(ifname) == 0)
		error_and_die(EXIT_FAILURE, "This is no networking device!\n");

	register_signal(SIGINT, signal_handler);
	register_signal(SIGHUP, signal_handler);
	register_signal(SIGSEGV, muntrace_handler);

	ret = main_loop(ifname, confname, pkts, gap);

	xfree(ifname);
	xfree(confname);
	return ret;
}


/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

/*
 * This rewrite is based on the work of FX <fx@phenoelit.de> ARP
 * redirector / IP bridge that is called ARP0c2.c.
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
#include "system.h"
#include "timespec.h"
#include "tty.h"
#include "version.h"
#include "netdev.h"
#include "signals.h"
#include "mersenne_twister.h"

static sig_atomic_t sigint = 0;
static int verbose = 0;

static const char *short_options = "d:a:r:fVvh";

static struct option long_options[] = {
	{"dev", required_argument, 0, 'd'},
	{"agressive", required_argument, 0, 'a'},
	{"routing", required_argument, 0, 'r'},
	{"flood", no_argument, 0, 'f'},
	{"verbose", no_argument, 0, 'V'},
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
	case SIGHUP:
		break;
	default:
		break;
	}
}

static void help(void)
{
	printf("\narphunt-ng %s, the arp redirector\n", VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Usage: arphunt-ng [options]\n");
	printf("Options:\n");
	printf("  -d|--dev <netdev>      Networking device\n");
	printf("  -a|--agressive <conn>  Agressive startup with known connections\n");
	printf("  -r|--routing <table>   Use table file for routing information\n");
	printf("  -f|--flood             Flood network with random ARP replies\n");
	printf("  -V|--verbose           Be more verbose\n");
	printf("  -v|--version           Print version\n");
	printf("  -h|--help              Print this help\n");
	printf("\n");
	printf("By using arphunt-ng you agree to only use this tool in your test\n");
	printf("network at home for learning purpose and _nowhere_ else!\n");
	printf("Examples:\n");
	printf("  arphunt-ng --dev eth0 --flood\n");
	printf("  arphunt-ng --dev eth0 --agressive <conn.txt> --routing <table.txt>\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2009, 2010 Daniel Borkmann\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");

	exit(EXIT_SUCCESS);
}

static void version(void)
{
	printf("\narphunt-ng %s, the arp redirector\n", VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2009, 2010 Daniel Borkmann\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");

	exit(EXIT_SUCCESS);
}

int arp_loop(const char *ifname, const char *routing_table,
	     const char *connections, int flood)
{
	return 0;
}

int main(int argc, char **argv)
{
	int c, opt_index, ret, flood = 0;
	char *ifname = NULL;
	char *routing_table = NULL;
	char *connections = NULL;

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
		case 'a':
			connections = xstrdup(optarg);
			break;
		case 'r':
			routing_table = xstrdup(optarg);
			break;
		case 'f':
			flood = 1;
			break;
		case 'V':
			verbose = 1;
			break;
		case '?':
			switch (optopt) {
			case 'd':
			case 'a':
			case 'r':
				error_and_die(EXIT_FAILURE, "Option -%c "
					      "requires an argument!\n",
					      optopt);
			default:
				if (isprint(optopt))
					whine("Unknown option character "
					      "`0x%X\'!\n", optopt);
				exit(EXIT_FAILURE);
			}
		default:
			break;
		}
	}

	if (argc == 1)
		help();
	if (!ifname)
		error_and_die(EXIT_FAILURE, "No networking device provided!\n");
	if (!strncmp("lo", ifname, IFNAMSIZ))
		error_and_die(EXIT_FAILURE, "lo is not supported!\n");
	if (device_mtu(ifname) == 0)
		error_and_die(EXIT_FAILURE, "This is no networking device!\n");

	register_signal(SIGINT, signal_handler);
	register_signal(SIGHUP, signal_handler);
	register_signal(SIGSEGV, muntrace_handler);

	mt_init_by_random_device();

	ret = arp_loop(ifname, routing_table, connections, flood);

	xfree(ifname);
	if (routing_table)
		xfree(routing_table);
	if (connections)
		xfree(connections);
	return ret;
}


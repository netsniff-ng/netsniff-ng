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
#include "tty.h"
#include "version.h"
#include "signals.h"

static sig_atomic_t sigint = 0;

static const char *short_options = "d:t:vhcCHl";

static struct option long_options[] = {
	{"dev", required_argument, 0, 'd'},
	{"interval", required_argument, 0, 't'},
	{"loop", no_argument, 0, 'l'},
	{"term", no_argument, 0, 'c'},
	{"csv", no_argument, 0, 'C'},
	{"csv-tablehead", no_argument, 0, 'H'},
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
	printf("\ntrafgen %s, packet generator\n",
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Usage: trafgen [options]\n");
	printf("Options:\n");
	printf("  -d|--dev <netdev>      Device to fetch statistics for\n");
	printf("  -c|--conf <file>       Packet configuration file\n");
	printf("  -m|--mode <mode>       TX mode\n");
	printf("  `--     0              Loop until interrupt\n");
	printf("   `-     n              Send n packets and done\n");
	printf("  -v|--version           Print version\n");
	printf("  -h|--help              Print this help\n");
	printf("\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2011 Daniel Borkmann\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");

	exit(EXIT_SUCCESS);
}

static void version(void)
{
	printf("\ntrafgen %s, packet generator\n",
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2011 Daniel Borkmann\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");

	exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	int c, opt_index, ret;
	char *ifname = NULL;

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
			break;
		case '?':
			switch (optopt) {
			case 'd':
			case 'c':
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
	if (argc == 2)
		ifname = xstrndup(argv[1], IFNAMSIZ);
	if (ifname == NULL)
		error_and_die(EXIT_FAILURE, "No networking device given!\n");
	if (device_mtu(ifname) == 0)
		error_and_die(EXIT_FAILURE, "This is no networking device!\n");

	register_signal(SIGINT, signal_handler);
	register_signal(SIGHUP, signal_handler);
	register_signal(SIGSEGV, muntrace_handler);

	ret = 0;
//	ret = main_loop(ifname, interval);

	xfree(ifname);
	return ret;
}


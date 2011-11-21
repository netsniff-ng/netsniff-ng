/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL, version 2.
 *
 * A tiny tool to provide top-like UDP/TCP connection tracking information.
 * apt-get install libnetfilter-conntrack3 libnetfilter-conntrack-dev
 */

//geoip
//cache for reverse dns
//heavy hitters?!

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include "die.h"
#include "version.h"

#define CT_INCLUDE_UDP	(1 << 0)
#define CT_INCLUDE_TCP	(1 << 1)
#define CT_INCLUDE_IP4	(1 << 2)
#define CT_INCLUDE_IP6	(1 << 3)

static sig_atomic_t sigint = 0;

static const char *short_options = "t:vhTU46";

static struct option long_options[] = {
	{"interval", required_argument, 0, 't'},
	{"tcp", no_argument, 0, 'T'},
	{"udp", no_argument, 0, 'U'},
	{"ipv4", no_argument, 0, '4'},
	{"ipv6", no_argument, 0, '6'},
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
	printf("\nflowtop %s, top-like kernel connection tracking\n",
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Usage: flowtop [options]\n");
	printf("Options:\n");
	printf("  -t|--interval <time>   Refresh time in sec (default 1.0)\n");
	printf("  -T|--tcp               TCP connections only\n");
	printf("  -U|--udp               UDP connections only\n");
	printf("  -4|--ipv4              IPv4 connections only\n");
	printf("  -6|--ipv6              IPv6 connections only\n");
	printf("  -v|--version           Print version\n");
	printf("  -h|--help              Print this help\n");
	printf("\n");
	printf("Examples:\n");
	printf("  flowtop --tcp --ipv4\n");
	printf("  flowtop --tcp --udp --ipv6 --interval 2.0\n");
	printf("  flowtop\n\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2011 Daniel Borkmann <daniel@netsniff-ng.org>\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");
	die();
}

static void version(void)
{
	printf("\nflowtop %s, top-like kernel connection tracking\n",
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2011 Daniel Borkmann\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");
	die();
}

int main(int argc, char **argv)
{
	int c, opt_index;
	double interval = 1.0;

	while ((c = getopt_long(argc, argv, short_options, long_options,
	       &opt_index)) != EOF) {
		switch (c) {
		case 'h':
			help();
			break;
		case 'v':
			version();
			break;
		default:
			break;
		}
	}

	return 0;
}


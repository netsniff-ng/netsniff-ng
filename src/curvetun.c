/*
 * netsniff-ng - the packet sniffing beast
 * Portions of this code derived and modified from:
 *  Copyright 1998-2000 Maxim Krasnyansky <max_mk@yahoo.com>
 *  Copyright 2009 Bertram Poettering <seccure@point-at-infinity.org>
 *  All subject to the GPL, version 2.
 * curvetun - the cipherspace wormhole creator
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include <ctype.h>
#include <getopt.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "xmalloc.h"
#include "system.h"
#include "netdev.h"
#include "version.h"
#include "error_and_die.h"
#include "strlcpy.h"
#include "signals.h"

enum working_mode {
	MODE_UNKNOW,
	MODE_KEYGEN,
	MODE_CLIENT,
	MODE_SERVER,
};

enum client_mode {
	MODE_SINGLE,
	MODE_ALL_RROBIN,
	MODE_ALL_RANDOM,
	MODE_ALL_LATENCY,
};

static sig_atomic_t sigint = 0;

static const char *short_options = "kc:m:svhp:t:";

static struct option long_options[] = {
	{"client", optional_argument, 0, 'c'},
	{"mode", required_argument, 0, 'm'},
	{"port", required_argument, 0, 'p'},
	{"stun", required_argument, 0, 't'},
	{"keygen", no_argument, 0, 'k'},
	{"server", no_argument, 0, 's'},
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

static void header(void)
{
	printf("%s%s%s\n", colorize_start(bold), "curvetun "
	       VERSION_STRING, colorize_end());
}

static void help(void)
{
	printf("\ncurvetun %s, ``Elliptic Curve Crypto''-based IP-tunnel\n",
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Usage: curvetun [options]\n");
	printf("Options:\n");
	printf("  -k|--keygen             Generate public/private keypair\n");
	printf(" Client settings:\n");
	printf("  -c|--client [alias]     Client mode, server alias optional\n");
	printf("  -m|--mode <mode>        Working mode, if no alias specified\n");
	printf("   `--- latency           Select server with lowest latency\n");
	printf("    `-- rrobin            Select servers in round robin\n");
	printf("     `- random            Select servers randomly (default)\n");
	printf(" Server settings:\n");
	printf("  -s|--server             Server mode\n");
	printf("  -p|--port <num>         Port number (mandatory)\n");
	printf("  -t|--stun <server:port> Show public IP/Port mapping via STUN\n");
	printf(" Misc:\n");
	printf("  -v|--version            Print version\n");
	printf("  -h|--help               Print this help\n");
	printf("\n");
	printf("Example:\n");
	printf("  Server: curvetun --server --port 6666\n");
	printf("  Client: curvetun --client --mode random\n");
	printf("  Where both participants have the following files specified:\n");
	printf("   ~/.curvetun/clients      - Participants the server accepts\n");
	printf("        line-format:   username:pubkey\n");
	printf("   ~/.curvetun/servers      - Possible servers the client can connect to\n");
	printf("        line-format:   alias:serverip|servername:port:pubkey\n");
	printf("   ~/.curvetun/priv.key     - Your private key\n");
	printf("   ~/.curvetun/pub.key      - Your public key\n");
	printf("   ~/.curvetun/username     - Your username\n");
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
	printf("\ncurvetun %s, ``Elliptic Curve Crypto''-based IP-tunnel\n",
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

#if 0
static int __tun_open_or_die(void)
{
	int i, fd;
	char tunname[IFNAMSIZ];

	for (i = 0; i < 255; ++i) {
		memset(tunname, 0, sizeof(tunname));
		sprintf(tunname, "/dev/tun%d", i);

		fd = open(tunname, O_RDWR);
		if (fd > 0)
			return fd;
	}

	panic("Cannot open tunnel device!\n");
	return 0; /* never reached, but to suppress compiler warning */
}

#ifndef OTUNSETIFF
# define OTUNSETIFF (('T' << 8) | 202)
#endif

static int tun_open_or_die(void)
{
	int fd, ret;
	struct ifreq ifr;

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0)
		return __tun_open_or_die();

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	ret = ioctl(fd, TUNSETIFF, &ifr);
	if (ret < 0) {
		if (errno == EBADFD) {
			ret = ioctl(fd, OTUNSETIFF, &ifr);
			if (ret < 0)
				panic("ioctl screwed up!\n");
		} else
			panic("ioctl screwed up!\n");
	}

	return fd;
}

static inline ssize_t tun_write(int fd, const void *buf, size_t count)
{
	return write(fd, buf, count);
}

static inline int tun_read(int fd, void *buf, size_t count)
{
	return read(fd, buf, count);
}

static inline void tun_close(int fd)
{
	close(fd);
}
#endif

int main_keygen(void)
{
	return 0;
}

int main_client(enum client_mode cmode)
{
	return 0;
}

int main_server(int port)
{
	return 0;
}

int main(int argc, char **argv)
{
	int c, opt_index, port;
	enum working_mode wmode = MODE_UNKNOW;
	enum client_mode cmode = MODE_ALL_RANDOM;

	while ((c = getopt_long(argc, argv, short_options, long_options,
	       &opt_index)) != EOF) {
		switch (c) {
		case 'h':
			help();
			break;
		case 'v':
			version();
			break;
		case 'c':
			wmode = MODE_CLIENT;
			break;
		case 'm':
			cmode = MODE_ALL_RANDOM;
			break;
		case 'k':
			wmode = MODE_KEYGEN;
			break;
		case 's':
			wmode = MODE_SERVER;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case '?':
			switch (optopt) {
			case 'm':
			case 'p':
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

	if (argc < 2)
		help();

	register_signal(SIGINT, signal_handler);
	register_signal(SIGHUP, signal_handler);
	register_signal(SIGSEGV, muntrace_handler);

	header();

	switch (wmode) {
	case MODE_KEYGEN:
		main_keygen();
		break;
	case MODE_CLIENT:
		main_client(cmode);
		break;
	case MODE_SERVER:
		main_server(port);
		break;
	default:
		panic("Either select keygen, client or server mode!\n");
	}

	return 0;
}


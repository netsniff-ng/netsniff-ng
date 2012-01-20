/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include "netdev.h"
#include "compiler.h"
#include "write_or_die.h"
#include "die.h"
#include "signals.h"
#include "tty.h"
#include "misc.h"
#include "bpf.h"

sig_atomic_t sigint = 0;

static const char *short_options = "d:m:vhi:";

static struct option long_options[] = {
	{"dev", required_argument, 0, 'd'},
	{"mdev", required_argument, 0, 'm'},
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};

static void header(void)
{
	printf("%s%s%s\n", colorize_start(bold), "warp "
	       VERSION_STRING, colorize_end());
}

static void help(void)
{
	printf("\nwarp %s, arp cache poisoning tool\n", VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Usage: warp [options]\n");
	printf("Options:\n");
	printf("  -d|-i|--dev <dev>       Networking device, e.g. eth0\n");
	printf("  -m|--mdev <dev>         Man in the middle networking device\n");
	printf("                          (default: mitm<dev-nr>)\n");
	printf("  -v|--version            Print version\n");
	printf("  -h|--help               Print this help\n");
	printf("\n");
	printf("Example:\n");
	printf("  warp --dev eth0 --mdev mitm\n");
	printf("  netsniff-ng --in mitm --out dump.pcap --less\n");
	printf("\n");
	printf("Note:\n");
	printf("  This tool is targeted for network developers! You should\n");
	printf("  be aware of what you are doing and what these options above\n");
	printf("  mean! Only use this tool in an isolated LAN that you own!\n");
	printf("\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2011 Daniel Borkmann <daniel@netsniff-ng.org>,\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");
	die();
}

static void version(void)
{
	printf("\nwarp %s, arp cache poisoning tool\n", VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2011 Daniel Borkmann <daniel@netsniff-ng.org>,\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");
	die();
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

static struct sock_filter arp_type[] = {
	/* (000) ldh  [12] */
	{ 0x28, 0, 0, 0x0000000c },
	/* (001) jeq  #0x800 jt 2 jf 3 */
	{ 0x15, 0, 1, 0x00000806 },
	/* (002) ret  #65535 */
	{ 0x06, 0, 0, 0xffffffff },
	/* (003) ret  #0 */
	{ 0x06, 0, 0, 0x00000000 },
};

struct arphdr {
	uint16_t ar_hrd;   /* format of hardware address */
	uint16_t ar_pro;   /* format of protocol address */
	uint8_t ar_hln;    /* length of hardware address */
	uint8_t ar_pln;    /* length of protocol address */
	uint16_t ar_op;    /* ARP opcode (command)       */
	uint8_t ar_sha[6]; /* sender hardware address    */
	uint8_t ar_sip[4]; /* sender IP address          */
	uint8_t ar_tha[6]; /* target hardware address    */
	uint8_t ar_tip[4]; /* target IP address          */
} __attribute__((packed));

#define ARPOP_REQUEST   1  /* ARP request                */
#define ARPOP_REPLY     2  /* ARP reply                  */
#define ARPOP_RREQUEST  3  /* RARP request               */
#define ARPOP_RREPLY    4  /* RARP reply                 */
#define ARPOP_InREQUEST 8  /* InARP request              */
#define ARPOP_InREPLY   9  /* InARP reply                */
#define ARPOP_NAK       10 /* (ATM)ARP NAK               */

static int arp_daemon(const char *dev)
{
	int fd_arp;
	size_t len, plen;
	struct sock_fprog bpf_ops;
	char *buff;

	len = device_mtu(dev);
	buff = xzmalloc(len);

	fd_arp = pf_socket();
	enable_kernel_bpf_jit_compiler();
	memset(&bpf_ops, 0, sizeof(bpf_ops));
	bpf_ops.filter = arp_type;
	bpf_ops.len = (sizeof(arp_type) / sizeof(arp_type[0]));
	bpf_attach_to_sock(fd_arp, &bpf_ops);
	while ((plen = recv(fd_arp, buff, len, 0)) > 0 &&
	       likely(!sigint)) {
		char *opcode = NULL;
		struct arphdr *arp = (struct arphdr *) (buff + 14);
		switch (ntohs(arp->ar_op)) {
		case ARPOP_REQUEST:
			opcode = "ARP request";
			break;
		case ARPOP_REPLY:
			opcode = "ARP reply";
		default:
			break;
		};
		printf("%s\n", opcode);
		memset(buff, 0, len);
	}
	close(fd_arp);

	return 0;
}

int main(int argc, char **argv)
{
	int c, opt_index, msock, ifflags;
	char *dev = NULL, *mdev = NULL;
	check_for_root_maybe_die();
	while ((c = getopt_long(argc, argv, short_options, long_options,
	       &opt_index)) != EOF) {
		switch (c) {
		case 'd':
		case 'i':
			dev = xstrdup(optarg);
			break;
		case 'm':
			mdev = xstrdup(optarg);
			break;
		case 'h':
			help();
			break;
		case 'v':
			version();
			break;
		case '?':
			switch (optopt) {
			case 'd':
			case 'i':
			case 'm':
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
	register_signal(SIGINT, signal_handler);
	register_signal(SIGHUP, signal_handler);
	if (!dev)
		panic("No networking device given!\n");
	if (!strncmp("lo", dev, IFNAMSIZ))
		panic("lo is not supported!\n");
	if (device_mtu(dev) == 0)
		panic("This is no networking device!\n");
	header();
	if (!mdev) {
		char *ptr = dev;
		while (!isdigit(*ptr) && *ptr != '\0')
			ptr++;
		if (*ptr == '\0') {
			mdev = xstrdup("mitm");
		} else {
			int num = atoi(ptr);
			size_t len = strlen("mitm") + strlen(ptr) + 1;
			mdev = xmalloc(len);
			snprintf(mdev, len, "mitm%d", num);
		}
	}
	printf("Chain %s --> %s --> %s\n", dev, mdev, dev);
	msock = tun_open_or_die(mdev, IFF_TAP);
	ifflags = enter_promiscuous_mode(dev);

	arp_daemon(dev);
	/* forw. daemon */

	leave_promiscuous_mode(dev, ifflags);
	close(msock);
	if (dev)
		xfree(dev);
	if (mdev)
		xfree(mdev);
	return 0;
}

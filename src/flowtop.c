/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL, version 2.
 *
 * A tiny tool to provide top-like UDP/TCP connection tracking information.
 *
 * Debian: apt-get install libnetfilter-conntrack3 libnetfilter-conntrack-dev
 *
 * Start conntrack:
 *   iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
 *   iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <pthread.h>
#include <curses.h>
#include <signal.h>
#include <netdb.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>
#include <GeoIP.h>
#include <GeoIPCity.h>
#include <netinet/in.h>

#include "die.h"
#include "signals.h"
#include "locking.h"
#include "timespec.h"

#ifndef IPPROTO_SCTP
# define IPPROTO_SCTP 132
#endif

#ifndef IPPROTO_UDPLITE
# define IPPROTO_UDPLITE 136
#endif

#ifndef IPPROTO_DCCP
# define IPPROTO_DCCP 33
#endif

#define INCLUDE_UDP	(1 << 0)
#define INCLUDE_TCP	(1 << 1)
#define INCLUDE_TCP_EST	(1 << 2)
#define INCLUDE_IP4	(1 << 3)
#define INCLUDE_IP6	(1 << 4)

#ifndef ATTR_TIMESTAMP_START
# define ATTR_TIMESTAMP_START 63
#endif
#ifndef ATTR_TIMESTAMP_STOP
# define ATTR_TIMESTAMP_STOP 64
#endif

struct flow_entry {
	uint32_t flow_id;
	struct flow_entry *next;
	uint32_t use;
	uint32_t status;
	uint8_t  l3_proto;
	uint8_t  l4_proto;
	uint32_t ip4_src_addr;
	uint32_t ip4_dst_addr;
	uint32_t ip6_src_addr[4];
	uint32_t ip6_dst_addr[4];
	uint16_t port_src;
	uint16_t port_dst;
	uint8_t  tcp_state;
	uint8_t  tcp_flags;
	uint64_t counter_pkts;
	uint64_t counter_bytes;
	uint64_t timestamp_start;
	uint64_t timestamp_stop;
	char country_src[128];
	char city_src[128];
	char rev_dns_src[256];
	char country_dst[128];
	char city_dst[128];
	char rev_dns_dst[256];
};

struct flow_list {
	struct flow_entry *head;
	unsigned long size;
	struct spinlock lock;
};

static sig_atomic_t sigint = 0;

static const char *short_options = "t:vhTU46";

static double interval = 0.2;

/* Default only TCP */
static int what = INCLUDE_TCP | INCLUDE_IP4 | INCLUDE_IP6;

static struct flow_list flow_list;

static GeoIP *gi_country = NULL;
static GeoIP *gi_city = NULL;

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

const char *const l3proto2str[AF_MAX] = {
	[AF_INET]			= "ipv4",
	[AF_INET6]			= "ipv6",
};

const char *const proto2str[IPPROTO_MAX] = {
	[IPPROTO_TCP]			= "tcp",
	[IPPROTO_UDP]			= "udp",
	[IPPROTO_UDPLITE]		= "udplite",
	[IPPROTO_ICMP]			= "icmp",
	[IPPROTO_ICMPV6]		= "icmpv6",
	[IPPROTO_SCTP]			= "sctp",
	[IPPROTO_GRE]			= "gre",
	[IPPROTO_DCCP]			= "dccp",
};

const char *const states[TCP_CONNTRACK_MAX] = {
	[TCP_CONNTRACK_NONE]		= "NONE",
	[TCP_CONNTRACK_SYN_SENT]	= "SYN_SENT",
	[TCP_CONNTRACK_SYN_RECV]	= "SYN_RECV",
	[TCP_CONNTRACK_ESTABLISHED]	= "ESTABLISHED",
	[TCP_CONNTRACK_FIN_WAIT]	= "FIN_WAIT",
	[TCP_CONNTRACK_CLOSE_WAIT]	= "CLOSE_WAIT",
	[TCP_CONNTRACK_LAST_ACK]	= "LAST_ACK",
	[TCP_CONNTRACK_TIME_WAIT]	= "TIME_WAIT",
	[TCP_CONNTRACK_CLOSE]		= "CLOSE",
	[TCP_CONNTRACK_SYN_SENT2]	= "SYN_SENT2",
};

static void signal_handler(int number)
{
	switch (number) {
	case SIGINT:
		sigint = 1;
		break;
	case SIGHUP:
	default:
		break;
	}
}

static void help(void)
{
	printf("\nflowtop %s, top-like TCP flow connection tracking\n",
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Usage: flowtop [options]\n");
	printf("Options:\n");
	printf("  -t|--interval <time>   Refresh time in sec (default 0.2)\n");
	printf("  -v|--version           Print version\n");
	printf("  -h|--help              Print this help\n");
	printf("\n");
	printf("Examples:\n");
	printf("  flowtop --interval 1.0\n");
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
	printf("\nflowtop %s, top-like TCP flow connection tracking\n",
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2011 Daniel Borkmann\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");
	die();
}

static void screen_init(WINDOW **screen)
{
	(*screen) = initscr();
	noecho();
	cbreak();
	nodelay((*screen), TRUE);
	refresh();
	wrefresh((*screen));
}

/* TODO: add scrolling! */
static void screen_update(WINDOW *screen, struct flow_list *fl)
{
	int line = 3;
	struct flow_entry *n;
	curs_set(0);
	clear();
	spinlock_lock(&fl->lock);
	mvwprintw(screen, 1, 2, "Kernel TCP flow statistics (%u flows), t=%.2lfs",
		  fl->size, interval);
	n = fl->head;
	while (n) {
		mvwprintw(screen, line, 2,
			  "%s:%s[%s]\t%s:%u (%s, %s) -> %s:%u (%s, %s)"
			  "                                           ",
		       l3proto2str[n->l3_proto], proto2str[n->l4_proto], states[n->tcp_state],
		       n->rev_dns_src, ntohs(n->port_src), n->country_src, n->city_src,
		       n->rev_dns_dst, ntohs(n->port_dst), n->country_dst, n->city_dst);

		line++;
		n = n->next;
	}
	spinlock_unlock(&fl->lock);
	wrefresh(screen);
	refresh();
}

static void screen_end(void)
{
	endwin();
}

static void presenter(void)
{
	WINDOW *screen = NULL;
	screen_init(&screen);
	while (!sigint) {
		if (getch() == 'q')
			break;
		screen_update(screen, &flow_list);
		xnanosleep(interval);
	}
	screen_end();
}

static inline const char *make_n_a(const char *p)
{
	return p ? : "N/A";
}

static void flow_entry_from_ct(struct flow_entry *n, struct nf_conntrack *ct)
{
	n->flow_id = nfct_get_attr_u32(ct, ATTR_ID);
	n->use = nfct_get_attr_u32(ct, ATTR_USE);
	n->status = nfct_get_attr_u32(ct, ATTR_STATUS);
	n->l3_proto = nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO);
	n->l4_proto = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
	n->ip4_src_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
	n->ip4_dst_addr = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);
	const uint8_t *ipv6_src = nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC);
	if (ipv6_src)
		memcpy(n->ip6_src_addr, ipv6_src, sizeof(n->ip6_src_addr));
	const uint8_t *ipv6_dst = nfct_get_attr(ct, ATTR_ORIG_IPV6_DST);
	if (ipv6_dst)
		memcpy(n->ip6_dst_addr, ipv6_dst, sizeof(n->ip6_dst_addr));
	n->port_src = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC);
	n->port_dst = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST);
	n->tcp_state = nfct_get_attr_u8(ct, ATTR_TCP_STATE);
	n->tcp_flags = nfct_get_attr_u8(ct, ATTR_TCP_FLAGS_ORIG);
	n->counter_pkts = nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_PACKETS);
	n->counter_bytes = nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_BYTES);
	n->timestamp_start = nfct_get_attr_u64(ct, ATTR_TIMESTAMP_START);
	n->timestamp_stop = nfct_get_attr_u64(ct, ATTR_TIMESTAMP_STOP);
}

/* TODO: IP4 + IP6, what about UDP? */
static void flow_entry_get_extended(struct flow_entry *n)
{
	struct sockaddr_in sa;
	struct hostent *hent;
	GeoIPRecord *gir_src, *gir_dst;
	if (n->flow_id == 0)
		return;
	if (ntohs(n->port_src) == 53 || ntohs(n->port_dst) == 53)
		return;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = PF_INET; //XXX: IPv4
	sa.sin_addr.s_addr = n->ip4_src_addr;
	getnameinfo((struct sockaddr *) &sa, sizeof(sa), n->rev_dns_src,
		    sizeof(n->rev_dns_src), NULL, 0, NI_NUMERICHOST);
	hent = gethostbyaddr(&sa.sin_addr, sizeof(sa.sin_addr), PF_INET);
	if (hent)
		memcpy(n->rev_dns_src, hent->h_name,
		       min(sizeof(n->rev_dns_src), strlen(hent->h_name)));
	gir_src = GeoIP_record_by_ipnum(gi_city, ntohl(n->ip4_src_addr));
	if (gir_src) {
		const char *country =
			make_n_a(GeoIP_country_name_by_ipnum(gi_country,
							     ntohl(n->ip4_src_addr)));
		const char *city = make_n_a(gir_src->city);
		memcpy(n->country_src, country,
		       min(sizeof(n->country_src), strlen(country)));
		memcpy(n->city_src, city,
		       min(sizeof(n->city_src), strlen(city)));
	}

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = PF_INET; //XXX: IPv4
	sa.sin_addr.s_addr = n->ip4_dst_addr;
	getnameinfo((struct sockaddr *) &sa, sizeof(sa), n->rev_dns_dst,
		    sizeof(n->rev_dns_dst), NULL, 0, NI_NUMERICHOST);
	hent = gethostbyaddr(&sa.sin_addr, sizeof(sa.sin_addr), PF_INET);
	if (hent)
		memcpy(n->rev_dns_dst, hent->h_name,
		       min(sizeof(n->rev_dns_dst), strlen(hent->h_name)));
	gir_dst = GeoIP_record_by_ipnum(gi_city, ntohl(n->ip4_dst_addr));
	if (gir_dst) {
		const char *country =
			make_n_a(GeoIP_country_name_by_ipnum(gi_country,
							     ntohl(n->ip4_dst_addr)));
		const char *city = make_n_a(gir_dst->city);
		memcpy(n->country_dst, country,
		       min(sizeof(n->country_dst), strlen(country)));
		memcpy(n->city_dst, city,
		       min(sizeof(n->city_dst), strlen(city)));
	}
}

static void flow_list_init(struct flow_list *fl)
{
	fl->head = NULL;
	fl->size = 0;
	spinlock_init(&fl->lock);
}

static struct flow_entry *__flow_list_find_by_id(struct flow_list *fl, uint32_t id)
{
	struct flow_entry *n = fl->head;
	while (n != NULL) {
		if (n->flow_id == id)
			return n;
		n = n->next;
	}
	return NULL;
}

static struct flow_entry *__flow_list_find_prev_by_id(struct flow_list *fl, uint32_t id)
{
	struct flow_entry *n = fl->head;
	if (n->flow_id == id)
		return NULL;
	while (n->next != NULL) {
		if (n->next->flow_id == id)
			return n;
		n = n->next;
	}
	return NULL;
}

static void flow_list_new_entry(struct flow_list *fl, struct nf_conntrack *ct)
{
	struct flow_entry *n = xzmalloc(sizeof(*n));
	spinlock_lock(&fl->lock);
	n->next = fl->head;
	fl->head = n;
	fl->size++;
	flow_entry_from_ct(n, ct);
	flow_entry_get_extended(n);
	spinlock_unlock(&fl->lock);
}

static void flow_list_update_entry(struct flow_list *fl, struct nf_conntrack *ct)
{
	int do_ext = 0;
	uint32_t id = nfct_get_attr_u32(ct, ATTR_ID);
	struct flow_entry *n;
	spinlock_lock(&fl->lock);
	n = __flow_list_find_by_id(fl, id);
	if (n == NULL) {
		n = xzmalloc(sizeof(*n));
		n->next = fl->head;
		fl->head = n;
		fl->size++;
		do_ext = 1;
	}
	flow_entry_from_ct(n, ct);
	if (do_ext)
		flow_entry_get_extended(n);
	spinlock_unlock(&fl->lock);
}

static void flow_list_destroy_entry(struct flow_list *fl, struct nf_conntrack *ct)
{
	uint32_t id = nfct_get_attr_u32(ct, ATTR_ID);
	struct flow_entry *n1, *n2;
	spinlock_lock(&fl->lock);
	n1 = __flow_list_find_by_id(fl, id);
	if (n1) {
		n2 = __flow_list_find_prev_by_id(fl, id);
		if (n2) {
			n2->next = n1->next;
			n1->next = NULL;
			xfree(n1);
		} else {
			xfree(fl->head);
			fl->head = NULL;
		}
		fl->size--;
	}
	spinlock_unlock(&fl->lock);
}

static void flow_list_destroy(struct flow_list *fl)
{
	struct flow_entry *n;
	spinlock_lock(&fl->lock);
	while (fl->head != NULL) {
		n = fl->head->next;
		fl->head->next = NULL;
		xfree(fl->head);
		fl->size--;
		fl->head = n;
	}
	spinlock_unlock(&fl->lock);
	spinlock_destroy(&fl->lock);
}

static int collector_cb(enum nf_conntrack_msg_type type,
			struct nf_conntrack *ct,
			void *data)
{
	if (sigint)
		return NFCT_CB_STOP;
	switch (type) {
	case NFCT_T_NEW:
		flow_list_new_entry(&flow_list, ct);
		break;
	case NFCT_T_UPDATE:
		flow_list_update_entry(&flow_list, ct);
		break;
	case NFCT_T_DESTROY:
		flow_list_destroy_entry(&flow_list, ct);
		break;
	default:
		break;
	}
	return NFCT_CB_CONTINUE;
}

static void *collector(void *null)
{
	int ret;
	struct nfct_handle *handle;
	struct nfct_filter *filter;
	handle = nfct_open(CONNTRACK, NFCT_ALL_CT_GROUPS);
	if (!handle)
		panic("Cannot create a nfct handle!\n");
	filter = nfct_filter_create();
	if (!filter)
		panic("Cannot create a nfct filter!\n");
	if (what & INCLUDE_UDP)
		nfct_filter_add_attr_u32(filter, NFCT_FILTER_L4PROTO, IPPROTO_UDP);
	if (what & INCLUDE_TCP)
		nfct_filter_add_attr_u32(filter, NFCT_FILTER_L4PROTO, IPPROTO_TCP);
	struct nfct_filter_ipv4 filter_ipv4 = {
		.addr = ntohl(inet_addr("127.0.0.1")),
		.mask = 0xffffffff,
	};
	nfct_filter_set_logic(filter, NFCT_FILTER_SRC_IPV4,
			      NFCT_FILTER_LOGIC_NEGATIVE);
	nfct_filter_add_attr(filter, NFCT_FILTER_SRC_IPV4, &filter_ipv4);
	struct nfct_filter_ipv6 filter_ipv6 = {
		.addr = { 0x0, 0x0, 0x0, 0x1 },
		.mask = { 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff },
	}; 
	nfct_filter_set_logic(filter, NFCT_FILTER_SRC_IPV6,
			      NFCT_FILTER_LOGIC_NEGATIVE);
	nfct_filter_add_attr(filter, NFCT_FILTER_SRC_IPV6, &filter_ipv6);
	ret = nfct_filter_attach(nfct_fd(handle), filter);
	if (ret < 0)
		panic("Cannot attach filter to handle!\n");
	nfct_filter_destroy(filter);
	gi_country = GeoIP_new(GEOIP_STANDARD);
	gi_city = GeoIP_open_type(GEOIP_CITY_EDITION_REV1, GEOIP_STANDARD);
	if (!gi_country || !gi_city)
		panic("Cannot open GeoIP database!\n");
	flow_list_init(&flow_list);
	nfct_callback_register(handle, NFCT_T_ALL, collector_cb, NULL);
	while (!sigint)
		nfct_catch(handle);
	flow_list_destroy(&flow_list);
	GeoIP_delete(gi_city);
	GeoIP_delete(gi_country);
	nfct_close(handle);
	pthread_exit(0);
}

int main(int argc, char **argv)
{
	pthread_t tid;
	int ret, c, opt_index, what_cmd = 0;
	while ((c = getopt_long(argc, argv, short_options, long_options,
	       &opt_index)) != EOF) {
		switch (c) {
		case 't':
			if (!optarg)
				help();
			interval = atof(optarg);
			if (interval < 0.1)
				panic("Choose larger interval!\n");
			break;
		case 'T':
			what_cmd |= INCLUDE_TCP;
			break;
		case 'U':
			what_cmd |= INCLUDE_UDP;
			break;
		case '4':
			what_cmd |= INCLUDE_IP4;
			break;
		case '6':
			what_cmd |= INCLUDE_IP6;
			break;
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
	if (what_cmd > 0)
		what = what_cmd;
	register_signal(SIGINT, signal_handler);
	register_signal(SIGHUP, signal_handler);
	ret = pthread_create(&tid, NULL, collector, NULL);
	if (ret < 0)
		panic("Cannot create phthread!\n");
	presenter();
	return 0;
}


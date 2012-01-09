/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL, version 2.
 *
 * A tiny tool to provide top-like netfilter connection
 * tracking information.
 *
 * Debian: apt-get install libnetfilter-conntrack3 libnetfilter-conntrack-dev
 *
 * Start conntrack (if not yet running):
 *   iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
 *   iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <netdb.h>
#include <iconv.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>
#include <GeoIP.h>
#include <GeoIPCity.h>
#include <netinet/in.h>
#include <curses.h>

#include "die.h"
#include "misc.h"
#include "signals.h"
#include "locking.h"
#include "timespec.h"
#include "dissector_eth.h"

#define INCLUDE_UDP	(1 << 0)
#define INCLUDE_TCP	(1 << 1)

#ifndef ATTR_TIMESTAMP_START
# define ATTR_TIMESTAMP_START 63
#endif
#ifndef ATTR_TIMESTAMP_STOP
# define ATTR_TIMESTAMP_STOP 64
#endif

#define SCROLL_MAX 1000

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

static const char *short_options = "t:vh";

static double interval = 0.1;

static int what = INCLUDE_TCP | INCLUDE_UDP;

static struct flow_list flow_list;

static GeoIP *gi_country = NULL;
static GeoIP *gi_city = NULL;

static struct option long_options[] = {
	{"interval", required_argument, 0, 't'},
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
	[IPPROTO_UDPLITE]               = "udplite",
	[IPPROTO_ICMP]                  = "icmp",
	[IPPROTO_ICMPV6]                = "icmpv6",
	[IPPROTO_SCTP]                  = "sctp",
	[IPPROTO_GRE]                   = "gre",
	[IPPROTO_DCCP]                  = "dccp",
	[IPPROTO_IGMP]			= "igmp",
	[IPPROTO_IPIP]			= "ipip",
	[IPPROTO_EGP]			= "egp",
	[IPPROTO_PUP]			= "pup",
	[IPPROTO_IDP]			= "idp",
	[IPPROTO_RSVP]			= "rsvp",
	[IPPROTO_IPV6]			= "ip6tun",
	[IPPROTO_ESP]			= "esp",
	[IPPROTO_AH]			= "ah",
	[IPPROTO_PIM]			= "pim",
	[IPPROTO_COMP]			= "comp",
};

const char *const state2str[TCP_CONNTRACK_MAX] = {
	[TCP_CONNTRACK_NONE]		= "NOSTATE",
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

const uint8_t states[] = {
	TCP_CONNTRACK_SYN_SENT,
	TCP_CONNTRACK_SYN_RECV,
	TCP_CONNTRACK_ESTABLISHED,
	TCP_CONNTRACK_FIN_WAIT,
	TCP_CONNTRACK_CLOSE_WAIT,
	TCP_CONNTRACK_LAST_ACK,
	TCP_CONNTRACK_TIME_WAIT,
	TCP_CONNTRACK_CLOSE,
	TCP_CONNTRACK_SYN_SENT2,
	TCP_CONNTRACK_NONE,
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
	printf("\nflowtop %s, top-like netfilter TCP/UDP flow tracking\n",
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Usage: flowtop [options]\n");
	printf("Options:\n");
	printf("  -t|--interval <time>   Refresh time in sec (default 0.1)\n");
	printf("  -v|--version           Print version\n");
	printf("  -h|--help              Print this help\n");
	printf("\n");
	printf("Examples:\n");
	printf("  flowtop --interval 0.5\n");
	printf("  flowtop\n\n");
	printf("Note:\n");
	printf("  If netfilter is not running, you can activate it with i.e.:\n");
	printf("   iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT\n");
	printf("   iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT\n");
	printf("\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2011 Daniel Borkmann <daniel@netsniff-ng.org>\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");
	die();
}

static void version(void)
{
	printf("\nflowtop %s, top-like netfilter TCP/UDP flow tracking\n",
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
	keypad(stdscr, TRUE);
	nodelay(*screen, TRUE);
	refresh();
	wrefresh(*screen);
}

static inline uint16_t get_port(uint16_t src, uint16_t dst)
{
	char *tmp1, *tmp2;
	src = ntohs(src);
	dst = ntohs(dst);
	/* XXX: Is there a better way to determine? */
	if (src < dst && src < 1024) {
		return src;
	} else if (dst < src && dst < 1024) {
		return dst;
	} else {
		tmp1 = lookup_port_tcp(src);
		tmp2 = lookup_port_tcp(dst);
		if (tmp1 && !tmp2) {
			return src;
		} else if (!tmp1 && tmp2) {
			return dst;
		} else {
			if (src < dst)
				return src;
			else
				return dst;
		}
	}
}

static void screen_update(WINDOW *screen, struct flow_list *fl, int skip_lines)
{
	int i, line = 3;
	int maxx, maxy;
	struct flow_entry *n;
	curs_set(0);
	getmaxyx(screen, maxy, maxx);
	start_color();
	init_pair(1, COLOR_RED, COLOR_BLACK);
	init_pair(2, COLOR_BLUE, COLOR_BLACK);
	init_pair(3, COLOR_YELLOW, COLOR_BLACK);
	init_pair(4, COLOR_GREEN, COLOR_BLACK);
	clear();
	spinlock_lock(&fl->lock);
	mvwprintw(screen, 1, 2, "Kernel netfilter TCP/UDP flow statistics, [+%d] t=%.2lfs",
		  skip_lines, interval);
	if (fl->head == NULL)
		mvwprintw(screen, line, 2, "(No active sessions! Is netfilter running?)");
	maxy -= 4;
	/* Yes, that's lame :-P */
	for (i = 0; i < sizeof(states); i++) {
		n = fl->head;
		while (n && maxy > 0) {
			if (n->tcp_state != states[i] ||
			    /* Filter out DNS */
			    get_port(n->port_src, n->port_dst) == 53) {
				n = n->next;
				continue;
			}
			if (skip_lines > 0) {
				n = n->next;
				skip_lines--;
				continue;
			}
			mvwprintw(screen, line, 2, "%s:%s[",
				  l3proto2str[n->l3_proto],
				  proto2str[n->l4_proto]);
			attron(COLOR_PAIR(3));
			printw("%s", state2str[n->tcp_state]);
			attroff(COLOR_PAIR(3));
			printw("]:");
			attron(A_BOLD);
			if (n->tcp_state != TCP_CONNTRACK_NONE) {
				printw("%s\t", lookup_port_tcp(get_port(n->port_src,
									n->port_dst)));
			} else {
				printw("%s\t", lookup_port_udp(get_port(n->port_src,
									n->port_dst)));
			}
			attroff(A_BOLD);
			attron(COLOR_PAIR(1));
			mvwprintw(screen, line, 35, "%s", n->rev_dns_src);
			attroff(COLOR_PAIR(1));
			printw(":%u (", ntohs(n->port_src));
			attron(COLOR_PAIR(4));
			printw("%s", (strlen(n->country_src) > 0 ?
			       n->country_src : "Unknown"));
			attroff(COLOR_PAIR(4));
			printw(", %s) => ", (strlen(n->city_src) > 0 ?
			       n->city_src : "Unknown"));
			attron(COLOR_PAIR(2));
			printw("%s", n->rev_dns_dst);
			attroff(COLOR_PAIR(2));
			printw(":%u (", ntohs(n->port_dst));
			attron(COLOR_PAIR(4));
			printw("%s", strlen(n->country_dst) > 0 ?
			       n->country_dst : "Unknown");
			attroff(COLOR_PAIR(4));
			printw(", %s)", strlen(n->city_dst) > 0 ?
			       n->city_dst : "Unknown");
			line++;
			maxy--;
			n = n->next;
		}
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
	int skip_lines = 0;
	WINDOW *screen = NULL;
	dissector_init_ethernet(0);
	screen_init(&screen);
	while (!sigint) {
		switch (getch()) {
		case 'q':
			sigint = 1;
			break;
		case KEY_UP:
		case 'u':
		case 'k':
			skip_lines--;
			if (skip_lines < 0)
				skip_lines = 0;
			break;
		case KEY_DOWN:
		case 'd':
		case 'j':
			skip_lines++;
			if (skip_lines > SCROLL_MAX)
				skip_lines = SCROLL_MAX;
			break;
		default:
			break;
		}
		screen_update(screen, &flow_list, skip_lines);
		fflush(stdin);
		xnanosleep(interval);
	}
	screen_end();
	dissector_cleanup_ethernet();
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

/* TODO: IP4 + IP6 */
static void flow_entry_get_extended(struct flow_entry *n)
{
	struct sockaddr_in sa;
	struct hostent *hent;
	GeoIPRecord *gir_src, *gir_dst;
	iconv_t conv;
	if (n->flow_id == 0)
		return;
	if (ntohs(n->port_src) == 53 || ntohs(n->port_dst) == 53)
		return;
	conv = iconv_open("UTF-8", "ISO8859-1");
	if (!conv || conv == (iconv_t)(-1))
		panic("Cannot open charet converter!\n");
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = PF_INET; //XXX: IPv4
	sa.sin_addr.s_addr = n->ip4_src_addr;
	getnameinfo((struct sockaddr *) &sa, sizeof(sa), n->rev_dns_src,
		    sizeof(n->rev_dns_src), NULL, 0, NI_NUMERICHOST);
	hent = gethostbyaddr(&sa.sin_addr, sizeof(sa.sin_addr), PF_INET);
	if (hent) {
		memset(n->rev_dns_src, 0, sizeof(n->rev_dns_src));
		memcpy(n->rev_dns_src, hent->h_name,
		       min(sizeof(n->rev_dns_src), strlen(hent->h_name)));
	}
	gir_src = GeoIP_record_by_ipnum(gi_city, ntohl(n->ip4_src_addr));
	if (gir_src) {
		char city_tmp[128], *ptr;
		size_t inl, outl;
		const char *country =
			make_n_a(GeoIP_country_name_by_ipnum(gi_country,
							     ntohl(n->ip4_src_addr)));
		const char *city = make_n_a(gir_src->city);
		inl = strlen(city);
		outl = sizeof(city_tmp);
		ptr = city_tmp;
		memset(city_tmp, 0, sizeof(city_tmp));
		iconv(conv, (char ** restrict) &city, &inl, &ptr, &outl);
		memcpy(n->country_src, country,
		       min(sizeof(n->country_src), strlen(country)));
		memcpy(n->city_src, city_tmp,
		       min(sizeof(n->city_src), strlen(city_tmp)));
	}
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = PF_INET; //XXX: IPv4
	sa.sin_addr.s_addr = n->ip4_dst_addr;
	getnameinfo((struct sockaddr *) &sa, sizeof(sa), n->rev_dns_dst,
		    sizeof(n->rev_dns_dst), NULL, 0, NI_NUMERICHOST);
	hent = gethostbyaddr(&sa.sin_addr, sizeof(sa.sin_addr), PF_INET);
	if (hent) {
		memset(n->rev_dns_dst, 0, sizeof(n->rev_dns_dst));
		memcpy(n->rev_dns_dst, hent->h_name,
		       min(sizeof(n->rev_dns_dst), strlen(hent->h_name)));
	}
	gir_dst = GeoIP_record_by_ipnum(gi_city, ntohl(n->ip4_dst_addr));
	if (gir_dst) {
		char city_tmp[128], *ptr;
		size_t inl, outl;
		const char *country =
			make_n_a(GeoIP_country_name_by_ipnum(gi_country,
							     ntohl(n->ip4_dst_addr)));
		const char *city = make_n_a(gir_dst->city);
		inl = strlen(city);
		outl = sizeof(city_tmp);
		ptr = city_tmp;
		memset(city_tmp, 0, sizeof(city_tmp));
		iconv(conv, (char ** restrict) &city, &inl, &ptr, &outl);
		memcpy(n->country_dst, country,
		       min(sizeof(n->country_dst), strlen(country)));
		memcpy(n->city_dst, city_tmp,
		       min(sizeof(n->city_dst), strlen(city_tmp)));
	}
	iconv_close(conv);
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

static int dummy_cb(enum nf_conntrack_msg_type type, struct nf_conntrack *ct,
		    void *data)
{
	return NFCT_CB_STOP;
}

static void *collector(void *null)
{
	int ret;
	u_int32_t family = AF_INET;
	struct nfct_handle *handle;
	struct nfct_filter *filter;
	handle = nfct_open(CONNTRACK, NFCT_ALL_CT_GROUPS);
	if (!handle)
		panic("Cannot create a nfct handle!\n");
	nfct_callback_register(handle, NFCT_T_ALL, dummy_cb, NULL);
	nfct_query(handle, NFCT_Q_DUMP, &family);
	filter = nfct_filter_create();
	if (!filter)
		panic("Cannot create a nfct filter!\n");
	if (what & INCLUDE_UDP)
		nfct_filter_add_attr_u32(filter, NFCT_FILTER_L4PROTO, IPPROTO_UDP);
	if (what & INCLUDE_TCP)
		nfct_filter_add_attr_u32(filter, NFCT_FILTER_L4PROTO, IPPROTO_TCP);
	struct nfct_filter_ipv4 filter_ipv4 = {
		.addr = ntohl(INADDR_LOOPBACK),
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
	check_for_root_maybe_die();
	while ((c = getopt_long(argc, argv, short_options, long_options,
	       &opt_index)) != EOF) {
		switch (c) {
		case 't':
			if (!optarg)
				help();
			interval = atof(optarg);
			if (interval < 0.01)
				panic("Choose larger interval!\n");
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


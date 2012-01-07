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
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

#include "die.h"
#include "signals.h"
#include "locking.h"
#include "timespec.h"

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
	/* ... geoip data ... */
	/* ... rev dns ... */
};

struct flow_list {
	struct flow_entry *head;
	unsigned long size;
	struct spinlock lock;
};

static sig_atomic_t sigint = 0;

static const char *short_options = "t:vhTU46";

static double interval = 1.0;

static int what = INCLUDE_UDP | INCLUDE_TCP | INCLUDE_IP4 | INCLUDE_IP6;

static struct flow_list flow_list;

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
	default:
		break;
	}
}

static void help(void)
{
	printf("\nflowtop %s, top-like flow connection tracking\n",
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
	printf("\nflowtop %s, top-like flow connection tracking\n",
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2011 Daniel Borkmann\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");
	die();
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
	spinlock_unlock(&fl->lock);
}

static void flow_list_update_entry(struct flow_list *fl, struct nf_conntrack *ct)
{
	uint32_t id = nfct_get_attr_u32(ct, ATTR_ID);
	struct flow_entry *n;
	spinlock_lock(&fl->lock);
	n = __flow_list_find_by_id(fl, id);
	if (n == NULL) {
		n = xzmalloc(sizeof(*n));
		n->next = fl->head;
		fl->head = n;
		fl->size++;
	}
	flow_entry_from_ct(n, ct);
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

static void screen_init(WINDOW **screen)
{
	(*screen) = initscr();
	noecho();
	cbreak();
	nodelay((*screen), TRUE);
	refresh();
	wrefresh((*screen));
}

static void screen_update(WINDOW *screen, struct flow_list *fl)
{
	int line = 0;
	struct flow_entry *n;
	curs_set(0);
	spinlock_lock(&fl->lock);
	mvwprintw(screen, 1, 2, "Kernel flow statistics (%u flows), t=%.2lfs %p",
		  fl->size, interval, fl->head);
//	n = fl->head;
//	while (n) {
//		mvwprintw(screen, line, 2, "  %u -> %u", n->ip4_src_addr, n->ip4_dst_addr);
//		line++;
//		n = n->next;
//	}
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
	ret = nfct_filter_attach(nfct_fd(handle), filter);
	if (ret < 0)
		panic("Cannot attach filter to handle!\n");
	nfct_filter_destroy(filter);
	flow_list_init(&flow_list);
	nfct_callback_register(handle, NFCT_T_ALL, collector_cb, NULL);
	ret = nfct_catch(handle);
	if (ret < 0)
		panic("Error in nfct_catch!\n");
	flow_list_destroy(&flow_list);
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


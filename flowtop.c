/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2011 - 2013 Daniel Borkmann.
 * Copyright 2011 Emmanuel Roullit.
 * Subject to the GPL, version 2.
 */

#define _LGPL_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <netdb.h>
#include <ctype.h>
#include <netinet/in.h>
#include <curses.h>
#include <sys/time.h>
#include <sys/fsuid.h>
#include <libgen.h>
#include <inttypes.h>
#include <poll.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include <urcu.h>
#include <urcu/list.h>
#include <urcu/rculist.h>

#include "ui.h"
#include "die.h"
#include "xmalloc.h"
#include "conntrack.h"
#include "config.h"
#include "str.h"
#include "sig.h"
#include "lookup.h"
#include "geoip.h"
#include "built_in.h"
#include "pkt_buff.h"
#include "screen.h"
#include "proc.h"
#include "sysctl.h"

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC 1000000000L
#endif

#ifndef USEC_PER_SEC
#define USEC_PER_SEC 1000000L
#endif

struct flow_stat {
	uint64_t pkts_src, bytes_src;
	uint64_t pkts_dst, bytes_dst;
	double rate_bytes_src;
	double rate_bytes_dst;
	double rate_pkts_src;
	double rate_pkts_dst;
};

struct proc_entry {
	struct cds_list_head entry;
	struct cds_list_head flows;
	struct rcu_head rcu;

	struct timeval last_update;
	struct flow_stat stat;
	unsigned int pid;
	char name[256];
	int flows_count;
};

struct flow_entry {
	struct cds_list_head proc_head;
	struct cds_list_head entry;
	struct rcu_head rcu;

	uint32_t flow_id, use, status;
	uint8_t  l3_proto, l4_proto;
	uint32_t ip4_src_addr, ip4_dst_addr;
	uint32_t ip6_src_addr[4], ip6_dst_addr[4];
	uint16_t port_src, port_dst;
	uint8_t  tcp_state, tcp_flags, sctp_state, dccp_state;
	uint64_t timestamp_start, timestamp_stop;
	char country_src[128], country_dst[128];
	char country_code_src[4], country_code_dst[4];
	char city_src[128], city_dst[128];
	char rev_dns_src[256], rev_dns_dst[256];
	struct proc_entry *proc;
	int inode;
	bool is_visible;
	struct nf_conntrack *ct;
	struct timeval last_update;
	struct flow_stat stat;
};

struct flow_list {
	struct cds_list_head head;
};

struct proc_list {
	struct cds_list_head head;
};

enum flow_direction {
	FLOW_DIR_SRC,
	FLOW_DIR_DST,
};

#ifndef ATTR_TIMESTAMP_START
# define ATTR_TIMESTAMP_START 63
#endif
#ifndef ATTR_TIMESTAMP_STOP
# define ATTR_TIMESTAMP_STOP 64
#endif

#define INCLUDE_IPV4	(1 << 0)
#define INCLUDE_IPV6	(1 << 1)
#define INCLUDE_UDP	(1 << 2)
#define INCLUDE_TCP	(1 << 3)
#define INCLUDE_DCCP	(1 << 4)
#define INCLUDE_ICMP	(1 << 5)
#define INCLUDE_SCTP	(1 << 6)

#define TOGGLE_FLAG(what, flag) \
do { 				\
	if (what & flag) 	\
		what &= ~flag; 	\
	else 			\
		what |= flag;	\
} while (0)

struct sysctl_params_ctx {
	int nfct_acct;
	int nfct_tstamp;
};

enum rate_units {
	RATE_BITS,
	RATE_BYTES
};

static volatile bool do_reload_flows;
static volatile bool is_flow_collecting;
static volatile sig_atomic_t sigint = 0;
static int what = INCLUDE_IPV4 | INCLUDE_IPV6 | INCLUDE_TCP;
static struct proc_list proc_list;
static struct flow_list flow_list;
static struct sysctl_params_ctx sysctl = { -1, -1 };

static unsigned int cols, rows;
static WINDOW *screen;

static unsigned int interval = 1;
static bool show_src = false;
static bool resolve_dns = true;
static bool resolve_geoip = true;
static enum rate_units rate_type = RATE_BYTES;
static bool show_active_only = false;

enum tbl_flow_col {
	TBL_FLOW_PROCESS,
	TBL_FLOW_PID,
	TBL_FLOW_PROTO,
	TBL_FLOW_STATE,
	TBL_FLOW_TIME,
	TBL_FLOW_ADDRESS,
	TBL_FLOW_PORT,
	TBL_FLOW_GEO,
	TBL_FLOW_BYTES,
	TBL_FLOW_RATE,
};

enum tbl_proc_col {
	TBL_PROC_NAME,
	TBL_PROC_PID,
	TBL_PROC_FLOWS,
	TBL_PROC_BYTES_SRC,
	TBL_PROC_RATE_SRC,
	TBL_PROC_BYTES_DST,
	TBL_PROC_RATE_DST,
};

static struct ui_table flows_tbl;
static struct ui_table procs_tbl;
static struct ui_table *curr_tbl;

enum tab_entry {
	TAB_FLOWS,
	TAB_PROCS,
};

#define list_first_or_next(__ptr, __head, __entry) \
({ \
	struct cds_list_head *h; \
	if (!__ptr) \
		h = rcu_dereference((__head)->next); \
	else if (rcu_dereference(__ptr->__entry.next) == (__head)) \
		return NULL; \
	else \
		h = rcu_dereference(__ptr->__entry.next); \
	cds_list_entry(h, __typeof(* (__ptr)), __entry); \
})

static const char *short_options = "vhTUsDIS46ut:nGb";
static const struct option long_options[] = {
	{"ipv4",	no_argument,		NULL, '4'},
	{"ipv6",	no_argument,		NULL, '6'},
	{"tcp",		no_argument,		NULL, 'T'},
	{"udp",		no_argument,		NULL, 'U'},
	{"dccp",	no_argument,		NULL, 'D'},
	{"icmp",	no_argument,		NULL, 'I'},
	{"sctp",	no_argument,		NULL, 'S'},
	{"no-dns",      no_argument,		NULL, 'n'},
	{"no-geoip",    no_argument,		NULL, 'G'},
	{"show-src",	no_argument,		NULL, 's'},
	{"bits",        no_argument,		NULL, 'b'},
	{"update",	no_argument,		NULL, 'u'},
	{"interval",    required_argument,	NULL, 't'},
	{"version",	no_argument,		NULL, 'v'},
	{"help",	no_argument,		NULL, 'h'},
	{NULL, 0, NULL, 0}
};

static const char *copyright =
	"Please report bugs at https://github.com/netsniff-ng/netsniff-ng/issues\n"
	"Copyright (C) 2011-2013 Daniel Borkmann <dborkma@tik.ee.ethz.ch>\n"
	"Copyright (C) 2011-2012 Emmanuel Roullit <emmanuel.roullit@gmail.com>\n"
	"Swiss federal institute of technology (ETH Zurich)\n"
	"License: GNU GPL version 2.0\n"
	"This is free software: you are free to change and redistribute it.\n"
	"There is NO WARRANTY, to the extent permitted by law.";

static const char *const l4proto2str[IPPROTO_MAX] = {
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

static const char *const tcp_state2str[TCP_CONNTRACK_MAX] = {
	[TCP_CONNTRACK_NONE]		= "NONE",
	[TCP_CONNTRACK_SYN_SENT]	= "SYN-SENT",
	[TCP_CONNTRACK_SYN_RECV]	= "SYN-RECV",
	[TCP_CONNTRACK_ESTABLISHED]	= "ESTABLISHED",
	[TCP_CONNTRACK_FIN_WAIT]	= "FIN-WAIT",
	[TCP_CONNTRACK_CLOSE_WAIT]	= "CLOSE-WAIT",
	[TCP_CONNTRACK_LAST_ACK]	= "LAST-ACK",
	[TCP_CONNTRACK_TIME_WAIT]	= "TIME-WAIT",
	[TCP_CONNTRACK_CLOSE]		= "CLOSE",
	[TCP_CONNTRACK_SYN_SENT2]	= "SYN-SENT2",
};

static const char *const dccp_state2str[DCCP_CONNTRACK_MAX] = {
	[DCCP_CONNTRACK_NONE]		= "NONE",
	[DCCP_CONNTRACK_REQUEST]	= "REQUEST",
	[DCCP_CONNTRACK_RESPOND]	= "RESPOND",
	[DCCP_CONNTRACK_PARTOPEN]	= "PARTOPEN",
	[DCCP_CONNTRACK_OPEN]		= "OPEN",
	[DCCP_CONNTRACK_CLOSEREQ]	= "CLOSE-REQ",
	[DCCP_CONNTRACK_CLOSING]	= "CLOSING",
	[DCCP_CONNTRACK_TIMEWAIT]	= "TIME-WAIT",
	[DCCP_CONNTRACK_IGNORE]		= "IGNORE",
	[DCCP_CONNTRACK_INVALID]	= "INVALID",
};

static const char *const sctp_state2str[SCTP_CONNTRACK_MAX] = {
	[SCTP_CONNTRACK_NONE]		= "NONE",
	[SCTP_CONNTRACK_CLOSED]		= "CLOSED",
	[SCTP_CONNTRACK_COOKIE_WAIT]	= "COOKIE-WAIT",
	[SCTP_CONNTRACK_COOKIE_ECHOED]	= "COOKIE-ECHO",
	[SCTP_CONNTRACK_ESTABLISHED]	= "ESTABLISHED",
	[SCTP_CONNTRACK_SHUTDOWN_SENT]	= "SHUTD-SENT",
	[SCTP_CONNTRACK_SHUTDOWN_RECD]	= "SHUTD-RCVD",
	[SCTP_CONNTRACK_SHUTDOWN_ACK_SENT] = "SHUTD-ACK",
};

static const struct nfct_filter_ipv4 filter_ipv4 = {
	.addr = __constant_htonl(INADDR_LOOPBACK),
	.mask = 0xffffffff,
};

static const struct nfct_filter_ipv6 filter_ipv6 = {
	.addr = { 0x0, 0x0, 0x0, 0x1 },
	.mask = { 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff },
};

static int64_t time_after_us(struct timeval *tv)
{
	struct timeval now;

	bug_on(gettimeofday(&now, NULL));

	now.tv_sec  -= tv->tv_sec;
	now.tv_usec -= tv->tv_usec;

	return now.tv_sec * USEC_PER_SEC + now.tv_usec;
}

static void signal_handler(int number)
{
	switch (number) {
	case SIGINT:
	case SIGQUIT:
	case SIGTERM:
		sigint = 1;
		break;
	case SIGHUP:
	default:
		break;
	}
}

static void flow_entry_from_ct(struct flow_entry *n, const struct nf_conntrack *ct);
static void flow_entry_get_extended(struct flow_entry *n);

static void help(void)
{
	printf("flowtop %s, top-like netfilter TCP/UDP/SCTP/.. flow tracking\n",
	       VERSION_STRING);
	puts("http://www.netsniff-ng.org\n\n"
	     "Usage: flowtop [options]\n"
	     "Options:\n"
	     "  -4|--ipv4              Show only IPv4 flows (default)\n"
	     "  -6|--ipv6              Show only IPv6 flows (default)\n"
	     "  -T|--tcp               Show only TCP flows (default)\n"
	     "  -U|--udp               Show only UDP flows\n"
	     "  -D|--dccp              Show only DCCP flows\n"
	     "  -I|--icmp              Show only ICMP/ICMPv6 flows\n"
	     "  -S|--sctp              Show only SCTP flows\n"
	     "  -n|--no-dns            Don't perform hostname lookup\n"
	     "  -G|--no-geoip          Don't perform GeoIP lookup\n"
	     "  -s|--show-src          Also show source, not only dest\n"
	     "  -b|--bits              Show rates in bits/s instead of bytes/s\n"
	     "  -u|--update            Update GeoIP databases\n"
	     "  -t|--interval <time>   Refresh time in seconds (default 1s)\n"
	     "  -v|--version           Print version and exit\n"
	     "  -h|--help              Print this help and exit\n\n"
	     "Examples:\n"
	     "  flowtop\n"
	     "  flowtop -46UTDISs\n\n"
	     "Note:\n"
	     "  If netfilter is not running, you can activate it with e.g.:\n"
	     "   iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT\n"
	     "   iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT\n");
	puts(copyright);
	die();
}

static void version(void)
{
	printf("flowtop %s, Git id: %s\n", VERSION_LONG, GITVERSION);
	puts("top-like netfilter TCP/UDP/SCTP/.. flow tracking\n"
	     "http://www.netsniff-ng.org\n");
	puts(copyright);
	die();
}

static void flow_entry_update_time(struct flow_entry *n)
{
	bug_on(gettimeofday(&n->last_update, NULL));
}

#define CALC_RATE(fld) do {					\
	n->stat.rate_##fld = (((fld) > n->stat.fld) ?		\
			(((fld) - n->stat.fld) / sec) : 0);	\
} while (0)

static void flow_entry_calc_rate(struct flow_entry *n, const struct nf_conntrack *ct)
{
	uint64_t bytes_src = nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_BYTES);
	uint64_t bytes_dst = nfct_get_attr_u64(ct, ATTR_REPL_COUNTER_BYTES);
	uint64_t pkts_src  = nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_PACKETS);
	uint64_t pkts_dst  = nfct_get_attr_u64(ct, ATTR_REPL_COUNTER_PACKETS);
	double sec = (double)time_after_us(&n->last_update) / USEC_PER_SEC;

	if (sec < 1)
		return;

	CALC_RATE(bytes_src);
	CALC_RATE(bytes_dst);
	CALC_RATE(pkts_src);
	CALC_RATE(pkts_dst);
}

static inline struct flow_entry *flow_entry_xalloc(void)
{
	return xzmalloc(sizeof(struct flow_entry));
}

static inline void flow_entry_xfree(struct flow_entry *n)
{
	if (n->ct)
		nfct_destroy(n->ct);

	xfree(n);
}

static void flow_entry_xfree_rcu(struct rcu_head *head)
{
	struct flow_entry *n = container_of(head, struct flow_entry, rcu);

	flow_entry_xfree(n);
}

static inline void flow_list_init(struct flow_list *fl)
{
	CDS_INIT_LIST_HEAD(&fl->head);
}

static inline bool nfct_is_dns(const struct nf_conntrack *ct)
{
	uint16_t port_src = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC);
	uint16_t port_dst = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST);

	return ntohs(port_src) == 53 || ntohs(port_dst) == 53;
}

static int flow_list_new_entry(struct flow_list *fl, struct nf_conntrack *ct)
{
	struct flow_entry *n;

	/* We don't want to analyze / display DNS itself, since we
	 * use it to resolve reverse dns.
	 */
	if (nfct_is_dns(ct))
		return NFCT_CB_CONTINUE;

	n = flow_entry_xalloc();

	n->ct = ct;

	flow_entry_update_time(n);
	flow_entry_from_ct(n, ct);
	flow_entry_get_extended(n);

	cds_list_add_rcu(&n->entry, &fl->head);

	n->is_visible = true;

	return NFCT_CB_STOLEN;
}

static struct flow_entry *flow_list_find_id(struct flow_list *fl, uint32_t id)
{
	struct flow_entry *n;

	cds_list_for_each_entry_rcu(n, &fl->head, entry) {
		if (n->flow_id == id)
			return n;
	}

	return NULL;
}

static void __flow_list_del_entry(struct flow_list *fl, struct flow_entry *n)
{
	if (n->proc) {
		cds_list_del_rcu(&n->proc_head);
		n->proc->flows_count--;
	}

	cds_list_del_rcu(&n->entry);
	call_rcu(&n->rcu, flow_entry_xfree_rcu);
}

static int flow_list_del_entry(struct flow_list *fl, const struct nf_conntrack *ct)
{
	struct flow_entry *n;

	n = flow_list_find_id(fl, nfct_get_attr_u32(ct, ATTR_ID));
	if (n)
		__flow_list_del_entry(fl, n);

	return NFCT_CB_CONTINUE;
}

static void flow_list_destroy(struct flow_list *fl)
{
	struct flow_entry *n, *tmp;

	cds_list_for_each_entry_safe(n, tmp, &fl->head, entry)
		__flow_list_del_entry(fl, n);
}

static void proc_list_init(struct proc_list *proc_list)
{
	CDS_INIT_LIST_HEAD(&proc_list->head);
}

static struct proc_entry *proc_list_new_entry(unsigned int pid)
{
	struct proc_entry *proc;

	cds_list_for_each_entry(proc, &proc_list.head, entry) {
		if (proc->pid && proc->pid == pid)
			return proc;
	}

	proc = xzmalloc(sizeof(*proc));

	bug_on(gettimeofday(&proc->last_update, NULL));
	CDS_INIT_LIST_HEAD(&proc->flows);
	proc->pid = pid;

	cds_list_add_tail(&proc->entry, &proc_list.head);

	return proc;
}

static void proc_entry_xfree_rcu(struct rcu_head *head)
{
	struct proc_entry *p = container_of(head, struct proc_entry, rcu);

	xfree(p);
}

static void proc_list_destroy(struct proc_list *pl)
{
	struct proc_entry *p, *tmp;

	cds_list_for_each_entry_safe(p, tmp, &pl->head, entry) {
		cds_list_del_rcu(&p->entry);
		call_rcu(&p->rcu, proc_entry_xfree_rcu);
	}
}

static void flow_entry_find_process(struct flow_entry *n)
{
	struct proc_entry *p;
	char cmdline[512];
	pid_t pid;
	int ret;

	ret = proc_find_by_inode(n->inode, cmdline, sizeof(cmdline), &pid);
	if (ret <= 0)
		return;

	p = proc_list_new_entry(pid);

	if (snprintf(p->name, sizeof(p->name), "%s", basename(cmdline)) < 0)
		p->name[0] = '\0';

	p->stat.pkts_src += n->stat.pkts_src;
	p->stat.pkts_dst += n->stat.pkts_dst;
	p->stat.bytes_src += n->stat.bytes_src;
	p->stat.bytes_dst += n->stat.bytes_dst;
	p->flows_count++;

	cds_list_add_rcu(&n->proc_head, &p->flows);
	n->proc = p;
}

static int get_port_inode(uint16_t port, int proto, bool is_ip6)
{
	int ret = -ENOENT;
	char path[128], buff[1024];
	FILE *proc;

	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), "/proc/net/%s%s",
		 l4proto2str[proto], is_ip6 ? "6" : "");

	proc = fopen(path, "r");
	if (!proc)
		return -EIO;

	memset(buff, 0, sizeof(buff));

	while (fgets(buff, sizeof(buff), proc) != NULL) {
		int inode = 0;
		unsigned int lport = 0;

		buff[sizeof(buff) - 1] = 0;
		if (sscanf(buff, "%*u: %*X:%X %*X:%*X %*X %*X:%*X %*X:%*X "
			   "%*X %*u %*u %u", &lport, &inode) == 2) {
			if ((uint16_t) lport == port) {
				ret = inode;
				break;
			}
		}

		memset(buff, 0, sizeof(buff));
	}

	fclose(proc);
	return ret;
}

#define CP_NFCT(elem, attr, x)				\
	do { n->elem = nfct_get_attr_u##x(ct,(attr)); } while (0)
#define CP_NFCT_BUFF(elem, attr) do {			\
	const uint8_t *buff = nfct_get_attr(ct,(attr));	\
	if (buff != NULL)				\
		memcpy(n->elem, buff, sizeof(n->elem));	\
} while (0)

static void flow_entry_from_ct(struct flow_entry *n, const struct nf_conntrack *ct)
{
	uint64_t bytes_src = nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_BYTES);
	uint64_t bytes_dst = nfct_get_attr_u64(ct, ATTR_REPL_COUNTER_BYTES);
	uint64_t pkts_src  = nfct_get_attr_u64(ct, ATTR_ORIG_COUNTER_PACKETS);
	uint64_t pkts_dst  = nfct_get_attr_u64(ct, ATTR_REPL_COUNTER_PACKETS);

	/* Update stats diff to the related process entry */
	if (n->proc) {
		n->proc->stat.pkts_src += pkts_src - n->stat.pkts_src;
		n->proc->stat.pkts_dst += pkts_dst - n->stat.pkts_dst;
		n->proc->stat.bytes_src += bytes_src - n->stat.bytes_src;
		n->proc->stat.bytes_dst += bytes_dst - n->stat.bytes_dst;
	}

	CP_NFCT(l3_proto, ATTR_ORIG_L3PROTO, 8);
	CP_NFCT(l4_proto, ATTR_ORIG_L4PROTO, 8);

	CP_NFCT(ip4_src_addr, ATTR_ORIG_IPV4_SRC, 32);
	CP_NFCT(ip4_dst_addr, ATTR_ORIG_IPV4_DST, 32);

	CP_NFCT(port_src, ATTR_ORIG_PORT_SRC, 16);
	CP_NFCT(port_dst, ATTR_ORIG_PORT_DST, 16);

	CP_NFCT(status, ATTR_STATUS, 32);

	CP_NFCT(tcp_state, ATTR_TCP_STATE, 8);
	CP_NFCT(tcp_flags, ATTR_TCP_FLAGS_ORIG, 8);
	CP_NFCT(sctp_state, ATTR_SCTP_STATE, 8);
	CP_NFCT(dccp_state, ATTR_DCCP_STATE, 8);

	CP_NFCT(stat.pkts_src, ATTR_ORIG_COUNTER_PACKETS, 64);
	CP_NFCT(stat.bytes_src, ATTR_ORIG_COUNTER_BYTES, 64);

	CP_NFCT(stat.pkts_dst, ATTR_REPL_COUNTER_PACKETS, 64);
	CP_NFCT(stat.bytes_dst, ATTR_REPL_COUNTER_BYTES, 64);

	CP_NFCT(timestamp_start, ATTR_TIMESTAMP_START, 64);
	CP_NFCT(timestamp_stop, ATTR_TIMESTAMP_STOP, 64);

	CP_NFCT(flow_id, ATTR_ID, 32);
	CP_NFCT(use, ATTR_USE, 32);

	CP_NFCT_BUFF(ip6_src_addr, ATTR_ORIG_IPV6_SRC);
	CP_NFCT_BUFF(ip6_dst_addr, ATTR_ORIG_IPV6_DST);

	n->port_src = ntohs(n->port_src);
	n->port_dst = ntohs(n->port_dst);

	n->ip4_src_addr = ntohl(n->ip4_src_addr);
	n->ip4_dst_addr = ntohl(n->ip4_dst_addr);
}

#define SELFLD(dir,src_member,dst_member)	\
	(((dir) == FLOW_DIR_SRC) ? n->src_member : n->dst_member)

static void flow_entry_get_sain4_obj(const struct flow_entry *n,
				     enum flow_direction dir,
				     struct sockaddr_in *sa)
{
	memset(sa, 0, sizeof(*sa));
	sa->sin_family = PF_INET;
	sa->sin_addr.s_addr = htonl(SELFLD(dir, ip4_src_addr, ip4_dst_addr));
}

static void flow_entry_get_sain6_obj(const struct flow_entry *n,
				     enum flow_direction dir,
				     struct sockaddr_in6 *sa)
{
	memset(sa, 0, sizeof(*sa));
	sa->sin6_family = PF_INET6;

	memcpy(&sa->sin6_addr, SELFLD(dir, ip6_src_addr, ip6_dst_addr),
	       sizeof(sa->sin6_addr));
}

static void
flow_entry_geo_city_lookup_generic(struct flow_entry *n,
				   enum flow_direction dir)
{
	struct sockaddr_in sa4;
	struct sockaddr_in6 sa6;
	char *city = NULL;

	switch (n->l3_proto) {
	default:
		bug();

	case AF_INET:
		flow_entry_get_sain4_obj(n, dir, &sa4);
		city = geoip4_city_name(&sa4);
		break;

	case AF_INET6:
		flow_entry_get_sain6_obj(n, dir, &sa6);
		city = geoip6_city_name(&sa6);
		break;
	}

	build_bug_on(sizeof(n->city_src) != sizeof(n->city_dst));

	if (city)
		strlcpy(SELFLD(dir, city_src, city_dst), city,
		        sizeof(n->city_src));
	else
		SELFLD(dir, city_src, city_dst)[0] = '\0';

	free(city);
}

static void
flow_entry_geo_country_lookup_generic(struct flow_entry *n,
				      enum flow_direction dir)
{
	struct sockaddr_in sa4;
	struct sockaddr_in6 sa6;
	const char *country = NULL;
	const char *country_code = NULL;

	switch (n->l3_proto) {
	default:
		bug();

	case AF_INET:
		flow_entry_get_sain4_obj(n, dir, &sa4);
		country = geoip4_country_name(&sa4);
		country_code = geoip4_country_code3_name(&sa4);
		break;

	case AF_INET6:
		flow_entry_get_sain6_obj(n, dir, &sa6);
		country = geoip6_country_name(&sa6);
		country_code = geoip6_country_code3_name(&sa6);
		break;
	}

	build_bug_on(sizeof(n->country_src) != sizeof(n->country_dst));

	if (country)
		strlcpy(SELFLD(dir, country_src, country_dst), country,
		        sizeof(n->country_src));
	else
		SELFLD(dir, country_src, country_dst)[0] = '\0';

	build_bug_on(sizeof(n->country_code_src) != sizeof(n->country_code_dst));

	if (country_code)
		strlcpy(SELFLD(dir, country_code_src, country_code_dst),
			country_code, sizeof(n->country_code_src));
	else
		SELFLD(dir, country_code_src, country_code_dst)[0] = '\0';
}

static void flow_entry_get_extended_geo(struct flow_entry *n,
					enum flow_direction dir)
{
	if (resolve_geoip) {
		flow_entry_geo_city_lookup_generic(n, dir);
		flow_entry_geo_country_lookup_generic(n, dir);
	}
}

static void flow_entry_get_extended_revdns(struct flow_entry *n,
					   enum flow_direction dir)
{
	size_t sa_len;
	struct sockaddr_in sa4;
	struct sockaddr_in6 sa6;
	struct sockaddr *sa;
	struct hostent *hent;

	build_bug_on(sizeof(n->rev_dns_src) != sizeof(n->rev_dns_dst));

	switch (n->l3_proto) {
	default:
		bug();

	case AF_INET:
		flow_entry_get_sain4_obj(n, dir, &sa4);

		if (!resolve_dns) {
			inet_ntop(AF_INET, &sa4.sin_addr,
				  SELFLD(dir, rev_dns_src, rev_dns_dst),
				  sizeof(n->rev_dns_src));
			return;
		}

		sa = (struct sockaddr *) &sa4;
		sa_len = sizeof(sa4);
		hent = gethostbyaddr(&sa4.sin_addr, sizeof(sa4.sin_addr), AF_INET);
		break;

	case AF_INET6:
		flow_entry_get_sain6_obj(n, dir, &sa6);

		if (!resolve_dns) {
			inet_ntop(AF_INET6, &sa6.sin6_addr,
				  SELFLD(dir, rev_dns_src, rev_dns_dst),
				  sizeof(n->rev_dns_src));
			return;
		}

		sa = (struct sockaddr *) &sa6;
		sa_len = sizeof(sa6);
		hent = gethostbyaddr(&sa6.sin6_addr, sizeof(sa6.sin6_addr), AF_INET6);
		break;
	}

	getnameinfo(sa, sa_len, SELFLD(dir, rev_dns_src, rev_dns_dst),
		    sizeof(n->rev_dns_src), NULL, 0, NI_NUMERICHOST);

	if (hent)
		strlcpy(SELFLD(dir, rev_dns_src, rev_dns_dst), hent->h_name,
			sizeof(n->rev_dns_src));
}

static void flow_entry_get_extended(struct flow_entry *n)
{
	if (n->flow_id == 0)
		return;

	flow_entry_get_extended_revdns(n, FLOW_DIR_SRC);
	flow_entry_get_extended_geo(n, FLOW_DIR_SRC);

	flow_entry_get_extended_revdns(n, FLOW_DIR_DST);
	flow_entry_get_extended_geo(n, FLOW_DIR_DST);

	/* Lookup application */
	n->inode = get_port_inode(n->port_src, n->l4_proto,
				  n->l3_proto == AF_INET6);
	if (n->inode > 0)
		flow_entry_find_process(n);
}

static char *bandw2str(double bytes, char *buf, size_t len)
{
	if (bytes <= 0) {
		buf[0] = '\0';
		return buf;
	}

	if (bytes > 1000000000.)
		snprintf(buf, len, "%.1fGB", bytes / 1000000000.);
	else if (bytes > 1000000.)
		snprintf(buf, len, "%.1fMB", bytes / 1000000.);
	else if (bytes > 1000.)
		snprintf(buf, len, "%.1fkB", bytes / 1000.);
	else
		snprintf(buf, len, "%.0f", bytes);

	return buf;
}

static char *rate2str(double rate, char *buf, size_t len)
{
	const char * const unit_fmt[2][4] = {
		{ "%.1fGbit/s", "%.1fMbit/s", "%.1fkbit/s", "%.0fbit/s" },
		{ "%.1fGB/s",   "%.1fMB/s",   "%.1fkB/s",   "%.0fB/s"   }
	};

	if (rate <= 0) {
		buf[0] = '\0';
		return buf;
	}

	if (rate_type == RATE_BITS)
		rate *= 8;

	if (rate > 1000000000.)
		snprintf(buf, len, unit_fmt[rate_type][0], rate / 1000000000.);
	else if (rate > 1000000.)
		snprintf(buf, len, unit_fmt[rate_type][1], rate / 1000000.);
	else if (rate > 1000.)
		snprintf(buf, len, unit_fmt[rate_type][2], rate / 1000.);
	else
		snprintf(buf, len, unit_fmt[rate_type][3], rate);

	return buf;
}

static char *time2str(uint64_t tstamp, char *str, size_t len)
{
	time_t now;
	int v, s;

	time(&now);

	s = now - (tstamp ? (tstamp / NSEC_PER_SEC) : now);
	if (s <= 0) {
		str[0] = '\0';
		return str;
	}

	v = s / (3600 * 24);
	if (v > 0) {
		slprintf(str, len, "%dd", v);
		return str;
	}

	v = s / 3600;
	if (v > 0) {
		slprintf(str, len, "%dh", v);
		return str;
	}

	v = s / 60;
	if (v > 0) {
		slprintf(str, len, "%dm", v);
		return str;
	}

	slprintf(str, len, "%ds", s);
	return str;
}


static const char *flow_state2str(const struct flow_entry *n)
{
	switch (n->l4_proto) {
	case IPPROTO_TCP:
		return tcp_state2str[n->tcp_state];
	case IPPROTO_SCTP:
		return sctp_state2str[n->sctp_state];
	case IPPROTO_DCCP:
		return dccp_state2str[n->dccp_state];

	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
	default:
		return "";
	}
}

static char *flow_port2str(const struct flow_entry *n, char *str, size_t len,
		           enum flow_direction dir)
{
	const char *tmp = NULL;
	uint16_t port = 0;

	port = SELFLD(dir, port_src, port_dst);
	tmp = NULL;

	switch (n->l4_proto) {
	case IPPROTO_TCP:
		tmp = lookup_port_tcp(port);
		break;
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
		tmp = lookup_port_udp(port);
		break;
	}

	if (!tmp && port)
		slprintf(str, len, "%d", port);
	else
		slprintf(str, len, "%s", tmp ? tmp : "");

	return str;
}

static void print_flow_peer_info(const struct flow_entry *n, enum flow_direction dir)
{
	int counters_color = COLOR(YELLOW, BLACK);
	int src_color = COLOR(RED, BLACK);
	int dst_color = COLOR(BLUE, BLACK);
	int country_color = COLOR(GREEN, BLACK);
	int addr_color = dst_color;
	int port_color = A_BOLD;
	char tmp[128];

	if (show_src && dir == FLOW_DIR_SRC) {
		country_color  = src_color;
		counters_color = src_color;
		port_color    |= src_color;
		addr_color     = src_color;
	} else if (show_src && FLOW_DIR_DST) {
		country_color  = dst_color;
		counters_color = dst_color;
		port_color    |= dst_color;
		addr_color     = dst_color;
	}

	ui_table_col_color_set(&flows_tbl, TBL_FLOW_ADDRESS, addr_color);
	ui_table_col_color_set(&flows_tbl, TBL_FLOW_PORT, port_color);
	ui_table_col_color_set(&flows_tbl, TBL_FLOW_GEO, country_color);
	ui_table_col_color_set(&flows_tbl, TBL_FLOW_BYTES, counters_color);
	ui_table_col_color_set(&flows_tbl, TBL_FLOW_RATE, counters_color);

	/* Reverse DNS/IP */
	ui_table_row_col_set(&flows_tbl, TBL_FLOW_ADDRESS,
			      SELFLD(dir, rev_dns_src, rev_dns_dst));

	/* Application port */
	ui_table_row_col_set(&flows_tbl, TBL_FLOW_PORT,
			      flow_port2str(n, tmp, sizeof(tmp), dir));

	/* GEO */
	ui_table_row_col_set(&flows_tbl, TBL_FLOW_GEO,
			      SELFLD(dir, country_code_src, country_code_dst));

	/* Bytes */
	ui_table_row_col_set(&flows_tbl, TBL_FLOW_BYTES,
			      bandw2str(SELFLD(dir, stat.bytes_src, stat.bytes_dst),
					tmp, sizeof(tmp) - 1));

	/* Rate bytes */
	ui_table_row_col_set(&flows_tbl, TBL_FLOW_RATE,
			      rate2str(SELFLD(dir, stat.rate_bytes_src, stat.rate_bytes_dst),
				       tmp, sizeof(tmp) - 1));
}

static void draw_flow_entry(struct ui_table *tbl, const void *data)
{
	const struct flow_entry *n = data;
	char tmp[128];

	ui_table_row_add(tbl);

	/* Application */
	ui_table_row_col_set(tbl, TBL_FLOW_PROCESS, n->proc ? n->proc->name : "");

	/* PID */
	slprintf(tmp, sizeof(tmp), "%.d", n->proc ? n->proc->pid : 0);
	ui_table_row_col_set(tbl, TBL_FLOW_PID, tmp);

	/* L4 protocol */
	ui_table_row_col_set(tbl, TBL_FLOW_PROTO, l4proto2str[n->l4_proto]);

	/* L4 protocol state */
	ui_table_row_col_set(tbl, TBL_FLOW_STATE, flow_state2str(n));

	/* Time */
	time2str(n->timestamp_start, tmp, sizeof(tmp));
	ui_table_row_col_set(tbl, TBL_FLOW_TIME, tmp);

	print_flow_peer_info(n, show_src ? FLOW_DIR_SRC : FLOW_DIR_DST);

	ui_table_row_show(tbl);

	if (show_src) {
		ui_table_row_add(tbl);

		ui_table_row_col_set(tbl, TBL_FLOW_PROCESS, "");
		ui_table_row_col_set(tbl, TBL_FLOW_PID, "");
		ui_table_row_col_set(tbl, TBL_FLOW_PROTO, "");
		ui_table_row_col_set(tbl, TBL_FLOW_STATE, "");
		ui_table_row_col_set(tbl, TBL_FLOW_TIME, "");

		print_flow_peer_info(n, FLOW_DIR_DST);
		ui_table_row_show(tbl);
	}
}

static inline bool presenter_flow_wrong_state(struct flow_entry *n)
{
	switch (n->l4_proto) {
	case IPPROTO_TCP:
		switch (n->tcp_state) {
		case TCP_CONNTRACK_SYN_SENT:
		case TCP_CONNTRACK_SYN_RECV:
		case TCP_CONNTRACK_ESTABLISHED:
		case TCP_CONNTRACK_FIN_WAIT:
		case TCP_CONNTRACK_CLOSE_WAIT:
		case TCP_CONNTRACK_LAST_ACK:
		case TCP_CONNTRACK_TIME_WAIT:
		case TCP_CONNTRACK_CLOSE:
		case TCP_CONNTRACK_SYN_SENT2:
		case TCP_CONNTRACK_NONE:
			return false;
			break;
		}
		break;
	case IPPROTO_SCTP:
		switch (n->sctp_state) {
		case SCTP_CONNTRACK_NONE:
		case SCTP_CONNTRACK_CLOSED:
		case SCTP_CONNTRACK_COOKIE_WAIT:
		case SCTP_CONNTRACK_COOKIE_ECHOED:
		case SCTP_CONNTRACK_ESTABLISHED:
		case SCTP_CONNTRACK_SHUTDOWN_SENT:
		case SCTP_CONNTRACK_SHUTDOWN_RECD:
		case SCTP_CONNTRACK_SHUTDOWN_ACK_SENT:
			return false;
			break;
		}
		break;
	case IPPROTO_DCCP:
		switch (n->dccp_state) {
		case DCCP_CONNTRACK_NONE:
		case DCCP_CONNTRACK_REQUEST:
		case DCCP_CONNTRACK_RESPOND:
		case DCCP_CONNTRACK_PARTOPEN:
		case DCCP_CONNTRACK_OPEN:
		case DCCP_CONNTRACK_CLOSEREQ:
		case DCCP_CONNTRACK_CLOSING:
		case DCCP_CONNTRACK_TIMEWAIT:
		case DCCP_CONNTRACK_IGNORE:
		case DCCP_CONNTRACK_INVALID:
			return false;
			break;
		}
		break;
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		return false;
		break;
	}

	return true;
}

static void draw_filter_status(struct ui_table *tbl, char *title)
{
	mvwprintw(screen, 1, 0, "%*s", COLS - 1, " ");
	mvwprintw(screen, 1, 2, "%s(%u) for ", title, ui_table_data_count(tbl));

	if (what & INCLUDE_IPV4)
		printw("IPv4,");
	if (what & INCLUDE_IPV6)
		printw("IPv6,");
	if (what & INCLUDE_TCP)
		printw("TCP,");
	if (what & INCLUDE_UDP)
		printw("UDP,");
	if (what & INCLUDE_SCTP)
		printw("SCTP,");
	if (what & INCLUDE_DCCP)
		printw("DCCP,");
	if (what & INCLUDE_ICMP && what & INCLUDE_IPV4)
		printw("ICMP,");
	if (what & INCLUDE_ICMP && what & INCLUDE_IPV6)
		printw("ICMP6,");
	if (show_active_only)
		printw("Active,");

	printw(" [+%d]", ui_table_scroll_height(tbl));

	if (is_flow_collecting)
		printw(" [Collecting flows ...]");

}

static void draw_flows(WINDOW *screen, struct flow_list *fl)
{
	rcu_read_lock();

	if (cds_list_empty(&fl->head))
		mvwprintw(screen, 4, 2, "(No sessions! "
			  "Is netfilter running?)");

	ui_table_data_bind(&flows_tbl);

	rcu_read_unlock();

	draw_filter_status(&flows_tbl, "Kernel netfilter flows");
}

static void draw_proc_entry(struct ui_table *tbl, const void *data)
{
	const struct proc_entry *p = data;
	char tmp[128];

	ui_table_row_add(tbl);

	/* Application */
	ui_table_row_col_set(tbl, TBL_PROC_NAME, p->name);

	/* PID */
	slprintf(tmp, sizeof(tmp), "%.d", p->pid);
	ui_table_row_col_set(tbl, TBL_PROC_PID, tmp);

	/* Flows */
	slprintf(tmp, sizeof(tmp), "%.d", p->flows_count);
	ui_table_row_col_set(tbl, TBL_PROC_FLOWS, tmp);

	/* Bytes Src */
	bandw2str(p->stat.bytes_src, tmp, sizeof(tmp) - 1);
	ui_table_row_col_set(tbl, TBL_PROC_BYTES_SRC, tmp);

	/* Rate Src */
	rate2str(p->stat.rate_bytes_src, tmp, sizeof(tmp) - 1);
	ui_table_row_col_set(tbl, TBL_PROC_RATE_SRC, tmp);

	/* Bytes Dest */
	bandw2str(p->stat.bytes_dst, tmp, sizeof(tmp) - 1);
	ui_table_row_col_set(tbl, TBL_PROC_BYTES_DST, tmp);

	/* Rate Dest */
	rate2str(p->stat.rate_bytes_dst, tmp, sizeof(tmp) - 1);
	ui_table_row_col_set(tbl, TBL_PROC_RATE_DST, tmp);

	ui_table_row_show(tbl);
}

static void draw_procs(WINDOW *screen, struct flow_list *fl)
{
	rcu_read_lock();

	ui_table_data_bind(&procs_tbl);

	rcu_read_unlock();

	draw_filter_status(&procs_tbl, "Processes");
}

static void draw_help(void)
{
	int col = 0;
	int row = 1;
	int i;

	mvaddch(row, col, ACS_ULCORNER);
	mvaddch(rows - row - 1, col, ACS_LLCORNER);

	mvaddch(row, cols - 1, ACS_URCORNER);
	mvaddch(rows - row - 1, cols - 1, ACS_LRCORNER);

	for (i = 1; i < rows - row - 2; i++) {
		mvaddch(row + i, 0, ACS_VLINE);
		mvaddch(row + i, cols - 1, ACS_VLINE);
	}
	for (i = 1; i < cols - col - 1; i++) {
		mvaddch(row, col + i, ACS_HLINE);
		mvaddch(rows - row - 1, col + i, ACS_HLINE);
	}

	attron(A_BOLD);
	mvaddnstr(row, cols / 2 - 2, "| Help |", -1);

	attron(A_UNDERLINE);
	mvaddnstr(row + 2, col + 2, "Navigation", -1);
	attroff(A_BOLD | A_UNDERLINE);

	mvaddnstr(row + 4, col + 3, "TAB           Go to next tab panel", -1);
	mvaddnstr(row + 5, col + 3, "Up, u, k      Move up", -1);
	mvaddnstr(row + 6, col + 3, "Down, d, j    Move down", -1);
	mvaddnstr(row + 7, col + 3, "Left,l        Scroll left", -1);
	mvaddnstr(row + 8, col + 3, "Right,h       Scroll right", -1);
	mvaddnstr(row + 9, col + 3, "?             Toggle help window", -1);
	mvaddnstr(row + 10, col + 3, "q, Ctrl+C     Quit", -1);

	attron(A_BOLD | A_UNDERLINE);
	mvaddnstr(row + 12, col + 2, "Display Settings", -1);
	attroff(A_BOLD | A_UNDERLINE);

	mvaddnstr(row + 14, col + 3, "b     Toggle rate units (bits/bytes)", -1);
	mvaddnstr(row + 15, col + 3, "a     Toggle display of active flows (rate > 0) only", -1);
	mvaddnstr(row + 16, col + 3, "s     Toggle show source peer info", -1);

	mvaddnstr(row + 18, col + 3, "T     Toggle display TCP flows", -1);
	mvaddnstr(row + 19, col + 3, "U     Toggle display UDP flows", -1);
	mvaddnstr(row + 20, col + 3, "D     Toggle display DCCP flows", -1);
	mvaddnstr(row + 21, col + 3, "I     Toggle display ICMP flows", -1);
	mvaddnstr(row + 22, col + 3, "S     Toggle display SCTP flows", -1);
}

static void draw_header(WINDOW *screen)
{
	int i;

	attron(A_STANDOUT);

	for (i = 0; i < cols; i++)
		mvaddch(0, i, ' ');

	mvwprintw(screen, 0, 2, "flowtop %s", VERSION_LONG);
	attroff(A_STANDOUT);
}

static void draw_footer(void)
{
	int i;

	attron(A_STANDOUT);

	for (i = 0; i < cols; i++)
		mvaddch(rows - 1, i, ' ');

	mvaddnstr(rows - 1, 1, "Press '?' for help", -1);
	addch(ACS_VLINE);
	attroff(A_STANDOUT);
}

static void show_option_toggle(int opt)
{
	switch (opt) {
	case 'T':
		TOGGLE_FLAG(what, INCLUDE_TCP);
		break;
	case 'U':
		TOGGLE_FLAG(what, INCLUDE_UDP);
		break;
	case 'D':
		TOGGLE_FLAG(what, INCLUDE_DCCP);
		break;
	case 'I':
		TOGGLE_FLAG(what, INCLUDE_ICMP);
		break;
	case 'S':
		TOGGLE_FLAG(what, INCLUDE_SCTP);
		break;
	}
}

void * flows_iter(void *data)
{
	struct flow_entry *n = data;

	do {
		n = list_first_or_next(n, &flow_list.head, entry);
	} while (n && (!n->is_visible || presenter_flow_wrong_state(n)));

	return n;
}

static void flows_table_init(struct ui_table *tbl)
{
	ui_table_init(tbl);

	ui_table_pos_set(tbl, 3, 0);
	ui_table_height_set(tbl, LINES - 3);

	ui_table_col_add(tbl, TBL_FLOW_PROCESS, "PROCESS", 13);
	ui_table_col_add(tbl, TBL_FLOW_PID, "PID", 7);
	ui_table_col_add(tbl, TBL_FLOW_PROTO, "PROTO", 6);
	ui_table_col_add(tbl, TBL_FLOW_STATE, "STATE", 11);
	ui_table_col_add(tbl, TBL_FLOW_TIME, "TIME", 4);
	ui_table_col_add(tbl, TBL_FLOW_ADDRESS, "ADDRESS", 50);
	ui_table_col_add(tbl, TBL_FLOW_PORT, "PORT", 8);
	ui_table_col_add(tbl, TBL_FLOW_GEO, "GEO", 3);
	ui_table_col_add(tbl, TBL_FLOW_BYTES, "BYTES", 10);
	ui_table_col_add(tbl, TBL_FLOW_RATE, "RATE", 10);

	ui_table_col_align_set(tbl, TBL_FLOW_TIME, UI_ALIGN_RIGHT);
	ui_table_col_align_set(tbl, TBL_FLOW_BYTES, UI_ALIGN_RIGHT);
	ui_table_col_align_set(tbl, TBL_FLOW_RATE, UI_ALIGN_RIGHT);

	ui_table_col_color_set(tbl, TBL_FLOW_PROCESS, COLOR(YELLOW, BLACK));
	ui_table_col_color_set(tbl, TBL_FLOW_PID, A_BOLD);
	ui_table_col_color_set(tbl, TBL_FLOW_STATE, COLOR(YELLOW, BLACK));

	ui_table_header_color_set(&flows_tbl, COLOR(BLACK, GREEN));

	ui_table_data_bind_set(tbl, draw_flow_entry);
	ui_table_data_iter_set(tbl, flows_iter);
}

void * procs_iter(void *data)
{
	struct proc_entry *p = data;

	return list_first_or_next(p, &proc_list.head, entry);
}

static void procs_table_init(struct ui_table *tbl)
{
	ui_table_init(tbl);

	ui_table_pos_set(tbl, 3, 0);
	ui_table_height_set(tbl, LINES - 3);

	ui_table_col_add(tbl, TBL_PROC_NAME, "NAME", 13);
	ui_table_col_add(tbl, TBL_PROC_PID, "PID", 7);
	ui_table_col_add(tbl, TBL_PROC_FLOWS, "FLOWS", 7);
	ui_table_col_add(tbl, TBL_PROC_BYTES_SRC, "BYTES_SRC", 10);
	ui_table_col_add(tbl, TBL_PROC_BYTES_DST, "BYTES_DST", 10);
	ui_table_col_add(tbl, TBL_PROC_RATE_SRC, "RATE_SRC", 14);
	ui_table_col_add(tbl, TBL_PROC_RATE_DST, "RATE_DST", 14);

	ui_table_col_align_set(tbl, TBL_PROC_BYTES_SRC, UI_ALIGN_RIGHT);
	ui_table_col_align_set(tbl, TBL_PROC_RATE_SRC, UI_ALIGN_RIGHT);
	ui_table_col_align_set(tbl, TBL_PROC_BYTES_DST, UI_ALIGN_RIGHT);
	ui_table_col_align_set(tbl, TBL_PROC_RATE_DST, UI_ALIGN_RIGHT);

	ui_table_col_color_set(tbl, TBL_PROC_NAME, COLOR(YELLOW, BLACK));
	ui_table_col_color_set(tbl, TBL_PROC_PID, A_BOLD);
	ui_table_col_color_set(tbl, TBL_PROC_FLOWS, COLOR(YELLOW, BLACK));
	ui_table_col_color_set(tbl, TBL_PROC_BYTES_SRC, COLOR(RED, BLACK));
	ui_table_col_color_set(tbl, TBL_PROC_RATE_SRC, COLOR(RED, BLACK));
	ui_table_col_color_set(tbl, TBL_PROC_BYTES_DST, COLOR(BLUE, BLACK));
	ui_table_col_color_set(tbl, TBL_PROC_RATE_DST, COLOR(BLUE, BLACK));

	ui_table_header_color_set(tbl, COLOR(BLACK, GREEN));

	ui_table_data_bind_set(tbl, draw_proc_entry);
	ui_table_data_iter_set(tbl, procs_iter);
}

static void tab_main_on_open(struct ui_tab *tab, enum ui_tab_event_t evt, uint32_t id)
{
	if (evt != UI_TAB_EVT_OPEN)
		return;

	if (id == TAB_FLOWS) {
		draw_flows(screen, &flow_list);
		curr_tbl = &flows_tbl;
	} else if (id == TAB_PROCS) {
		draw_procs(screen, &flow_list);
		curr_tbl = &procs_tbl;
	}
}

static void presenter(void)
{
	bool show_help = false;
	struct ui_tab *tab_main;

	lookup_init(LT_PORTS_TCP);
	lookup_init(LT_PORTS_UDP);

	screen = screen_init(false);
	wclear(screen);
	halfdelay(1);

	start_color();
	INIT_COLOR(RED, BLACK);
	INIT_COLOR(BLUE, BLACK);
	INIT_COLOR(YELLOW, BLACK);
	INIT_COLOR(GREEN, BLACK);
	INIT_COLOR(BLACK, GREEN);

        flows_table_init(&flows_tbl);
        procs_table_init(&procs_tbl);

	tab_main = ui_tab_create();
	ui_tab_event_cb_set(tab_main, tab_main_on_open);
	ui_tab_pos_set(tab_main, 2, 0);
	ui_tab_active_color_set(tab_main, COLOR(BLACK, GREEN));
	ui_tab_entry_add(tab_main, TAB_FLOWS, "Flows");
	ui_tab_entry_add(tab_main, TAB_PROCS, "Processes");

	rcu_register_thread();
	while (!sigint) {
		int ch;

		curs_set(0);
		getmaxyx(screen, rows, cols);

		ch = getch();
		switch (ch) {
		case 'q':
			sigint = 1;
			break;
		case KEY_UP:
		case 'u':
		case 'k':
			ui_table_event_send(curr_tbl, UI_EVT_SCROLL_UP);
			break;
		case KEY_DOWN:
		case 'd':
		case 'j':
			ui_table_event_send(curr_tbl, UI_EVT_SCROLL_DOWN);
			break;
		case KEY_LEFT:
		case 'h':
			ui_table_event_send(curr_tbl, UI_EVT_SCROLL_LEFT);
			break;
		case KEY_RIGHT:
		case 'l':
			ui_table_event_send(curr_tbl, UI_EVT_SCROLL_RIGHT);
			break;
		case 'b':
			if (rate_type == RATE_BYTES)
				rate_type = RATE_BITS;
			else
				rate_type = RATE_BYTES;
			break;
		case 'a':
			show_active_only = !show_active_only;
			break;
		case 's':
			show_src = !show_src;
			break;
		case '?':
			show_help = !show_help;
			wclear(screen);
			clear();
			break;
		case 'T':
		case 'U':
		case 'D':
		case 'I':
		case 'S':
			show_option_toggle(ch);
			do_reload_flows = true;
			break;
		case '\t':
			ui_tab_event_send(tab_main, UI_EVT_SELECT_NEXT);
			break;
		default:
			fflush(stdin);
			break;
		}

		draw_header(screen);

		if (show_help)
			draw_help();
		else
			ui_tab_show(tab_main);

		draw_footer();
	}
	rcu_unregister_thread();

	ui_table_uninit(&flows_tbl);
	ui_table_uninit(&procs_tbl);
	ui_tab_destroy(tab_main);

	screen_end();
	lookup_cleanup(LT_PORTS_UDP);
	lookup_cleanup(LT_PORTS_TCP);
}

static void restore_sysctl(void *obj)
{
	struct sysctl_params_ctx *sysctl_ctx = obj;

	if (sysctl_ctx->nfct_acct == 0)
		sysctl_set_int("net/netfilter/nf_conntrack_acct",
				sysctl_ctx->nfct_acct);

	if (sysctl_ctx->nfct_tstamp == 0)
		sysctl_set_int("net/netfilter/nf_conntrack_timestamp",
				sysctl_ctx->nfct_tstamp);
}

static void on_panic_handler(void *arg)
{
	restore_sysctl(arg);
	screen_end();
}

static void conntrack_acct_enable(void)
{
	/* We can still work w/o traffic accounting so just warn about error */
	if (sysctl_get_int("net/netfilter/nf_conntrack_acct", &sysctl.nfct_acct)) {
		fprintf(stderr, "Can't read net/netfilter/nf_conntrack_acct: %s\n",
			strerror(errno));
		return;
	}

	if (sysctl.nfct_acct == 1)
		return;

	if (sysctl_set_int("net/netfilter/nf_conntrack_acct", 1)) {
		fprintf(stderr, "Can't write net/netfilter/nf_conntrack_acct: %s\n",
			strerror(errno));
	}
}

static void conntrack_tstamp_enable(void)
{
	if (sysctl_get_int("net/netfilter/nf_conntrack_timestamp", &sysctl.nfct_tstamp)) {
		fprintf(stderr, "Can't read net/netfilter/nf_conntrack_timestamp: %s\n",
			strerror(errno));
		return;
	}

	if (sysctl.nfct_tstamp == 1)
		return;

	if (sysctl_set_int("net/netfilter/nf_conntrack_timestamp", 1)) {
		fprintf(stderr, "Can't write net/netfilter/nf_conntrack_timestamp: %s\n",
			strerror(errno));
	}
}

static void flow_entry_filter(struct flow_entry *n)
{
	if (show_active_only && !n->stat.rate_bytes_src && !n->stat.rate_bytes_dst)
		n->is_visible = false;
	else
		n->is_visible = true;
}

static int flow_list_update_entry(struct flow_list *fl, struct nf_conntrack *ct)
{
	struct flow_entry *n;

	n = flow_list_find_id(fl, nfct_get_attr_u32(ct, ATTR_ID));
	if (!n)
		return NFCT_CB_CONTINUE;

	flow_entry_calc_rate(n, ct);
	flow_entry_update_time(n);
	flow_entry_from_ct(n, ct);
	flow_entry_filter(n);

	return NFCT_CB_CONTINUE;
}

static int flow_event_cb(enum nf_conntrack_msg_type type,
			 struct nf_conntrack *ct, void *data __maybe_unused)
{
	if (sigint)
		return NFCT_CB_STOP;

	switch (type) {
	case NFCT_T_NEW:
		return flow_list_new_entry(&flow_list, ct);
	case NFCT_T_UPDATE:
		return flow_list_update_entry(&flow_list, ct);
	case NFCT_T_DESTROY:
		return flow_list_del_entry(&flow_list, ct);
	default:
		return NFCT_CB_CONTINUE;
	}
}

static void collector_refresh_procs(void)
{
	struct proc_entry *p, *tmp;

	cds_list_for_each_entry_safe(p, tmp, &proc_list.head, entry) {
		double sec = (double)time_after_us(&p->last_update) / USEC_PER_SEC;
		struct flow_entry *n;

		if (sec < 1)
			continue;

		bug_on(gettimeofday(&p->last_update, NULL));

		if (!p->flows_count && !proc_exists(p->pid)) {
			cds_list_del_rcu(&p->entry);
			call_rcu(&p->rcu, proc_entry_xfree_rcu);
			continue;
		}

		p->stat.rate_bytes_src = 0;
		p->stat.rate_bytes_dst = 0;
		p->stat.rate_pkts_src = 0;
		p->stat.rate_pkts_dst = 0;

		cds_list_for_each_entry_rcu(n, &p->flows, proc_head) {
			p->stat.rate_bytes_src += n->stat.rate_bytes_src;
			p->stat.rate_bytes_dst += n->stat.rate_bytes_dst;
			p->stat.rate_pkts_src += n->stat.rate_pkts_src;
			p->stat.rate_pkts_dst += n->stat.rate_pkts_dst;
		}
	}
}

static void collector_refresh_flows(struct nfct_handle *handle)
{
	struct flow_entry *n;

	cds_list_for_each_entry_rcu(n, &flow_list.head, entry) {
		nfct_query(handle, NFCT_Q_GET, n->ct);
	}
}

static void collector_create_filter(struct nfct_handle *nfct)
{
	struct nfct_filter *filter;
	int ret;

	filter = nfct_filter_create();
	if (!filter)
		panic("Cannot create a nfct filter: %s\n", strerror(errno));

	if (what & INCLUDE_UDP) {
		nfct_filter_add_attr_u32(filter, NFCT_FILTER_L4PROTO, IPPROTO_UDP);
		nfct_filter_add_attr_u32(filter, NFCT_FILTER_L4PROTO, IPPROTO_UDPLITE);
	}
	if (what & INCLUDE_TCP)
		nfct_filter_add_attr_u32(filter, NFCT_FILTER_L4PROTO, IPPROTO_TCP);
	if (what & INCLUDE_DCCP)
		nfct_filter_add_attr_u32(filter, NFCT_FILTER_L4PROTO, IPPROTO_DCCP);
	if (what & INCLUDE_SCTP)
		nfct_filter_add_attr_u32(filter, NFCT_FILTER_L4PROTO, IPPROTO_SCTP);
	if (what & INCLUDE_ICMP && what & INCLUDE_IPV4)
		nfct_filter_add_attr_u32(filter, NFCT_FILTER_L4PROTO, IPPROTO_ICMP);
	if (what & INCLUDE_ICMP && what & INCLUDE_IPV6)
		nfct_filter_add_attr_u32(filter, NFCT_FILTER_L4PROTO, IPPROTO_ICMPV6);
	if (what & INCLUDE_IPV4) {
		nfct_filter_set_logic(filter, NFCT_FILTER_SRC_IPV4, NFCT_FILTER_LOGIC_NEGATIVE);
		nfct_filter_add_attr(filter, NFCT_FILTER_SRC_IPV4, &filter_ipv4);
	}
	if (what & INCLUDE_IPV6) {
		nfct_filter_set_logic(filter, NFCT_FILTER_SRC_IPV6, NFCT_FILTER_LOGIC_NEGATIVE);
		nfct_filter_add_attr(filter, NFCT_FILTER_SRC_IPV6, &filter_ipv6);
	}

	ret = nfct_filter_attach(nfct_fd(nfct), filter);
	if (ret < 0)
		panic("Cannot attach filter to handle: %s\n", strerror(errno));

	nfct_filter_destroy(filter);
}

/* This hand-crafted filter looks ugly but it allows to do not
 * flush nfct connections & filter them by user specified filter.
 * May be it is better to replace this one by nfct_cmp. */
static int flow_dump_cb(enum nf_conntrack_msg_type type __maybe_unused,
			struct nf_conntrack *ct, void *data __maybe_unused)
{
	struct flow_entry fl;
	struct flow_entry *n = &fl;

	if (sigint)
		return NFCT_CB_STOP;

	if (!(what & ~(INCLUDE_IPV4 | INCLUDE_IPV6)))
		goto check_addr;

	CP_NFCT(l4_proto, ATTR_ORIG_L4PROTO, 8);

	if (what & INCLUDE_UDP) {
		if (n->l4_proto == IPPROTO_UDP)
			goto check_addr;

		if (n->l4_proto == IPPROTO_UDPLITE)
			goto check_addr;

	}
	if ((what & INCLUDE_TCP) && n->l4_proto == IPPROTO_TCP)
		goto check_addr;

	if ((what & INCLUDE_DCCP) && n->l4_proto == IPPROTO_DCCP)
		goto check_addr;

	if ((what & INCLUDE_SCTP) && n->l4_proto == IPPROTO_SCTP)
		goto check_addr;

	if ((what & INCLUDE_ICMP) && (what & INCLUDE_IPV4) &&
			n->l4_proto == IPPROTO_ICMP) {
		goto check_addr;
	}

	if ((what & INCLUDE_ICMP) && (what & INCLUDE_IPV6) &&
			n->l4_proto == IPPROTO_ICMPV6) {
		goto check_addr;
	}

	goto skip_flow;

check_addr:
	/* filter loopback addresses */
	if (what & INCLUDE_IPV4) {
		CP_NFCT(ip4_src_addr, ATTR_ORIG_IPV4_SRC, 32);

		if (n->ip4_src_addr == filter_ipv4.addr)
			goto skip_flow;
	}
	if (what & INCLUDE_IPV6) {
		CP_NFCT_BUFF(ip6_src_addr, ATTR_ORIG_IPV6_SRC);

		if (n->ip6_src_addr[0] == 0x0 &&
		    n->ip6_src_addr[1] == 0x0 &&
		    n->ip6_src_addr[2] == 0x0 &&
		    n->ip6_src_addr[3] == 0x1)
			goto skip_flow;
	}

	return flow_list_new_entry(&flow_list, ct);

skip_flow:
	return NFCT_CB_CONTINUE;
}

static void collector_dump_flows(void)
{
	struct nfct_handle *nfct = nfct_open(CONNTRACK, 0);

	if (!nfct)
		panic("Cannot create a nfct handle: %s\n", strerror(errno));

	nfct_callback_register(nfct, NFCT_T_ALL, flow_dump_cb, NULL);

	is_flow_collecting = true;
	if (what & INCLUDE_IPV4) {
		int family = AF_INET;
		nfct_query(nfct, NFCT_Q_DUMP, &family);
	}
	if (what & INCLUDE_IPV6) {
		int family = AF_INET6;
		nfct_query(nfct, NFCT_Q_DUMP, &family);
	}
	is_flow_collecting = false;

	nfct_close(nfct);
}

static void *collector(void *null __maybe_unused)
{
	struct nfct_handle *ct_event;
	struct pollfd poll_fd[1];

	proc_list_init(&proc_list);
	flow_list_init(&flow_list);

	ct_event = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_NEW |
				      NF_NETLINK_CONNTRACK_UPDATE |
				      NF_NETLINK_CONNTRACK_DESTROY);
	if (!ct_event)
		panic("Cannot create a nfct handle: %s\n", strerror(errno));

	collector_create_filter(ct_event);

	nfct_callback_register(ct_event, NFCT_T_ALL, flow_event_cb, NULL);

	poll_fd[0].fd = nfct_fd(ct_event);
	poll_fd[0].events = POLLIN;

	if (fcntl(nfct_fd(ct_event), F_SETFL, O_NONBLOCK) == -1)
		panic("Cannot set non-blocking socket: fcntl(): %s\n",
		      strerror(errno));

	rcu_register_thread();

	collector_dump_flows();

	while (!sigint) {
		int status;

		if (!do_reload_flows) {
			usleep(USEC_PER_SEC * interval);
		} else {
			do_reload_flows = false;

			flow_list_destroy(&flow_list);

			collector_create_filter(ct_event);
			collector_dump_flows();
		}

		collector_refresh_procs();
		collector_refresh_flows(ct_event);

		status = poll(poll_fd, 1, 0);
		if (status < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;

			panic("Error while polling: %s\n", strerror(errno));
		} else if (status != 0) {
			if (poll_fd[0].revents & POLLIN)
				nfct_catch(ct_event);
		}
	}

	flow_list_destroy(&flow_list);
	proc_list_destroy(&proc_list);

	rcu_unregister_thread();

	nfct_close(ct_event);

	pthread_exit(NULL);
}

int main(int argc, char **argv)
{
	pthread_t tid;
	int ret, c, what_cmd = 0;

	setfsuid(getuid());
	setfsgid(getgid());

	while ((c = getopt_long(argc, argv, short_options, long_options,
				NULL)) != EOF) {
		switch (c) {
		case '4':
			what_cmd |= INCLUDE_IPV4;
			break;
		case '6':
			what_cmd |= INCLUDE_IPV6;
			break;
		case 'T':
			what_cmd |= INCLUDE_TCP;
			break;
		case 'U':
			what_cmd |= INCLUDE_UDP;
			break;
		case 'D':
			what_cmd |= INCLUDE_DCCP;
			break;
		case 'I':
			what_cmd |= INCLUDE_ICMP;
			break;
		case 'S':
			what_cmd |= INCLUDE_SCTP;
			break;
		case 's':
			show_src = true;
			break;
		case 'b':
			rate_type = RATE_BITS;
			break;
		case 'u':
			update_geoip();
			die();
			break;
		case 't':
			interval = strtoul(optarg, NULL, 10);
			break;
		case 'n':
			resolve_dns = false;
			break;
		case 'G':
			resolve_geoip = false;
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

	if (what_cmd > 0) {
		what = what_cmd;

		if (!(what & (INCLUDE_IPV4 | INCLUDE_IPV6)))
			what |= INCLUDE_IPV4 | INCLUDE_IPV6;
	}

	rcu_init();

	register_signal(SIGINT, signal_handler);
	register_signal(SIGQUIT, signal_handler);
	register_signal(SIGTERM, signal_handler);
	register_signal(SIGHUP, signal_handler);

	panic_handler_add(on_panic_handler, &sysctl);

	conntrack_acct_enable();
	conntrack_tstamp_enable();

	if (resolve_geoip)
		init_geoip(1);

	ret = pthread_create(&tid, NULL, collector, NULL);
	if (ret < 0)
		panic("Cannot create phthread!\n");

	presenter();

	if (resolve_geoip)
		destroy_geoip();

	restore_sysctl(&sysctl);

	return 0;
}

/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2012 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL, version 2.
 */

/* yaac-func-prefix: yy */

%{

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>
#include <libgen.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <linux/if_ether.h>

#include "xmalloc.h"
#include "trafgen_parser.tab.h"
#include "trafgen_conf.h"
#include "trafgen_proto.h"
#include "trafgen_l2.h"
#include "trafgen_l3.h"
#include "trafgen_l4.h"
#include "built_in.h"
#include "die.h"
#include "str.h"
#include "csum.h"
#include "cpp.h"

#define YYERROR_VERBOSE		0
#define YYDEBUG			0
#define YYENABLE_NLS		1
#define YYLTYPE_IS_TRIVIAL	1
#define ENABLE_NLS		1

extern FILE *yyin;
extern int yylex(void);
extern void yy_scan_string(char *);
extern void yylex_destroy();
extern void yyerror(const char *);
extern int yylineno;
extern char *yytext;

extern struct packet *packets;
extern size_t plen;

#define packet_last		(plen - 1)

#define payload_last		(packets[packet_last].len - 1)

extern struct packet_dyn *packet_dyn;
extern size_t dlen;

#define packetd_last		(dlen - 1)

#define packetdc_last		(packet_dyn[packetd_last].clen - 1)
#define packetdr_last		(packet_dyn[packetd_last].rlen - 1)
#define packetds_last		(packet_dyn[packetd_last].slen - 1)

static int our_cpu, min_cpu = -1, max_cpu = -1;

static struct proto_hdr *hdr;

static inline int test_ignore(void)
{
	if (min_cpu < 0 && max_cpu < 0)
		return 0;
	else if (max_cpu >= our_cpu && min_cpu <= our_cpu)
		return 0;
	else
		return 1;
}

static inline void __init_new_packet_slot(struct packet *slot)
{
	slot->payload = NULL;
	slot->len = 0;
}

static inline void __init_new_counter_slot(struct packet_dyn *slot)
{
	slot->cnt = NULL;
	slot->clen = 0;
}

static inline void __init_new_randomizer_slot(struct packet_dyn *slot)
{
	slot->rnd = NULL;
	slot->rlen = 0;
}

static inline void __init_new_csum_slot(struct packet_dyn *slot)
{
	slot->csum = NULL;
	slot->slen = 0;
}

static inline void __setup_new_counter(struct counter *c, uint8_t start,
				       uint8_t stop, uint8_t stepping,
				       int type)
{
	c->min = start;
	c->max = stop;
	c->inc = stepping;
	c->val = (type == TYPE_INC) ? start : stop;
	c->off = payload_last;
	c->type = type;
}

static inline void __setup_new_randomizer(struct randomizer *r)
{
	r->off = payload_last;
}

static inline void __setup_new_csum16(struct csum16 *s, off_t from, off_t to,
				      enum csum which)
{
	s->off = payload_last - 1;
	s->from = from;
	s->to = to;
	s->which = which;
}

static void realloc_packet(void)
{
	if (test_ignore())
		return;

	plen++;
	packets = xrealloc(packets, plen * sizeof(*packets));

	__init_new_packet_slot(&packets[packet_last]);

	dlen++;
	packet_dyn = xrealloc(packet_dyn, dlen * sizeof(*packet_dyn));

	__init_new_counter_slot(&packet_dyn[packetd_last]);
	__init_new_randomizer_slot(&packet_dyn[packetd_last]);
	__init_new_csum_slot(&packet_dyn[packetd_last]);
}

struct packet *current_packet(void)
{
	return &packets[packet_last];
}

static void set_byte(uint8_t val)
{
	struct packet *pkt = &packets[packet_last];

	if (test_ignore())
		return;

	pkt->len++;
	pkt->payload = xrealloc(pkt->payload, pkt->len);
	pkt->payload[payload_last] = val;
}

static void set_multi_byte(uint8_t *s, size_t len)
{
	size_t i;

	for (i = 0; i < len; ++i)
		set_byte(s[i]);
}

void set_fill(uint8_t val, size_t len)
{
	size_t i;
	struct packet *pkt = &packets[packet_last];

	if (test_ignore())
		return;

	pkt->len += len;
	pkt->payload = xrealloc(pkt->payload, pkt->len);
	for (i = 0; i < len; ++i)
		pkt->payload[payload_last - i] = val;
}

static void __set_csum16_dynamic(size_t from, size_t to, enum csum which)
{
	struct packet *pkt = &packets[packet_last];
	struct packet_dyn *pktd = &packet_dyn[packetd_last];

	pkt->len += 2;
	pkt->payload = xrealloc(pkt->payload, pkt->len);

	pktd->slen++;
	pktd->csum = xrealloc(pktd->csum, pktd->slen * sizeof(struct csum16));

	__setup_new_csum16(&pktd->csum[packetds_last], from, to, which);
}

static void __set_csum16_static(size_t from, size_t to, enum csum which __maybe_unused)
{
	struct packet *pkt = &packets[packet_last];
	uint16_t sum;
	uint8_t *psum;

	sum = htons(calc_csum(pkt->payload + from, to - from));
	psum = (uint8_t *) &sum;

	set_byte(psum[0]);
	set_byte(psum[1]);
}

static inline bool is_dynamic_csum(enum csum which)
{
	switch (which) {
	case CSUM_UDP:
	case CSUM_TCP:
	case CSUM_UDP6:
	case CSUM_TCP6:
		return true;
	default:
		return false;
	}
}

static void set_csum16(size_t from, size_t to, enum csum which)
{
	struct packet *pkt = &packets[packet_last];
	struct packet_dyn *pktd = &packet_dyn[packetd_last];

	if (test_ignore())
		return;

	if (to < from) {
		size_t tmp = to;

		to = from;
		from = tmp;
	}

	bug_on(!(from < to));

	if (packet_dyn_has_elems(pktd) || to >= pkt->len || is_dynamic_csum(which))
		__set_csum16_dynamic(from, to, which);
	else
		__set_csum16_static(from, to, which);
}

static void set_rnd(size_t len)
{
	size_t i;
	struct packet *pkt = &packets[packet_last];

	if (test_ignore())
		return;

	pkt->len += len;
	pkt->payload = xrealloc(pkt->payload, pkt->len);
	for (i = 0; i < len; ++i)
		pkt->payload[payload_last - i] = (uint8_t) rand();
}

static void set_sequential_inc(uint8_t start, size_t len, uint8_t stepping)
{
	size_t i;
	struct packet *pkt = &packets[packet_last];

	if (test_ignore())
		return;

	pkt->len += len;
	pkt->payload = xrealloc(pkt->payload, pkt->len);
	for (i = 0; i < len; ++i) {
		off_t off = len - 1 - i;

		pkt->payload[payload_last - off] = start;
		start += stepping;
	}
}

static void set_sequential_dec(uint8_t start, size_t len, uint8_t stepping)
{
	size_t i;
	struct packet *pkt = &packets[packet_last];

	if (test_ignore())
		return;

	pkt->len += len;
	pkt->payload = xrealloc(pkt->payload, pkt->len);
	for (i = 0; i < len; ++i) {
		int off = len - 1 - i;

		pkt->payload[payload_last - off] = start;
		start -= stepping;
	}
}

static void set_dynamic_rnd(void)
{
	struct packet *pkt = &packets[packet_last];
	struct packet_dyn *pktd = &packet_dyn[packetd_last];

	if (test_ignore())
		return;

	pkt->len++;
	pkt->payload = xrealloc(pkt->payload, pkt->len);

	pktd->rlen++;
	pktd->rnd = xrealloc(pktd->rnd, pktd->rlen * sizeof(struct randomizer));

	__setup_new_randomizer(&pktd->rnd[packetdr_last]);
}

static void set_dynamic_incdec(uint8_t start, uint8_t stop, uint8_t stepping,
			       int type)
{
	struct packet *pkt = &packets[packet_last];
	struct packet_dyn *pktd = &packet_dyn[packetd_last];

	if (test_ignore())
		return;

	pkt->len++;
	pkt->payload = xrealloc(pkt->payload, pkt->len);

	pktd->clen++;
	pktd->cnt = xrealloc(pktd->cnt, pktd->clen * sizeof(struct counter));

	__setup_new_counter(&pktd->cnt[packetdc_last], start, stop, stepping, type);
}

static void proto_add(enum proto_id pid)
{
	hdr = proto_header_init(pid);
}

%}

%union {
	struct in_addr ip4_addr;
	long long int number;
	uint8_t bytes[256];
	char *str;
}

%token K_COMMENT K_FILL K_RND K_SEQINC K_SEQDEC K_DRND K_DINC K_DDEC K_WHITE
%token K_CPU K_CSUMIP K_CSUMUDP K_CSUMTCP K_CSUMUDP6 K_CSUMTCP6 K_CONST8 K_CONST16 K_CONST32 K_CONST64

%token K_DADDR K_SADDR K_ETYPE
%token K_OPER K_SHA K_SPA K_THA K_TPA K_REQUEST K_REPLY K_PTYPE K_HTYPE
%token K_PROT K_TTL K_DSCP K_ECN K_TOS K_LEN K_ID K_FLAGS K_FRAG K_IHL K_VER K_CSUM K_DF K_MF
%token K_SPORT K_DPORT
%token K_SEQ K_ACK_SEQ K_DOFF K_CWR K_ECE K_URG K_ACK K_PSH K_RST K_SYN K_FIN K_WINDOW K_URG_PTR
%token K_TPID K_TCI K_PCP K_DEI K_1Q K_1AD

%token K_ETH
%token K_VLAN
%token K_ARP
%token K_IP4
%token K_UDP K_TCP

%token ',' '{' '}' '(' ')' '[' ']' ':' '-' '+' '*' '/' '%' '&' '|' '<' '>' '^'

%token number string mac ip4_addr

%type <number> number expression
%type <str> string
%type <bytes> mac
%type <ip4_addr> ip4_addr

%left '-' '+' '*' '/' '%' '&' '|' '<' '>' '^'

%%

packets
	: { }
	| packets packet { }
	| packets inline_comment { }
	| packets K_WHITE { }
	;

inline_comment
	: K_COMMENT { }
	;

cpu_delim
	: ':' { }
	| '-' { }
	;

delimiter_nowhite
	: ',' { }
	| ',' K_WHITE { }
	;

noenforce_white
	: { }
	| K_WHITE { }
	| delimiter_nowhite { }
	;

skip_white
	: { }
	| K_WHITE { }
	;
packet
	: '{' noenforce_white payload noenforce_white '}' {
			min_cpu = max_cpu = -1;

			proto_packet_finish();

			realloc_packet();
		}
	| K_CPU '(' number cpu_delim number ')' ':' noenforce_white '{' noenforce_white payload noenforce_white '}' {
			min_cpu = $3;
			max_cpu = $5;

			if (min_cpu > max_cpu) {
				int tmp = min_cpu;

				min_cpu = max_cpu;
				max_cpu = tmp;
			}

			proto_packet_finish();

			realloc_packet();
		}
	| K_CPU '(' number ')' ':' noenforce_white '{' noenforce_white payload noenforce_white '}' {
			min_cpu = max_cpu = $3;

			proto_packet_finish();

			realloc_packet();
		}
	;

payload
	: elem { }
	| payload elem_delimiter { }
	;

delimiter
	: delimiter_nowhite { }
	| K_WHITE { }
	;

elem_delimiter
	: delimiter elem { }
	;

elem
	: number { set_byte((uint8_t) $1); }
	| string { set_multi_byte((uint8_t *) $1 + 1, strlen($1) - 2); }
	| fill { }
	| rnd { }
	| drnd { }
	| seqinc { }
	| seqdec { }
	| dinc { }
	| ddec { }
	| csum { }
	| const { }
	| proto { proto_header_finish(hdr); }
	| inline_comment { }
	;

expression
	: number
		{ $$ = $1; }
	| expression '+' expression
		{ $$ = $1 + $3; }
	| expression '-' expression
		{ $$ = $1 - $3; }
	| expression '*' expression
		{ $$ = $1 * $3; }
	| expression '/' expression
		{ $$ = $1 / $3; }
	| expression '%' expression
		{ $$ = $1 % $3; }
	| expression '&' expression
		{ $$ = $1 & $3; }
	| expression '|' expression
		{ $$ = $1 | $3; }
	| expression '^' expression
		{ $$ = $1 ^ $3; }
	| expression '<' '<' expression
		{ $$ = $1 << $4; }
	| expression '>' '>' expression
		{ $$ = $1 >> $4; }
	| '-' expression
		{ $$ = -1 * $2; }
	| '(' expression ')'
		{ $$ = $2;}
	;

fill
	: K_FILL '(' number delimiter number ')'
		{ set_fill($3, $5); }
	;

const
	: K_CONST8 '(' expression ')'
		{ set_byte((uint8_t) $3); }
	| K_CONST16 '(' expression ')' {
			uint16_t __c = cpu_to_be16((uint16_t) $3);

			set_multi_byte((uint8_t *) &__c, sizeof(__c));
		}
	| K_CONST32 '(' expression ')' {
			uint32_t __c = cpu_to_be32((uint32_t) $3);

			set_multi_byte((uint8_t *) &__c, sizeof(__c));
		}
	| K_CONST64 '(' expression ')' {
			uint64_t __c = cpu_to_be64((uint64_t) $3);

			set_multi_byte((uint8_t *) &__c, sizeof(__c));
		}
	;

rnd
	: K_RND '(' number ')'
		{ set_rnd($3); }
	;

csum
	: K_CSUMIP '(' number delimiter number ')'
		{ set_csum16($3, $5, CSUM_IP); }
	| K_CSUMTCP '(' number delimiter number ')'
		{ set_csum16($3, $5, CSUM_TCP); }
	| K_CSUMUDP '(' number delimiter number ')'
		{ set_csum16($3, $5, CSUM_UDP); }
	| K_CSUMTCP6 '(' number delimiter number ')'
		{ set_csum16($3, $5, CSUM_TCP6); }
	| K_CSUMUDP6 '(' number delimiter number ')'
		{ set_csum16($3, $5, CSUM_UDP6); }
	;

seqinc
	: K_SEQINC '(' number delimiter number ')'
		{ set_sequential_inc($3, $5, 1); }
	| K_SEQINC '(' number delimiter number delimiter number ')'
		{ set_sequential_inc($3, $5, $7); }
	;

seqdec
	: K_SEQDEC '(' number delimiter number ')'
		{ set_sequential_dec($3, $5, 1); }
	| K_SEQDEC '(' number delimiter number delimiter number ')'
		{ set_sequential_dec($3, $5, $7); }
	;

drnd
	: K_DRND '(' ')'
		{ set_dynamic_rnd(); }
	| K_DRND '(' number ')'
		{
			int i, max = $3;
			for (i = 0; i < max; ++i)
				set_dynamic_rnd();
		}
	;

dinc
	: K_DINC '(' number delimiter number ')'
		{ set_dynamic_incdec($3, $5, 1, TYPE_INC); }
	| K_DINC '(' number delimiter number delimiter number ')'
		{ set_dynamic_incdec($3, $5, $7, TYPE_INC); }
	;

ddec
	: K_DDEC '(' number delimiter number ')'
		{ set_dynamic_incdec($3, $5, 1, TYPE_DEC); }
	| K_DDEC '(' number delimiter number delimiter number ')'
		{ set_dynamic_incdec($3, $5, $7, TYPE_DEC); }
	;

proto
	: eth_proto { }
	| vlan_proto { }
	| arp_proto { }
	| ip4_proto { }
	| udp_proto { }
	| tcp_proto { }
	;

eth_proto
	: eth '(' eth_param_list ')' { }
	;

eth
	: K_ETH	{ proto_add(PROTO_ETH); }
	;

eth_param_list
	: { }
	| eth_field { }
	| eth_field delimiter eth_param_list { }
	;

eth_type
	: K_ETYPE { }
	| K_PROT { }
	;

eth_field
	: K_DADDR skip_white '=' skip_white mac
		{ proto_field_set_bytes(hdr, ETH_DST_ADDR, $5); }
	| K_SADDR skip_white '=' skip_white mac
		{ proto_field_set_bytes(hdr, ETH_SRC_ADDR, $5); }
	| eth_type skip_white '=' skip_white number
		{ proto_field_set_be16(hdr, ETH_TYPE, $5); }
	;

vlan_proto
	: vlan '(' vlan_param_list ')' { }
	;

vlan
	: K_VLAN { proto_add(PROTO_VLAN); }
	;

vlan_param_list
	: { }
	| vlan_field { }
	| vlan_field delimiter vlan_param_list { }
	;

vlan_type
	: K_TPID { }
	| K_PROT
	;

vlan_field
	: vlan_type skip_white '=' skip_white number
		{ proto_field_set_be16(hdr, VLAN_TPID, $5); }
	| K_1Q
		{ proto_field_set_be16(hdr, VLAN_TPID, ETH_P_8021Q); }
	| K_1AD
		{ proto_field_set_be16(hdr, VLAN_TPID, ETH_P_8021AD); }
	| K_TCI skip_white '=' skip_white number
		{ proto_field_set_be16(hdr, VLAN_TCI, $5); }
	| K_PCP skip_white '=' skip_white number
		{ proto_field_set_be16(hdr, VLAN_PCP, $5); }
	| K_DEI skip_white '=' skip_white number
		{ proto_field_set_be16(hdr, VLAN_DEI, $5); }
	| K_ID skip_white '=' skip_white number
		{ proto_field_set_be16(hdr, VLAN_VID, $5); }
	;

arp_proto
	: arp '(' arp_param_list ')' { }
	;

arp_param_list
	: { }
	| arp_field { }
	| arp_field delimiter arp_param_list { }
	;

arp_field
	: K_OPER skip_white '=' skip_white K_REQUEST
		{ proto_field_set_be16(hdr, ARP_OPER, ARPOP_REQUEST); }
	| K_OPER skip_white '=' skip_white K_REPLY
		{ proto_field_set_be16(hdr, ARP_OPER, ARPOP_REPLY); }
	| K_OPER skip_white '=' skip_white number
		{ proto_field_set_be16(hdr, ARP_OPER, $5); }
	| K_REQUEST
		{ proto_field_set_be16(hdr, ARP_OPER, ARPOP_REQUEST); }
	| K_REPLY
		{ proto_field_set_be16(hdr, ARP_OPER, ARPOP_REPLY); }
	| K_HTYPE skip_white '=' skip_white number
		{ proto_field_set_be16(hdr, ARP_HTYPE, $5); }
	| K_PTYPE skip_white '=' skip_white number
		{ proto_field_set_be16(hdr, ARP_PTYPE, $5); }
	| K_SHA skip_white '=' skip_white mac
		{ proto_field_set_bytes(hdr, ARP_SHA, $5); }
	| K_THA skip_white '=' skip_white mac
		{ proto_field_set_bytes(hdr, ARP_THA, $5); }
	| K_SPA skip_white '=' skip_white ip4_addr
		{ proto_field_set_u32(hdr, ARP_SPA, $5.s_addr); }
	| K_TPA skip_white '=' skip_white ip4_addr
		{ proto_field_set_u32(hdr, ARP_TPA, $5.s_addr); }
	;
arp
	: K_ARP	{ proto_add(PROTO_ARP); }
	;

ip4_proto
	: ip4 '(' ip4_param_list ')' { }
	;

ip4_param_list
	: { }
	| ip4_field { }
	| ip4_field delimiter ip4_param_list { }
	;

ip4_field
	: K_VER skip_white '=' skip_white number
		{ proto_field_set_u8(hdr, IP4_VER, $5); }
	| K_IHL skip_white '=' skip_white number
		{ proto_field_set_u8(hdr, IP4_IHL, $5); }
	| K_DADDR skip_white '=' skip_white ip4_addr
		{ proto_field_set_u32(hdr, IP4_DADDR, $5.s_addr); }
	| K_SADDR skip_white '=' skip_white ip4_addr
		{ proto_field_set_u32(hdr, IP4_SADDR, $5.s_addr); }
	| K_PROT skip_white '=' skip_white number
		{ proto_field_set_u8(hdr, IP4_PROTO, $5); }
	| K_TTL skip_white '=' skip_white number
		{ proto_field_set_u8(hdr, IP4_TTL, $5); }
	| K_DSCP skip_white '=' skip_white number
		{ proto_field_set_u8(hdr, IP4_DSCP, $5); }
	| K_ECN skip_white '=' skip_white number
		{ proto_field_set_u8(hdr, IP4_ECN, $5); }
	| K_TOS skip_white '=' skip_white number
		{ proto_field_set_u8(hdr, IP4_TOS, $5); }
	| K_LEN skip_white '=' skip_white number
		{ proto_field_set_be16(hdr, IP4_LEN, $5); }
	| K_ID skip_white '=' skip_white number
		{ proto_field_set_be16(hdr, IP4_ID, $5); }
	| K_FLAGS skip_white '=' skip_white number
		{ proto_field_set_be16(hdr, IP4_FLAGS, $5); }
	| K_DF  { proto_field_set_be16(hdr, IP4_DF, 1); }
	| K_MF  { proto_field_set_be16(hdr, IP4_MF, 1); }
	| K_FRAG skip_white '=' skip_white number
		{ proto_field_set_be16(hdr, IP4_FRAG_OFFS, $5); }
	| K_CSUM skip_white '=' skip_white number
		{ proto_field_set_be16(hdr, IP4_CSUM, $5); }
	;

ip4
	: K_IP4	{ proto_add(PROTO_IP4); }
	;

udp_proto
	: udp '(' udp_param_list ')' { }
	;

udp_param_list
	: { }
	| udp_field { }
	| udp_field delimiter udp_param_list { }
	;

udp_field
	: K_SPORT skip_white '=' skip_white number
		{ proto_field_set_be16(hdr, UDP_SPORT, $5); }
	| K_DPORT skip_white '=' skip_white number
		{ proto_field_set_be16(hdr, UDP_DPORT, $5); }
	| K_LEN skip_white '=' skip_white number
		{ proto_field_set_be16(hdr, UDP_LEN, $5); }
	| K_CSUM skip_white '=' skip_white number
		{ proto_field_set_be16(hdr, UDP_CSUM, $5); }
	;

udp
	: K_UDP	{ proto_add(PROTO_UDP); }
	;

tcp_proto
	: tcp '(' tcp_param_list ')' { }
	;

tcp_param_list
	: { }
	| tcp_field { }
	| tcp_field delimiter tcp_param_list { }
	;

tcp_field
	: K_SPORT skip_white '=' skip_white number
		{ proto_field_set_be16(hdr, TCP_SPORT, $5); }
	| K_DPORT skip_white '=' skip_white number
		{ proto_field_set_be16(hdr, TCP_DPORT, $5); }
	| K_SEQ skip_white '=' skip_white number
		{ proto_field_set_be32(hdr, TCP_SEQ, $5); }
	| K_ACK_SEQ skip_white '=' skip_white number
		{ proto_field_set_be32(hdr, TCP_ACK_SEQ, $5); }
	| K_DOFF skip_white '=' skip_white number
		{ proto_field_set_be16(hdr, TCP_DOFF, $5); }
	| K_CWR { proto_field_set_be16(hdr, TCP_CWR, 1); }
	| K_ECE { proto_field_set_be16(hdr, TCP_ECE, 1); }
	| K_URG { proto_field_set_be16(hdr, TCP_URG, 1); }
	| K_ACK { proto_field_set_be16(hdr, TCP_ACK, 1); }
	| K_PSH { proto_field_set_be16(hdr, TCP_PSH, 1); }
	| K_RST { proto_field_set_be16(hdr, TCP_RST, 1); }
	| K_SYN { proto_field_set_be16(hdr, TCP_SYN, 1); }
	| K_FIN { proto_field_set_be16(hdr, TCP_FIN, 1); }
	| K_WINDOW skip_white '=' skip_white number
		{ proto_field_set_be16(hdr, TCP_WINDOW, $5); }
	| K_CSUM skip_white '=' skip_white number
		{ proto_field_set_be16(hdr, TCP_CSUM, $5); }
	| K_URG_PTR skip_white '=' skip_white number
		{ proto_field_set_be16(hdr, TCP_URG_PTR, $5); }
	;

tcp
	: K_TCP	{ proto_add(PROTO_TCP); }
	;

%%

static void finalize_packet(void)
{
	/* XXX hack ... we allocated one packet pointer too much */
	plen--;
	dlen--;
}

static void dump_conf(void)
{
	size_t i, j;

	for (i = 0; i < plen; ++i) {
		printf("[%zu] pkt\n", i);
		printf(" len %zu cnts %zu rnds %zu\n",
		       packets[i].len,
		       packet_dyn[i].clen,
		       packet_dyn[i].rlen);

		printf(" payload ");
		for (j = 0; j < packets[i].len; ++j)
			printf("%02x ", packets[i].payload[j]);
		printf("\n");

		for (j = 0; j < packet_dyn[i].clen; ++j)
			printf(" cnt%zu [%u,%u], inc %u, off %jd type %s\n", j,
			       packet_dyn[i].cnt[j].min,
			       packet_dyn[i].cnt[j].max,
			       packet_dyn[i].cnt[j].inc,
			       (intmax_t)packet_dyn[i].cnt[j].off,
			       packet_dyn[i].cnt[j].type == TYPE_INC ?
			       "inc" : "dec");

		for (j = 0; j < packet_dyn[i].rlen; ++j)
			printf(" rnd%zu off %jd\n", j,
			       (intmax_t)packet_dyn[i].rnd[j].off);
	}
}

void cleanup_packets(void)
{
	size_t i;

	for (i = 0; i < plen; ++i) {
		if (packets[i].len > 0)
			xfree(packets[i].payload);
	}

	free(packets);

	for (i = 0; i < dlen; ++i) {
		free(packet_dyn[i].cnt);
		free(packet_dyn[i].rnd);
	}

	free(packet_dyn);
}

void compile_packets(char *file, bool verbose, unsigned int cpu,
		     bool invoke_cpp, char *const cpp_argv[])
{
	char tmp_file[128];
	int ret = -1;

	memset(tmp_file, 0, sizeof(tmp_file));
	our_cpu = cpu;

	if (invoke_cpp) {
		if (cpp_exec(file, tmp_file, sizeof(tmp_file), cpp_argv)) {
			fprintf(stderr, "Failed to invoke C preprocessor!\n");
			goto err;
		}
		file = tmp_file;
	}

	if (!strncmp("-", file, strlen("-")))
		yyin = stdin;
	else
		yyin = fopen(file, "r");
	if (!yyin) {
		fprintf(stderr, "Cannot open %s: %s!\n", file, strerror(errno));
		goto err;
	}

	realloc_packet();
	if (yyparse() != 0)
		goto err;
	finalize_packet();

	if (our_cpu == 0 && verbose)
		dump_conf();

	ret = 0;
err:
	if (yyin && yyin != stdin)
		fclose(yyin);

	if (invoke_cpp)
		unlink(tmp_file);
	if (ret)
		die();
}

void compile_packets_str(char *str, bool verbose, unsigned int cpu)
{
	int ret = 1;

	our_cpu = cpu;
	realloc_packet();

	yy_scan_string(str);
	if (yyparse() != 0)
		goto err;

	finalize_packet();
	if (our_cpu == 0 && verbose)
		dump_conf();

	ret = 0;
err:
	yylex_destroy();

	if (ret)
		die();
}

void yyerror(const char *err)
{
	fprintf(stderr, "Syntax error at line %d, char '%s': %s\n", yylineno, yytext, err);
}

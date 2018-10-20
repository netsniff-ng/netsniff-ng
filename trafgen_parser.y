/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2012 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL, version 2.
 */

/* yacc-func-prefix: yy */

%{

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <libgen.h>
#include <signal.h>
#include <unistd.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/icmpv6.h>

#include "xmalloc.h"
#include "trafgen_parser.tab.h"
#include "trafgen_conf.h"
#include "trafgen_proto.h"
#include "trafgen_l2.h"
#include "trafgen_l3.h"
#include "trafgen_l4.h"
#include "trafgen_l7.h"
#include "built_in.h"
#include "die.h"
#include "str.h"
#include "csum.h"
#include "cpp.h"

#ifndef ETH_P_8021AD
#define ETH_P_8021AD	0x88A8
#endif

#define YYERROR_VERBOSE		0
#define YYDEBUG			0
#define YYLTYPE_IS_TRIVIAL	1

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

enum field_expr_type_t {
	FIELD_EXPR_UNKNOWN	= 0,
	FIELD_EXPR_NUMB		= 1 << 0,
	FIELD_EXPR_MAC		= 1 << 1,
	FIELD_EXPR_IP4_ADDR	= 1 << 2,
	FIELD_EXPR_IP6_ADDR	= 1 << 3,
	FIELD_EXPR_INC		= 1 << 4,
	FIELD_EXPR_RND		= 1 << 5,
	FIELD_EXPR_OFFSET	= 1 << 6,
	FIELD_EXPR_STRING	= 1 << 7,
	FIELD_EXPR_FQDN		= 1 << 8,
};

struct proto_field_expr {
	enum field_expr_type_t type;
	struct proto_field *field;

	union {
		struct in_addr ip4_addr;
		struct in6_addr ip6_addr;
		long long int number;
		uint8_t mac[256];
		char *str;
		struct proto_field_func func;
	} val;
};

static struct proto_field_expr field_expr;
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
	memset(slot, 0, sizeof(*slot));
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

static inline void __init_new_fields_slot(struct packet_dyn *slot)
{
	slot->fields = NULL;
	slot->flen = 0;
}

static inline void __setup_new_counter(struct counter *c, uint8_t start,
				       uint8_t stop, uint8_t stepping,
				       int type)
{
	c->min = start;
	c->max = stop;
	c->inc = (type == TYPE_INC) ? stepping : -stepping;
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

struct packet *realloc_packet(void)
{
	uint32_t i;

	if (test_ignore())
		return NULL;

	plen++;
	packets = xrealloc(packets, plen * sizeof(*packets));

	__init_new_packet_slot(&packets[packet_last]);

	dlen++;
	packet_dyn = xrealloc(packet_dyn, dlen * sizeof(*packet_dyn));

	__init_new_counter_slot(&packet_dyn[packetd_last]);
	__init_new_randomizer_slot(&packet_dyn[packetd_last]);
	__init_new_csum_slot(&packet_dyn[packetd_last]);
	__init_new_fields_slot(&packet_dyn[packetd_last]);

	for (i = 0; i < plen; i++)
		packets[i].id = i;

	return &packets[packet_last];
}

struct packet *current_packet(void)
{
	return &packets[packet_last];
}

uint32_t current_packet_id(void)
{
	return packet_last;
}

struct packet *packet_get(uint32_t id)
{
	return &packets[id];
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
	case CSUM_ICMP6:
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
	hdr = proto_header_push(pid);
}

static void proto_field_set(uint32_t fid)
{
	memset(&field_expr, 0, sizeof(field_expr));
	field_expr.field = proto_hdr_field_by_id(hdr, fid);
}

static void proto_field_func_setup(struct proto_field *field, struct proto_field_func *func)
{
	struct proto_field *field_copy;
	struct packet_dyn *pkt_dyn;

	field_copy = xmalloc(sizeof(*field));
	memcpy(field_copy, field, sizeof(*field));

	field_copy->pkt_offset += func->offset;
	if (func->len)
		field_copy->len = func->len;

	proto_field_func_add(field_copy, func);

	pkt_dyn = &packet_dyn[packetd_last];
	pkt_dyn->flen++;
	pkt_dyn->fields = xrealloc(pkt_dyn->fields, pkt_dyn->flen *
				   sizeof(struct proto_field *));

	pkt_dyn->fields[pkt_dyn->flen - 1] = field_copy;
}

static void proto_field_expr_eval(void)
{
	struct proto_field *field = field_expr.field;

	if ((field_expr.type & FIELD_EXPR_OFFSET) &&
			!((field_expr.type & FIELD_EXPR_INC) ||
				(field_expr.type & FIELD_EXPR_RND))) {

		panic("Field offset expression is valid only with function expression\n");
	}

	if (field_expr.type & FIELD_EXPR_NUMB) {
		if (field->len == 1)
			proto_field_set_u8(field, field_expr.val.number);
		else if (field->len == 2)
			proto_field_set_be16(field, field_expr.val.number);
		else if (field->len == 4)
			proto_field_set_be32(field, field_expr.val.number);
		else
			panic("Invalid value length %zu, can be 1,2 or 4\n", field->len);
	} else if (field_expr.type & FIELD_EXPR_MAC) {
		proto_field_set_bytes(field, field_expr.val.mac, 6);
	} else if (field_expr.type & FIELD_EXPR_FQDN) {
		char *fqdn = str2fqdn(field_expr.val.str);
		proto_field_set_bytes(field, (uint8_t *) fqdn, strlen(fqdn) + 1);
		xfree(field_expr.val.str);
		xfree(fqdn);
	} else if (field_expr.type & FIELD_EXPR_STRING) {
		proto_field_set_string(field, field_expr.val.str);
		xfree(field_expr.val.str);
	} else if (field_expr.type & FIELD_EXPR_IP4_ADDR) {
		proto_field_set_u32(field, field_expr.val.ip4_addr.s_addr);
	} else if (field_expr.type & FIELD_EXPR_IP6_ADDR) {
		proto_field_set_bytes(field, (uint8_t *)&field_expr.val.ip6_addr.s6_addr, 16);
	} else if ((field_expr.type & FIELD_EXPR_INC) ||
			(field_expr.type & FIELD_EXPR_RND)) {

		if (field_expr.val.func.min
			&& field_expr.val.func.min >= field_expr.val.func.max)
			panic("dinc(): min(%u) can't be >= max(%u)\n",
				field_expr.val.func.min, field_expr.val.func.max);

		proto_field_func_setup(field, &field_expr.val.func);
	} else if ((field_expr.type & FIELD_EXPR_OFFSET) &&
			!((field_expr.type & FIELD_EXPR_INC) ||
				(field_expr.type & FIELD_EXPR_RND))) {

		panic("Field expression is valid only for function value expression\n");
	} else {
		bug();
	}

	memset(&field_expr, 0, sizeof(field_expr));
}

static void field_index_validate(struct proto_field *field, uint16_t index, size_t len)
{
	if (field_expr.field->len <= index) {
		yyerror("Invalid [index] parameter");
		panic("Index (%u) is bigger than field's length (%zu)\n",
		       index, field->len);
	}
	if (len != 1 && len != 2 && len != 4) {
		yyerror("Invalid [index:len] parameter");
		panic("Invalid index length - 1,2 or 4 is only allowed\n");
	}
}

static void proto_push_sub_hdr(uint32_t id)
{
	hdr = proto_hdr_push_sub_header(hdr, id);
}

static void proto_pop_sub_hdr(void)
{
	if (hdr->ops->header_finish)
		hdr->ops->header_finish(hdr);

	hdr = hdr->parent;
}

%}

%union {
	struct in_addr ip4_addr;
	struct in6_addr ip6_addr;
	long long int number;
	uint8_t mac[6];
	char *str;
}

%token K_COMMENT K_FILL K_RND K_SEQINC K_SEQDEC K_DRND K_DINC K_DDEC K_WHITE
%token K_CPU K_CSUMIP K_CSUMUDP K_CSUMTCP K_CSUMUDP6 K_CSUMTCP6 K_CSUMICMP6 K_CONST8 K_CONST16 K_CONST32 K_CONST64

%token K_DADDR K_SADDR K_ETYPE K_TYPE
%token K_TIME K_PRIO
%token K_OPER K_SHA K_SPA K_THA K_TPA K_REQUEST K_REPLY K_PTYPE K_HTYPE
%token K_PROT K_TTL K_DSCP K_ECN K_TOS K_LEN K_ID K_FLAGS K_FRAG K_IHL K_VER K_CSUM K_DF K_MF
%token K_FLOW K_NEXT_HDR K_HOP_LIMIT
%token K_CODE K_ECHO_REQUEST K_ECHO_REPLY
%token K_SPORT K_DPORT
%token K_SEQ K_ACK_SEQ K_DOFF K_CWR K_ECE K_URG K_ACK K_PSH K_RST K_SYN K_FIN K_WINDOW K_URG_PTR
%token K_TPID K_TCI K_PCP K_DEI K_1Q K_1AD
%token K_LABEL K_TC K_LAST K_EXP

%token K_ADDR K_MTU

%token K_QR K_AANSWER K_TRUNC K_RAVAIL K_RDESIRED K_ZERO K_RCODE K_QDCOUNT K_ANCOUNT K_NSCOUNT K_ARCOUNT
%token K_QUERY K_ANSWER K_AUTH K_ADD
%token K_NAME K_CLASS K_DATA K_NS K_CNAME K_PTR

%token K_ETH
%token K_PAUSE
%token K_PFC
%token K_VLAN K_MPLS
%token K_ARP
%token K_IP4 K_IP6
%token K_ICMP4 K_ICMP6
%token K_UDP K_TCP
%token K_DNS

%token ',' '{' '}' '(' ')' '[' ']' ':' '-' '+' '*' '/' '%' '&' '|' '<' '>' '^'

%token number string mac ip4_addr ip6_addr

%type <number> number expression
%type <str> string
%type <mac> mac
%type <ip4_addr> ip4_addr
%type <ip6_addr> ip6_addr

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
	| K_CSUMICMP6 '(' number delimiter number ')'
		{ set_csum16($3, $5, CSUM_ICMP6); }
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
	| pause_proto { }
	| pfc_proto { }
	| vlan_proto { }
	| mpls_proto { }
	| arp_proto { }
	| ip4_proto { }
	| ip6_proto { }
	| icmp4_proto { }
	| icmpv6_proto { }
	| udp_proto { }
	| tcp_proto { }
	| dns_proto { }
	;

field_expr
	: '[' skip_white number skip_white ']'
		{ field_index_validate(field_expr.field, $3, 1);
		  field_expr.type |= FIELD_EXPR_OFFSET;
		  field_expr.val.func.offset = $3;
		  field_expr.val.func.len = 1; }
	| '[' skip_white number skip_white ':' skip_white number skip_white ']'
		{ field_index_validate(field_expr.field, $3, $7);
		  field_expr.type |= FIELD_EXPR_OFFSET;
		  field_expr.val.func.offset = $3;
		  field_expr.val.func.len = $7; }
	;

field_value_expr
	: number { field_expr.type |= FIELD_EXPR_NUMB;
		   field_expr.val.number = $1; }
	| mac { field_expr.type |= FIELD_EXPR_MAC;
		memcpy(field_expr.val.mac, $1, sizeof(field_expr.val.mac)); }
	| string { field_expr.type |= FIELD_EXPR_STRING;
		   field_expr.val.str = xstrdup($1 + 1);
		   field_expr.val.str[strlen($1 + 1) - 1] = '\0'; }
	| ip4_addr { field_expr.type |= FIELD_EXPR_IP4_ADDR;
		     field_expr.val.ip4_addr = $1; }
	| ip6_addr { field_expr.type |= FIELD_EXPR_IP6_ADDR;
		     field_expr.val.ip6_addr = $1; }
	| K_DINC '(' ')' { field_expr.type |= FIELD_EXPR_INC;
			   field_expr.val.func.type = PROTO_FIELD_FUNC_INC;
			   field_expr.val.func.inc = 1; }
	| K_DINC '(' number ')'
			{ field_expr.type |= FIELD_EXPR_INC;
			  field_expr.val.func.type = PROTO_FIELD_FUNC_INC;
			  field_expr.val.func.inc = $3; }
	| K_DINC '(' number delimiter number ')'
			{ field_expr.type |= FIELD_EXPR_INC;
			  field_expr.val.func.type  = PROTO_FIELD_FUNC_INC;
			  field_expr.val.func.type |= PROTO_FIELD_FUNC_MIN;
			  field_expr.val.func.min = $3;
			  field_expr.val.func.max = $5;
			  field_expr.val.func.inc = 1; }
	| K_DINC '(' number delimiter number delimiter number ')'
			{ field_expr.type |= FIELD_EXPR_INC;
			  field_expr.val.func.type  = PROTO_FIELD_FUNC_INC;
			  field_expr.val.func.type |= PROTO_FIELD_FUNC_MIN;
			  field_expr.val.func.min = $3;
			  field_expr.val.func.max = $5;
			  field_expr.val.func.inc = $7; }
	| K_DRND '(' ')' { field_expr.type |= FIELD_EXPR_RND;
			  field_expr.val.func.type = PROTO_FIELD_FUNC_RND; }
	| K_DRND '(' number delimiter number ')'
			{ field_expr.type |= FIELD_EXPR_RND;
			  field_expr.val.func.type = PROTO_FIELD_FUNC_RND;
			  field_expr.val.func.min = $3;
			  field_expr.val.func.max = $5; }
	;

eth_proto
	: eth '(' eth_param_list ')' { }
	;

eth
	: K_ETH	{ proto_add(PROTO_ETH); }
	;

eth_param_list
	: { }
	| eth_expr { }
	| eth_expr delimiter eth_param_list { }
	;

eth_type
	: K_ETYPE { }
	| K_TYPE { }
	| K_PROT { }
	;

eth_field
	: K_DADDR { proto_field_set(ETH_DST_ADDR); }
	| K_SADDR { proto_field_set(ETH_SRC_ADDR); }
	| eth_type { proto_field_set(ETH_TYPE); }

eth_expr
	: eth_field field_expr skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	| eth_field skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	;

pause_proto
	: pause '(' pause_param_list ')' { }
	;

pause
	: K_PAUSE { proto_add(PROTO_PAUSE); }
	;

pause_param_list
	: { }
	| pause_expr { }
	| pause_expr delimiter pause_param_list { }
	;

pause_field
	: K_CODE { proto_field_set(PAUSE_OPCODE); }
	| K_TIME { proto_field_set(PAUSE_TIME); }
	;

pause_expr
	: pause_field field_expr skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	| pause_field skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	;

pfc_proto
	: pfc '(' pfc_param_list ')' { }
	;

pfc
	: K_PFC { proto_add(PROTO_PFC); }
	;

pfc_param_list
	: { }
	| pfc_expr { }
	| pfc_expr delimiter pfc_param_list { }
	;

pfc_field
	: K_CODE { proto_field_set(PFC_OPCODE); }
	| K_PRIO { proto_field_set(PFC_PRIO); }
	| K_PRIO '(' number ')'
		{ if ($3 > 7) {
		      yyerror("pfc: Invalid prio(index) parameter");
		      panic("pfc: prio(0)..prio(7) is allowed only\n");
		  }
		  proto_field_set(PFC_PRIO_0 + $3); }
	| K_TIME '(' number ')'
		{ if ($3 > 7) {
		      yyerror("pfc: Invalid time(index) parameter");
		      panic("pfc: time(0)..time(7) is allowed only\n");
		  }
		  proto_field_set(PFC_TIME_0 + $3); }
	;

pfc_expr
	: pfc_field field_expr skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	| pfc_field skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	;

vlan_proto
	: vlan '(' vlan_param_list ')' { }
	;

vlan
	: K_VLAN { proto_add(PROTO_VLAN); }
	;

vlan_param_list
	: { }
	| vlan_expr { }
	| vlan_expr delimiter vlan_param_list { }
	;

vlan_type
	: K_TPID { }
	| K_PROT
	;

vlan_field
	: vlan_type { proto_field_set(VLAN_TPID); }
	| K_TCI { proto_field_set(VLAN_TCI); }
	| K_PCP { proto_field_set(VLAN_PCP); }
	| K_DEI { proto_field_set(VLAN_DEI); }
	| K_ID { proto_field_set(VLAN_VID); }
	;

vlan_expr
	: vlan_field field_expr skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	| vlan_field skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	| K_1Q
		{ proto_hdr_field_set_be16(hdr, VLAN_TPID, ETH_P_8021Q); }
	| K_1AD
		{ proto_hdr_field_set_be16(hdr, VLAN_TPID, ETH_P_8021AD); }
	;

mpls_proto
	: mpls '(' mpls_param_list ')' { }
	;

mpls
	: K_MPLS { proto_add(PROTO_MPLS); }
	;

mpls_param_list
	: { }
	| mpls_expr { }
	| mpls_expr delimiter mpls_param_list { }
	;

mpls_tc
	: K_TC { }
	| K_EXP { }
	;

mpls_field
	: K_LABEL { proto_field_set(MPLS_LABEL); }
	| mpls_tc { proto_field_set(MPLS_TC); }
	| K_LAST { proto_field_set(MPLS_LAST); }
	| K_TTL { proto_field_set(MPLS_TTL); }
	;

mpls_expr
	: mpls_field field_expr skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	| mpls_field skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	;

arp_proto
	: arp '(' arp_param_list ')' { }
	;

arp_param_list
	: { }
	| arp_expr { }
	| arp_expr delimiter arp_param_list { }
	;

arp_field
	: K_HTYPE
		{ proto_field_set(ARP_HTYPE); }
	| K_PTYPE
		{ proto_field_set(ARP_PTYPE); }
	| K_SHA
		{ proto_field_set(ARP_SHA); }
	| K_THA
		{ proto_field_set(ARP_THA); }
	| K_SPA
		{ proto_field_set(ARP_SPA); }
	| K_TPA
		{ proto_field_set(ARP_TPA); }
	;

arp_expr
	: arp_field field_expr skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	| arp_field skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	| K_OPER field_expr skip_white '=' skip_white field_value_expr
		{ proto_field_set(ARP_OPER);
		  proto_field_expr_eval(); }
	| K_OPER skip_white '=' skip_white field_value_expr
		{ proto_field_set(ARP_OPER);
		  proto_field_expr_eval(); }
	| K_OPER skip_white '=' skip_white K_REQUEST
		{ proto_hdr_field_set_be16(hdr, ARP_OPER, ARPOP_REQUEST); }
	| K_OPER skip_white '=' skip_white K_REPLY
		{ proto_hdr_field_set_be16(hdr, ARP_OPER, ARPOP_REPLY); }
	| K_REQUEST
		{ proto_hdr_field_set_be16(hdr, ARP_OPER, ARPOP_REQUEST); }
	| K_REPLY
		{ proto_hdr_field_set_be16(hdr, ARP_OPER, ARPOP_REPLY); }
	;

arp
	: K_ARP	{ proto_add(PROTO_ARP); }
	;

ip4_proto
	: ip4 '(' ip4_param_list ')' { }
	;

ip4_param_list
	: { }
	| ip4_expr { }
	| ip4_expr delimiter ip4_param_list { }
	;

ip4_field
	: K_VER { proto_field_set(IP4_VER); }
	| K_IHL { proto_field_set(IP4_IHL); }
	| K_DADDR { proto_field_set(IP4_DADDR); }
	| K_SADDR { proto_field_set(IP4_SADDR); }
	| K_PROT { proto_field_set(IP4_PROTO); }
	| K_TTL { proto_field_set(IP4_TTL); }
	| K_DSCP { proto_field_set(IP4_DSCP); }
	| K_ECN { proto_field_set(IP4_ECN); }
	| K_TOS { proto_field_set(IP4_TOS); }
	| K_LEN { proto_field_set(IP4_LEN); }
	| K_ID { proto_field_set(IP4_ID); }
	| K_FLAGS { proto_field_set(IP4_FLAGS); }
	| K_FRAG { proto_field_set(IP4_FRAG_OFFS); }
	| K_CSUM { proto_field_set(IP4_CSUM); }
	;

ip4_expr
	: ip4_field field_expr skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	| ip4_field skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	| K_DF  { proto_hdr_field_set_be16(hdr, IP4_DF, 1); }
	| K_MF  { proto_hdr_field_set_be16(hdr, IP4_MF, 1); }
	;

ip4
	: K_IP4	{ proto_add(PROTO_IP4); }
	;

ip6_proto
	: ip6 '(' ip6_param_list ')' { }
	;

ip6_param_list
	: { }
	| ip6_expr { }
	| ip6_expr delimiter ip6_param_list { }
	;

ip6_hop_limit
	: K_HOP_LIMIT { }
	| K_TTL { }
	;

ip6_field
	: K_VER { proto_field_set(IP6_VER); }
	| K_TC { proto_field_set(IP6_CLASS); }
	| K_FLOW { proto_field_set(IP6_FLOW_LBL); }
	| K_LEN { proto_field_set(IP6_LEN); }
	| K_NEXT_HDR { proto_field_set(IP6_NEXT_HDR); }
	| ip6_hop_limit { proto_field_set(IP6_HOP_LIMIT); }
	| K_SADDR { proto_field_set(IP6_SADDR); }
	| K_DADDR { proto_field_set(IP6_DADDR) ; }
	;

ip6_expr
	: ip6_field field_expr skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	| ip6_field skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	;

ip6
	: K_IP6	{ proto_add(PROTO_IP6); }
	;

icmp4_proto
	: icmp4 '(' icmp4_param_list ')' { }
	;

icmp4_param_list
	: { }
	| icmp4_expr { }
	| icmp4_expr delimiter icmp4_param_list { }
	;

icmp4_field
	: K_TYPE { proto_field_set(ICMPV4_TYPE); }
	| K_CODE { proto_field_set(ICMPV4_CODE); }
	| K_ID { proto_field_set(ICMPV4_ID); }
	| K_SEQ { proto_field_set(ICMPV4_SEQ); }
	| K_MTU { proto_field_set(ICMPV4_MTU); }
	| K_ADDR { proto_field_set(ICMPV4_REDIR_ADDR); }
	;

icmp4_expr
	: icmp4_field field_expr skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	| icmp4_field skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	| K_ECHO_REQUEST
		{ proto_hdr_field_set_u8(hdr, ICMPV4_TYPE, ICMP_ECHO);
		  proto_hdr_field_set_u8(hdr, ICMPV4_CODE, 0); }
	| K_ECHO_REPLY
		{ proto_hdr_field_set_u8(hdr, ICMPV4_TYPE, ICMP_ECHOREPLY);
		  proto_hdr_field_set_u8(hdr, ICMPV4_CODE, 0); }
	;

icmp4
	: K_ICMP4	{ proto_add(PROTO_ICMP4); }
	;

icmpv6_proto
	: icmp6 '(' icmp6_param_list ')' { }
	;

icmp6_param_list
	: { }
	| icmp6_expr { }
	| icmp6_expr delimiter icmp6_param_list { }
	;

icmp6_field
	: K_CODE { proto_field_set(ICMPV6_CODE); }
	| K_CSUM { proto_field_set(ICMPV6_CSUM); }
	;

icmp6_expr
	: icmp6_field field_expr skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	| icmp6_field skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	| K_TYPE field_expr skip_white '=' skip_white field_value_expr
		{ proto_field_set(ICMPV6_TYPE);
		  proto_field_expr_eval(); }
	| K_TYPE skip_white '=' skip_white field_value_expr
		{ proto_field_set(ICMPV6_TYPE);
		  proto_field_expr_eval(); }
	| K_TYPE skip_white '=' K_ECHO_REQUEST
		{ proto_hdr_field_set_u8(hdr, ICMPV6_TYPE, ICMPV6_ECHO_REQUEST); }
	| K_ECHO_REQUEST
		{ proto_hdr_field_set_u8(hdr, ICMPV6_TYPE, ICMPV6_ECHO_REQUEST); }
	| K_TYPE skip_white '=' K_ECHO_REPLY
		{ proto_hdr_field_set_u8(hdr, ICMPV6_TYPE, ICMPV6_ECHO_REPLY); }
	| K_ECHO_REPLY
		{ proto_hdr_field_set_u8(hdr, ICMPV6_TYPE, ICMPV6_ECHO_REPLY); }
	;
icmp6
	: K_ICMP6 { proto_add(PROTO_ICMP6); }
	;

udp_proto
	: udp '(' udp_param_list ')' { }
	;

udp_param_list
	: { }
	| udp_expr { }
	| udp_expr delimiter udp_param_list { }
	;

udp_field
	: K_SPORT { proto_field_set(UDP_SPORT); }
	| K_DPORT { proto_field_set(UDP_DPORT); }
	| K_LEN { proto_field_set(UDP_LEN); }
	| K_CSUM { proto_field_set(UDP_CSUM); }
	;

udp_expr
	: udp_field field_expr skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	| udp_field skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	;

udp
	: K_UDP	{ proto_add(PROTO_UDP); }
	;

tcp_proto
	: tcp '(' tcp_param_list ')' { }
	;

tcp_param_list
	: { }
	| tcp_expr { }
	| tcp_expr delimiter tcp_param_list { }
	;

tcp_field
	: K_SPORT { proto_field_set(TCP_SPORT); }
	| K_DPORT { proto_field_set(TCP_DPORT); }
	| K_SEQ { proto_field_set(TCP_SEQ); }
	| K_ACK_SEQ { proto_field_set(TCP_ACK_SEQ); }
	| K_DOFF { proto_field_set(TCP_DOFF); }
	| K_WINDOW { proto_field_set(TCP_WINDOW); }
	| K_CSUM { proto_field_set(TCP_CSUM); }
	| K_URG_PTR { proto_field_set(TCP_URG_PTR); }
	;

tcp_expr
	: tcp_field field_expr skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	| tcp_field skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	| K_CWR { proto_hdr_field_set_be16(hdr, TCP_CWR, 1); }
	| K_ECE { proto_hdr_field_set_be16(hdr, TCP_ECE, 1); }
	| K_URG { proto_hdr_field_set_be16(hdr, TCP_URG, 1); }
	| K_ACK { proto_hdr_field_set_be16(hdr, TCP_ACK, 1); }
	| K_PSH { proto_hdr_field_set_be16(hdr, TCP_PSH, 1); }
	| K_RST { proto_hdr_field_set_be16(hdr, TCP_RST, 1); }
	| K_SYN { proto_hdr_field_set_be16(hdr, TCP_SYN, 1); }
	| K_FIN { proto_hdr_field_set_be16(hdr, TCP_FIN, 1); }
	;

tcp
	: K_TCP	{ proto_add(PROTO_TCP); }
	;

dns_proto
	: dns '(' dns_param_list ')' { }
	;

dns_param_list
	: { }
	| dns_expr { }
	| dns_expr delimiter dns_param_list { }
	;

dns_field
	: K_ID { proto_field_set(DNS_ID); }
	| K_QR { proto_field_set(DNS_QR); }
	| K_OPER { proto_field_set(DNS_OPCODE); }
	| K_AANSWER { proto_field_set(DNS_AA); }
	| K_TRUNC { proto_field_set(DNS_TC); }
	| K_RDESIRED { proto_field_set(DNS_RD); }
	| K_RAVAIL { proto_field_set(DNS_RA); }
	| K_ZERO { proto_field_set(DNS_ZERO); }
	| K_RCODE { proto_field_set(DNS_RCODE); }
	| K_QDCOUNT { proto_field_set(DNS_QD_COUNT); }
	| K_ANCOUNT { proto_field_set(DNS_AN_COUNT); }
	| K_NSCOUNT { proto_field_set(DNS_NS_COUNT); }
	| K_ARCOUNT { proto_field_set(DNS_AR_COUNT); }
	;

dns_query
	: K_QUERY { proto_push_sub_hdr(DNS_QUERY_HDR); }
	;

dns_query_name
	: K_NAME { proto_field_set(DNS_QUERY_NAME); }
	;

dns_query_field
	: K_TYPE { proto_field_set(DNS_QUERY_TYPE); }
	| K_CLASS { proto_field_set(DNS_QUERY_CLASS); }
	;

dns_query_expr
	: dns_query_field field_expr skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	| dns_query_field skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	| dns_query_name field_expr skip_white '=' skip_white field_value_expr
		{ if (field_expr.type & FIELD_EXPR_STRING)
			field_expr.type = FIELD_EXPR_FQDN;
		  proto_field_expr_eval(); }
	| dns_query_name skip_white '=' skip_white field_value_expr
		{ if (field_expr.type & FIELD_EXPR_STRING)
			field_expr.type = FIELD_EXPR_FQDN;
		  proto_field_expr_eval(); }
	;

dns_query_param_list
	: { }
	| dns_query_expr { }
	| dns_query_expr delimiter dns_query_param_list { }
	;

dns_query_hdr
	: dns_query '(' dns_query_param_list ')' { }
	;

dns_rrecord
	: K_ANSWER { proto_push_sub_hdr(DNS_ANSWER_HDR); }
	| K_AUTH { proto_push_sub_hdr(DNS_AUTH_HDR); }
	| K_ADD { proto_push_sub_hdr(DNS_ADD_HDR); }
	;

dns_rrecord_name
	: K_NAME { proto_field_set(DNS_RRECORD_NAME); }
	;

dns_rrecord_data_addr
	: ip4_addr
		{ proto_hdr_field_set_u32(hdr, DNS_RRECORD_DATA, $1.s_addr);
		  proto_hdr_field_set_be16(hdr, DNS_RRECORD_TYPE, 1); }
	| ip6_addr
		{ proto_hdr_field_set_bytes(hdr, DNS_RRECORD_DATA, (uint8_t *)&$1.s6_addr, 16);
		  proto_hdr_field_set_be16(hdr, DNS_RRECORD_TYPE, 28); }
	;

dns_rrecord_data_fqdn
	: string
		{ char *str = xstrdup($1 + 1);
		  char *fqdn;
		  str[strlen($1 + 1) - 1] = '\0';
		  fqdn = str2fqdn(str);
		  proto_hdr_field_set_bytes(hdr, DNS_RRECORD_DATA, (uint8_t *) fqdn, strlen(fqdn) + 1);
		  xfree(str);
		  xfree(fqdn); }
	;

dns_rrecord_data_expr
	: K_ADDR '(' skip_white dns_rrecord_data_addr skip_white ')'
		{ }
	| K_NS '(' skip_white dns_rrecord_data_fqdn skip_white ')'
		{ proto_hdr_field_set_be16(hdr, DNS_RRECORD_TYPE, 2); }
	| K_CNAME '(' skip_white dns_rrecord_data_fqdn skip_white ')'
		{ proto_hdr_field_set_be16(hdr, DNS_RRECORD_TYPE, 5); }
	| K_PTR '(' skip_white dns_rrecord_data_fqdn skip_white ')'
		{ proto_hdr_field_set_be16(hdr, DNS_RRECORD_TYPE, 12); }
	;

dns_rrecord_field
	: K_TYPE { proto_field_set(DNS_RRECORD_TYPE); }
	| K_CLASS { proto_field_set(DNS_RRECORD_CLASS); }
	| K_TTL { proto_field_set(DNS_RRECORD_TTL); }
	| K_LEN { proto_field_set(DNS_RRECORD_LEN); }
	| K_DATA { proto_field_set(DNS_RRECORD_DATA); }
	;

dns_rrecord_expr
	: dns_rrecord_field field_expr skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	| dns_rrecord_field skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	| dns_rrecord_name field_expr skip_white '=' skip_white field_value_expr
		{ if (field_expr.type & FIELD_EXPR_STRING)
			field_expr.type = FIELD_EXPR_FQDN;
		  proto_field_expr_eval(); }
	| dns_rrecord_name skip_white '=' skip_white field_value_expr
		{ if (field_expr.type & FIELD_EXPR_STRING)
			field_expr.type = FIELD_EXPR_FQDN;
		  proto_field_expr_eval(); }
	| dns_rrecord_data_expr
		{ }
	;

dns_rrecord_param_list
	: { }
	| dns_rrecord_expr { }
	| dns_rrecord_expr delimiter dns_rrecord_param_list { }
	;

dns_rrecord_hdr
	: dns_rrecord '(' dns_rrecord_param_list ')' { }
	;

dns_expr
	: dns_field field_expr skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	| dns_field skip_white '=' skip_white field_value_expr
		{ proto_field_expr_eval(); }
	| dns_query_hdr { proto_pop_sub_hdr(); }
	| dns_rrecord_hdr { proto_pop_sub_hdr(); }
	;

dns
	: K_DNS	{ proto_add(PROTO_DNS); }
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
	size_t i, j;

	for (i = 0; i < plen; ++i) {
		struct packet *pkt = &packets[i];

		if (pkt->len > 0)
			xfree(pkt->payload);

		for (j = 0; j < pkt->headers_count; j++) {
			struct proto_hdr *hdr = pkt->headers[j];
			uint32_t k;

			for (k = 0; k < hdr->sub_headers_count; k++)
				xfree(hdr->sub_headers[k]);

			if (hdr->sub_headers)
				xfree(hdr->sub_headers);

			if (hdr->fields)
				xfree(hdr->fields);

			xfree(hdr);
		}
	}

	free(packets);

	for (i = 0; i < dlen; ++i) {
		free(packet_dyn[i].cnt);
		free(packet_dyn[i].rnd);

		for (j = 0; j < packet_dyn[j].flen; j++)
			xfree(packet_dyn[i].fields[j]);

		free(packet_dyn[i].fields);
	}

	free(packet_dyn);
}

void compile_packets(char *file, bool verbose, unsigned int cpu,
		     bool invoke_cpp, char *const cpp_argv[])
{
	char tmp_file[128];
	int ret = -1;

	if (strncmp("-", file, strlen("-")) && access(file, R_OK)) {
		fprintf(stderr, "Cannot access %s: %s!\n", file, strerror(errno));
		die();
	}

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

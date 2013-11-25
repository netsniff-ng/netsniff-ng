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

#include "xmalloc.h"
#include "trafgen_parser.tab.h"
#include "trafgen_conf.h"
#include "built_in.h"
#include "die.h"
#include "str.h"
#include "csum.h"

#define YYERROR_VERBOSE		0
#define YYDEBUG			0
#define YYENABLE_NLS		1
#define YYLTYPE_IS_TRIVIAL	1
#define ENABLE_NLS		1

extern FILE *yyin;
extern int yylex(void);
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

static inline int test_ignore(void)
{
	if (min_cpu < 0 && max_cpu < 0)
		return 0;
	else if (max_cpu >= our_cpu && min_cpu <= our_cpu)
		return 0;
	else
		return 1;
}

static inline int has_dynamic_elems(struct packet_dyn *p)
{
	return (p->rlen + p->slen + p->clen);
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
	packets = xrealloc(packets, 1, plen * sizeof(*packets));

	__init_new_packet_slot(&packets[packet_last]);

	dlen++;
	packet_dyn = xrealloc(packet_dyn, 1, dlen * sizeof(*packet_dyn));

	__init_new_counter_slot(&packet_dyn[packetd_last]);
	__init_new_randomizer_slot(&packet_dyn[packetd_last]);
	__init_new_csum_slot(&packet_dyn[packetd_last]);
}

static void set_byte(uint8_t val)
{
	struct packet *pkt = &packets[packet_last];

	if (test_ignore())
		return;

	pkt->len++;
	pkt->payload = xrealloc(pkt->payload, 1, pkt->len);
	pkt->payload[payload_last] = val;
}

static void set_multi_byte(uint8_t *s, size_t len)
{
	size_t i;

	for (i = 0; i < len; ++i)
		set_byte(s[i]);
}

static void set_fill(uint8_t val, size_t len)
{
	size_t i;
	struct packet *pkt = &packets[packet_last];

	if (test_ignore())
		return;

	pkt->len += len;
	pkt->payload = xrealloc(pkt->payload, 1, pkt->len);
	for (i = 0; i < len; ++i)
		pkt->payload[payload_last - i] = val;
}

static void __set_csum16_dynamic(size_t from, size_t to, enum csum which)
{
	struct packet *pkt = &packets[packet_last];
	struct packet_dyn *pktd = &packet_dyn[packetd_last];

	pkt->len += 2;
	pkt->payload = xrealloc(pkt->payload, 1, pkt->len);

	pktd->slen++;
	pktd->csum = xrealloc(pktd->csum, 1, pktd->slen * sizeof(struct csum16));

	__setup_new_csum16(&pktd->csum[packetds_last], from, to, which);
}

static void __set_csum16_static(size_t from, size_t to, enum csum which __maybe_unused)
{
	struct packet *pkt = &packets[packet_last];
	uint16_t sum;
	uint8_t *psum;

	sum = htons(calc_csum(pkt->payload + from, to - from, 0));
	psum = (uint8_t *) &sum;

	set_byte(psum[0]);
	set_byte(psum[1]);
}

static void set_csum16(size_t from, size_t to, enum csum which)
{
	int make_it_dynamic = 0;
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

	if (to >= pkt->len || which == CSUM_TCP || which == CSUM_UDP)
		make_it_dynamic = 1;

	if (has_dynamic_elems(pktd) || make_it_dynamic)
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
	pkt->payload = xrealloc(pkt->payload, 1, pkt->len);
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
	pkt->payload = xrealloc(pkt->payload, 1, pkt->len);
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
	pkt->payload = xrealloc(pkt->payload, 1, pkt->len);
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
	pkt->payload = xrealloc(pkt->payload, 1, pkt->len);

	pktd->rlen++;
	pktd->rnd = xrealloc(pktd->rnd, 1, pktd->rlen *	sizeof(struct randomizer));

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
	pkt->payload = xrealloc(pkt->payload, 1, pkt->len);

	pktd->clen++;
	pktd->cnt =xrealloc(pktd->cnt, 1, pktd->clen * sizeof(struct counter));

	__setup_new_counter(&pktd->cnt[packetdc_last], start, stop, stepping, type);
}

%}

%union {
	long long int number;
	char *str;
}

%token K_COMMENT K_FILL K_RND K_SEQINC K_SEQDEC K_DRND K_DINC K_DDEC K_WHITE
%token K_CPU K_CSUMIP K_CSUMUDP K_CSUMTCP K_CONST8 K_CONST16 K_CONST32 K_CONST64

%token ',' '{' '}' '(' ')' '[' ']' ':' '-' '+' '*' '/' '%' '&' '|' '<' '>' '^'

%token number string

%type <number> number expression
%type <str> string

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

packet
	: '{' noenforce_white payload noenforce_white '}' {
			min_cpu = max_cpu = -1;
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

			realloc_packet();
		}
	| K_CPU '(' number ')' ':' noenforce_white '{' noenforce_white payload noenforce_white '}' {
			min_cpu = max_cpu = $3;
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
			printf(" cnt%zu [%u,%u], inc %u, off %ld type %s\n", j,
			       packet_dyn[i].cnt[j].min,
			       packet_dyn[i].cnt[j].max,
			       packet_dyn[i].cnt[j].inc,
			       packet_dyn[i].cnt[j].off,
			       packet_dyn[i].cnt[j].type == TYPE_INC ?
			       "inc" : "dec");

		for (j = 0; j < packet_dyn[i].rlen; ++j)
			printf(" rnd%zu off %ld\n", j,
			       packet_dyn[i].rnd[j].off);
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

int compile_packets(char *file, int verbose, int cpu, bool invoke_cpp)
{
	char tmp_file[128];

	memset(tmp_file, 0, sizeof(tmp_file));
	our_cpu = cpu;

	if (invoke_cpp) {
		char cmd[256], *dir, *base, *a, *b;

		dir = dirname((a = xstrdup(file)));
		base = basename((b = xstrdup(file)));

		slprintf(tmp_file, sizeof(tmp_file), "%s/.tmp-%u-%s", dir, rand(), base);
		slprintf(cmd, sizeof(cmd), "cpp -I" PREFIX_STRING
			 "/etc/netsniff-ng/ %s > %s", file, tmp_file);
		if (system(cmd) != 0)
			panic("Failed to invoke C preprocessor!\n");

		file = tmp_file;
		xfree(a);
		xfree(b);
	}

	if (!strncmp("-", file, strlen("-")))
		yyin = stdin;
	else
		yyin = fopen(file, "r");
	if (!yyin)
		panic("Cannot open %s: %s!\n", file, strerror(errno));

	realloc_packet();
	yyparse();
	finalize_packet();

	if (our_cpu == 0 && verbose)
		dump_conf();

	fclose(yyin);
	if (invoke_cpp)
		unlink(tmp_file);

	return 0;
}

void yyerror(const char *err)
{
	panic("Syntax error at line%d, at char '%s'! %s!\n", yylineno, yytext, err);
}

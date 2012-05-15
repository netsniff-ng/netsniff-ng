/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2012 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL, version 2.
 */

%{

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <stdint.h>
#include <errno.h>

#include "xmalloc.h"
#include "trafgen_parser.tab.h"
#include "trafgen_conf.h"
#include "built_in.h"
#include "die.h"
#include "mtrand.h"

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
extern unsigned int packets_len;
#define packets_last		(packets_len - 1)
#define payload_last		(packets[packets_last].len - 1)

extern struct packet_dynamics *packet_dyns;
extern unsigned int packet_dyn_len;
#define packetds_last		(packet_dyn_len - 1)
#define packetds_c_last		(packet_dyns[packetds_last].counter_len - 1)
#define packetds_r_last		(packet_dyns[packetds_last].randomizer_len - 1)

static int dfunc_note_flag = 0;

static void give_note_dynamic(void)
{
	if (!dfunc_note_flag) {
		printf("Note: dynamic elements like drnd, dinc, ddec and "
		       "others make trafgen slower!\n");
		dfunc_note_flag = 1;
	}
}

static inline void init_new_packet_slot(struct packet *slot)
{
	slot->payload = NULL;
	slot->len = 0;
}

static inline void init_new_counter_slot(struct packet_dynamics *slot)
{
	slot->counter = NULL;
	slot->counter_len = 0;
}

static inline void init_new_randomizer_slot(struct packet_dynamics *slot)
{
	slot->randomizer = NULL;
	slot->randomizer_len = 0;
}

static void realloc_packet(void)
{
	packets_len++;
	packets = xrealloc(packets, 1, packets_len * sizeof(*packets));

	init_new_packet_slot(&packets[packets_last]);

	packet_dyn_len++;
	packet_dyns = xrealloc(packet_dyns, 1,
			       packet_dyn_len * sizeof(*packet_dyns));

	init_new_counter_slot(&packet_dyns[packetds_last]);
	init_new_randomizer_slot(&packet_dyns[packetds_last]);
}

static void set_byte(uint8_t val)
{
	packets[packets_last].len++;
	packets[packets_last].payload = xrealloc(packets[packets_last].payload,
						 1, packets[packets_last].len);
	packets[packets_last].payload[payload_last] = val;
}

static void set_fill(uint8_t val, size_t len)
{
	int i;

	packets[packets_last].len += len;
	packets[packets_last].payload = xrealloc(packets[packets_last].payload,
						 1, packets[packets_last].len);
	for (i = 0; i < len; ++i)
		packets[packets_last].payload[payload_last - i] = val;
}

static void set_rnd(size_t len)
{
	int i;

	packets[packets_last].len += len;
	packets[packets_last].payload = xrealloc(packets[packets_last].payload,
						 1, packets[packets_last].len);
	for (i = 0; i < len; ++i)
		packets[packets_last].payload[payload_last - i] =
			(uint8_t) mt_rand_int32();
}

static void set_seqinc(uint8_t start, size_t len, uint8_t stepping)
{
	int i;

	packets[packets_last].len += len;
	packets[packets_last].payload = xrealloc(packets[packets_last].payload,
						 1, packets[packets_last].len);
	for (i = 0; i < len; ++i) {
		int off = len - 1 - i;
		packets[packets_last].payload[payload_last - off] = start;
		start += stepping;
	}
}

static void set_seqdec(uint8_t start, size_t len, uint8_t stepping)
{
	int i;

	packets[packets_last].len += len;
	packets[packets_last].payload = xrealloc(packets[packets_last].payload,
						 1, packets[packets_last].len);
	for (i = 0; i < len; ++i) {
		int off = len - 1 - i;
		packets[packets_last].payload[payload_last - off] = start;
		start -= stepping;
	}
}

static inline void setup_new_counter(struct counter *counter, uint8_t start,
				     uint8_t stop, uint8_t stepping, int type)
{
	counter->min = start;
	counter->max = stop;
	counter->inc = stepping;
	counter->val = (type == TYPE_INC) ? start : stop;
	counter->off = payload_last;
	counter->type = type;
}

static inline void setup_new_randomizer(struct randomizer *randomizer)
{
	randomizer->val = (uint8_t) mt_rand_int32();
	randomizer->off = payload_last;
}

static void set_drnd(void)
{
	give_note_dynamic();

	packets[packets_last].len++;
	packets[packets_last].payload = xrealloc(packets[packets_last].payload,
						 1, packets[packets_last].len);

	packet_dyns[packetds_last].randomizer_len++;
	packet_dyns[packetds_last].randomizer =
		xrealloc(packet_dyns[packetds_last].randomizer, 1,
			 packet_dyns[packetds_last].randomizer_len *
				sizeof(struct randomizer));

	setup_new_randomizer(&packet_dyns[packetds_last].
				randomizer[packetds_r_last]);
}

static void set_dincdec(uint8_t start, uint8_t stop, uint8_t stepping, int type)
{
	give_note_dynamic();

	packets[packets_last].len++;
	packets[packets_last].payload = xrealloc(packets[packets_last].payload,
						 1, packets[packets_last].len);

	packet_dyns[packetds_last].counter_len++;
	packet_dyns[packetds_last].counter =
		xrealloc(packet_dyns[packetds_last].counter, 1,
			 packet_dyns[packetds_last].counter_len *
				sizeof(struct counter));

	setup_new_counter(&packet_dyns[packetds_last].counter[packetds_c_last],
			  start, stop, stepping, type);
}

%}

%union {
	long int number;
}

%token K_COMMENT K_FILL K_RND K_SEQINC K_SEQDEC K_DRND K_DINC K_DDEC K_WHITE
%token K_NEWL

%token ',' '{' '}' '(' ')' '[' ']'

%token number_hex number_dec number_ascii number_bin number_oct

%type <number> number_hex number_dec number_ascii number_bin number_oct number

%%

packets
	: { }
	| packets packet { }
	| packets inline_comment { }
	| packets white { }
	;

inline_comment
	: K_COMMENT { }
	;

packet
	: '{' delimiter payload delimiter '}' { realloc_packet(); }
	;

payload
	: elem { }
	| payload elem_delimiter { }
	;

white
	: white K_WHITE { }
	| white K_NEWL { }
	| K_WHITE { }
	| K_NEWL { }
	;

delimiter
	: ',' { }
	| white { }
	| ',' white { }
	;

elem_delimiter
	: delimiter elem { }
	;

number
	: number_dec { $$ = $1; }
	| number_hex { $$ = $1; }
	| number_ascii { $$ = $1; }
	| number_bin { $$ = $1; }
	| number_oct { $$ = $1; }
	;

fill
	: K_FILL '(' number delimiter number ')'
		{ set_fill($3, $5); }
	;

rnd
	: K_RND '(' number ')'
		{ set_rnd($3); }
	;

seqinc
	: K_SEQINC '(' number delimiter number ')'
		{ set_seqinc($3, $5, 1); }
	| K_SEQINC '(' number delimiter number delimiter number ')'
		{ set_seqinc($3, $5, $7); }
	;

seqdec
	: K_SEQDEC '(' number delimiter number ')'
		{ set_seqdec($3, $5, 1); }
	| K_SEQDEC '(' number delimiter number delimiter number ')'
		{ set_seqdec($3, $5, $7); }
	;

drnd
	: K_DRND '(' ')'
		{ set_drnd(); }
	| K_DRND '(' number ')'
		{
			int i, max = $3;
			for (i = 0; i < max; ++i)
				set_drnd();
		}
	;

dinc
	: K_DINC '(' number delimiter number ')'
		{ set_dincdec($3, $5, 1, TYPE_INC); }
	| K_DINC '(' number delimiter number delimiter number ')'
		{ set_dincdec($3, $5, $7, TYPE_INC); }
	;

ddec
	: K_DDEC '(' number delimiter number ')'
		{ set_dincdec($3, $5, 1, TYPE_DEC); }
	| K_DDEC '(' number delimiter number delimiter number ')'
		{ set_dincdec($3, $5, $7, TYPE_DEC); }
	;

elem
	: number { set_byte((uint8_t) $1); }
	| fill { }
	| rnd { }
	| drnd { }
	| seqinc { }
	| seqdec { }
	| dinc { }
	| ddec { }
	| inline_comment { }
	;

%%

static void finalize_packet(void)
{
	/* XXX hack ... we allocated one packet pointer too much */
	packets_len--;
	packet_dyn_len--;
}

static void dump_conf(void)
{
	size_t i, j;

	for (i = 0; i < packets_len; ++i) {
		printf("[%zu] pkt\n", i);
		printf(" len %zu cnts %zu rnds %zu\n",
		       packets[i].len,
		       packet_dyns[i].counter_len,
		       packet_dyns[i].randomizer_len);

		printf(" payload ");
		for (j = 0; j < packets[i].len; ++j)
			printf("%02x ", packets[i].payload[j]);
		printf("\n");

		for (j = 0; j < packet_dyns[i].counter_len; ++j)
			printf(" cnt%zu [%u,%u], inc %u, off %ld type %s\n", j,
			       packet_dyns[i].counter[j].min,
			       packet_dyns[i].counter[j].max,
			       packet_dyns[i].counter[j].inc,
			       packet_dyns[i].counter[j].off,
			       packet_dyns[i].counter[j].type == TYPE_INC ?
			       "inc" : "dec");

		for (j = 0; j < packet_dyns[i].randomizer_len; ++j)
			printf(" rnd%zu off %ld\n", j,
			       packet_dyns[i].randomizer[j].off);
	}
}

void cleanup_packets(void)
{
	int i;

	for (i = 0; i < packets_len; ++i) {
		if (packets[i].len > 0)
			xfree(packets[i].payload);
	}

	if (packets_len > 0)
		xfree(packets);

	for (i = 0; i < packet_dyn_len; ++i) {
		if (packet_dyns[i].counter_len > 0)
			xfree(packet_dyns[i].counter);

		if (packet_dyns[i].randomizer_len > 0)
			xfree(packet_dyns[i].randomizer);
	}

	if (packet_dyn_len > 0)
		xfree(packet_dyns);
}

int compile_packets(char *file, int verbose)
{
	mt_init_by_seed_time();

	yyin = fopen(file, "r");
	if (!yyin)
		panic("Cannot open file!\n");

	realloc_packet();
	yyparse();
	finalize_packet();

	if (verbose) {
		dump_conf();
	} else {
		int i;
		size_t total_len = 0;

		printf("%u packets to schedule\n", packets_len);
		for (i = 0; i < packets_len; ++i)
			total_len += packets[i].len;
		printf("%zu bytes in total\n", total_len);
	}

	fclose(yyin);
	return 0;
}

void yyerror(const char *err)
{
	panic("Syntax error at line %d: '%s'! %s!\n", yylineno, yytext, err);
}

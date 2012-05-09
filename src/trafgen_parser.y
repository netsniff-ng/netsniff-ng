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

static struct pktconf *conf = NULL;
static int note_flag = 0;

#define am(x)	((x)->len - 1)

static void give_note_dynamic(void)
{
	if (!note_flag) {
		printf("Note: dynamic elements like drnd, dinc, ddec and "
		       "others make trafgen slower!\n");
		note_flag = 1;
	}
}

static void dump_conf(struct pktconf *cfg)
{
	size_t i, j;

	printf("n %lu, gap %lu us, pkts %zu\n", cfg->num, cfg->gap, cfg->len);
	if (cfg->len == 0)
		return;
	for (i = 0; i < cfg->len; ++i) {
		printf("[%zu] pkt\n", i);
		printf(" len %zu cnts %zu rnds %zu\n", cfg->pkts[i].plen,
		       cfg->pkts[i].clen, cfg->pkts[i].rlen);
		printf(" payload ");
		for (j = 0; j < cfg->pkts[i].plen; ++j)
			printf("%02x ", cfg->pkts[i].payload[j]);
		printf("\n");
		for (j = 0; j < cfg->pkts[i].clen; ++j)
			printf(" cnt%zu [%u,%u], inc %u, off %ld type %s\n",
			       j, cfg->pkts[i].cnt[j].min,
			       cfg->pkts[i].cnt[j].max,
			       cfg->pkts[i].cnt[j].inc,
			       cfg->pkts[i].cnt[j].off,
			       cfg->pkts[i].cnt[j].type == TYPE_INC ?
			       "inc" : "dec");
		for (j = 0; j < cfg->pkts[i].rlen; ++j)
			printf(" rnd%zu off %ld\n",
			       j, cfg->pkts[i].rnd[j].off);
	}
}

static void realloc_packet(void)
{
	conf->len++;
	conf->pkts = xrealloc(conf->pkts, 1, conf->len * sizeof(*conf->pkts));
	fmemset(&conf->pkts[am(conf)], 0, sizeof(conf->pkts[am(conf)]));
}

static void set_byte(uint8_t val)
{
	int base;

	conf->pkts[am(conf)].plen++;
	conf->pkts[am(conf)].payload = xrealloc(conf->pkts[am(conf)].payload,
						1, conf->pkts[am(conf)].plen);

	base = conf->pkts[am(conf)].plen - 1;
	conf->pkts[am(conf)].payload[base] = val;
}

static void set_fill(uint8_t val, size_t len)
{
	int i, base;

	conf->pkts[am(conf)].plen += len;
	conf->pkts[am(conf)].payload = xrealloc(conf->pkts[am(conf)].payload,
						1, conf->pkts[am(conf)].plen);

	base = conf->pkts[am(conf)].plen - 1;
	for (i = 0; i < len; ++i) {
		conf->pkts[am(conf)].payload[base - i] = val;
	}
}

static void set_rnd(size_t len)
{
	int i, base;

	conf->pkts[am(conf)].plen += len;
	conf->pkts[am(conf)].payload = xrealloc(conf->pkts[am(conf)].payload,
						1, conf->pkts[am(conf)].plen);

	base = conf->pkts[am(conf)].plen - 1;
	for (i = 0; i < len; ++i) {
		conf->pkts[am(conf)].payload[base - i] = (uint8_t) mt_rand_int32();
	}
}

static void set_seqinc(uint8_t start, size_t len, uint8_t stepping)
{
	int i, base;

	conf->pkts[am(conf)].plen += len;
	conf->pkts[am(conf)].payload = xrealloc(conf->pkts[am(conf)].payload,
						1, conf->pkts[am(conf)].plen);

	base = conf->pkts[am(conf)].plen - 1;
	for (i = 0; i < len; ++i) {
		int off = len - 1 - i;
		conf->pkts[am(conf)].payload[base - off] = start;
		start += stepping;
	}
}

static void set_seqdec(uint8_t start, size_t len, uint8_t stepping)
{
	int i, base;

	conf->pkts[am(conf)].plen += len;
	conf->pkts[am(conf)].payload = xrealloc(conf->pkts[am(conf)].payload,
						1, conf->pkts[am(conf)].plen);

	base = conf->pkts[am(conf)].plen - 1;
	for (i = 0; i < len; ++i) {
		int off = len - 1 - i;
		conf->pkts[am(conf)].payload[base - off] = start;
		start -= stepping;
	}
}

static void set_drnd(void)
{
	int base, rnds;
	struct randomizer *new;

	give_note_dynamic();

	conf->pkts[am(conf)].plen++;
	conf->pkts[am(conf)].payload = xrealloc(conf->pkts[am(conf)].payload,
						1, conf->pkts[am(conf)].plen);

	base = conf->pkts[am(conf)].plen - 1;
	rnds = ++(conf->pkts[am(conf)].rlen);

	conf->pkts[am(conf)].rnd = xrealloc(conf->pkts[am(conf)].rnd,
					    1, rnds * sizeof(struct randomizer));

	new = &conf->pkts[am(conf)].rnd[rnds - 1];
	new->val = (uint8_t) mt_rand_int32();
	new->off = base;
}

static void set_dincdec(uint8_t start, uint8_t stop, uint8_t stepping, int type)
{
	int base, cnts;
	struct counter *new;

	give_note_dynamic();

	conf->pkts[am(conf)].plen++;
	conf->pkts[am(conf)].payload = xrealloc(conf->pkts[am(conf)].payload,
						1, conf->pkts[am(conf)].plen);

	base = conf->pkts[am(conf)].plen - 1;
	cnts = ++(conf->pkts[am(conf)].clen);

	conf->pkts[am(conf)].cnt = xrealloc(conf->pkts[am(conf)].cnt,
					    1, cnts * sizeof(struct counter));

	new = &conf->pkts[am(conf)].cnt[cnts - 1];
	new->min = start;
	new->max = stop;
	new->inc = stepping;
	new->val = type == TYPE_INC ? start : stop;
	new->off = base;
	new->type = type;
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
	: white K_WHITE
	| white K_NEWL
	| K_WHITE
	| K_NEWL
	;

delimiter
	: ','
	| white
	| ',' white
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

int compile_packets(char *file, struct pktconf *cfg, int verbose)
{
	yyin = fopen(file, "r");
	if (!yyin)
		panic("Cannot open file!\n");
	if (!cfg)
		panic("No config given!\n");

	mt_init_by_seed_time();
	conf = cfg;
	realloc_packet();

	yyparse();
	/* hack ... */
	conf->len--;

	if (verbose)
		dump_conf(cfg);
	else {
		int i;
		size_t total_len = 0;

		printf("%zu packets to schedule\n", conf->len);

		for (i = 0; i < conf->len; ++i)
			total_len += conf->pkts[i].plen;
		printf("%zu bytes in total\n", total_len);
	}

	fclose(yyin);
	return 0;
}

void yyerror(const char *err)
{
	panic("Syntax error at line %d: '%s'! %s!\n",
	      yylineno, yytext, err);
}

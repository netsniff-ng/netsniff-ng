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

#define am(x)	((x)->len - 1)

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
			printf(" cnt%zu [%u,%u], inc %u, off %ld\n",
			       j, cfg->pkts[i].cnt[j].min,
			       cfg->pkts[i].cnt[j].max,
			       cfg->pkts[i].cnt[j].inc,
			       cfg->pkts[i].cnt[j].off);
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
	conf->pkts[am(conf)].plen++;
	conf->pkts[am(conf)].payload = xrealloc(conf->pkts[am(conf)].payload,
						1, conf->pkts[am(conf)].plen);

	conf->pkts[am(conf)].payload[conf->pkts[am(conf)].plen - 1] = val;
}

static void set_fill(uint8_t val, size_t len)
{
	int i;

	conf->pkts[am(conf)].plen += len;
	conf->pkts[am(conf)].payload = xrealloc(conf->pkts[am(conf)].payload,
						1, conf->pkts[am(conf)].plen);

	for (i = 0; i < len; ++i) {
		conf->pkts[am(conf)].
			payload[conf->pkts[am(conf)].plen - 1 - i] = val;
	}
}

static void set_rnd(size_t len)
{
	int i;

	conf->pkts[am(conf)].plen += len;
	conf->pkts[am(conf)].payload = xrealloc(conf->pkts[am(conf)].payload,
						1, conf->pkts[am(conf)].plen);

	for (i = 0; i < len; ++i) {
		conf->pkts[am(conf)].
			payload[conf->pkts[am(conf)].plen - 1 - i] =
				(uint8_t) mt_rand_int32();
	}
}



%}

%union {
	long int number;
}

%token K_COMMENT K_FILL K_RND K_SEQINC K_SEQDEC K_DRND K_DINC K_DDEC

%token ' ' ',' '{' '}' '(' ')' '[' ']'

%token number_hex number_dec number_ascii number_bin number_oct

%type <number> number_hex number_dec number_ascii number_bin number_oct number

%%

packets
	: { }
	| packets packet { }
	| packets inline_comment { }
	;

inline_comment
	: K_COMMENT { }
	;

packet
	: '{' ' ' payload ' ' '}' { realloc_packet(); }
	;

payload
	: elem { }
	| payload elem_delimiter { }
	;

delimiter
	: ','
	| ' '
	| ',' ' '
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
	: K_FILL '(' number delimiter number ')' { set_fill($3, $5); }
	;

rnd
	: K_RND '(' number ')' { set_rnd($3); }
	;

drnd
	: K_DRND '(' number ')'
		{ printf("Drnd times %u\n", $3); }
	;

seqinc
	: K_SEQINC '(' number delimiter number ')'
		{ printf("Seqinc from %u times %u\n", $3, $5); }
	| K_SEQINC '(' number delimiter number delimiter number ')'
		{ printf("Seqinc from %u times %u steps %u\n", $3, $5, $7); }
	;

seqdec
	: K_SEQDEC '(' number delimiter number ')'
		{ printf("Seqdec from %u times %u\n", $3, $5); }
	| K_SEQDEC '(' number delimiter number delimiter number ')'
		{ printf("Seqdec from %u times %u steps %u\n", $3, $5, $7); }
	;

dinc
	: K_DINC '(' number delimiter number ')'
		{ printf("Dinc from %u to %u\n", $3, $5); }
	| K_DINC '(' number delimiter number delimiter number ')'
		{ printf("Seqinc from %u to %u stepping %u\n", $3, $5, $7); }
	;

ddec
	: K_DDEC '(' number delimiter number ')'
		{ printf("Ddec from %u to %u\n", $3, $5); }
	| K_DDEC '(' number delimiter number delimiter number ')'
		{ printf("Ddec from %u to %u stepping %u\n", $3, $5, $7); }
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

	fclose(yyin);
	return 0;
}

void yyerror(const char *err)
{
	panic("Syntax error at line %d: '%s'! %s!\n",
	      yylineno, yytext, err);
}

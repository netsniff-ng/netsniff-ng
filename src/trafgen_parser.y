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
#include "built_in.h"
#include "die.h"

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
	: {}
	| packets packet { }
	| packets inline_comment { }
	;

inline_comment
	: K_COMMENT {}
	;

packet
	: '{' ' ' payload ' ' '}' { }
	;

payload
	: elem {}
	| payload elem_delimiter {}
	;

delimiter
	: ','
	| ' '
	| ',' ' '
	;

elem_delimiter
	: delimiter elem {}
	;

number
	: number_dec { printf("Got dec: %u\n", $1); }
	| number_hex { printf("Got hex: %u\n", $1); }
	| number_ascii { printf("Got ascii: %u\n", $1); }
	| number_bin { printf("Got bin: %u\n", $1); }
	| number_oct { printf("Got oct: %u\n", $1); }
	;

fill
	: K_FILL '(' number delimiter number ')' { printf("Fill %u times %u\n", $3, $5); }
	;

rnd
	: K_RND '(' number ')' { printf("Rnd times %u\n", $3); }
	;

drnd
	: K_DRND '(' number ')' { printf("Drnd times %u\n", $3); }
	;

seqinc
	: K_SEQINC '(' number delimiter number ')' { printf("Seqinc from %u times %u\n", $3, $5); }
	| K_SEQINC '(' number delimiter number delimiter number ')' { printf("Seqinc from %u times %u steps %u\n", $3, $5, $7); }
	;

seqdec
	: K_SEQDEC '(' number delimiter number ')' { printf("Seqdec from %u times %u\n", $3, $5); }
	| K_SEQDEC '(' number delimiter number delimiter number ')' { printf("Seqdec from %u times %u steps %u\n", $3, $5, $7); }
	;

dinc
	: K_DINC '(' number delimiter number ')' { printf("Dinc from %u to %u\n", $3, $5); }
	| K_DINC '(' number delimiter number delimiter number ')' { printf("Seqinc from %u to %u stepping %u\n", $3, $5, $7); }
	;

ddec
	: K_DDEC '(' number delimiter number ')' { printf("Ddec from %u to %u\n", $3, $5); }
	| K_DDEC '(' number delimiter number delimiter number ')' { printf("Ddec from %u to %u stepping %u\n", $3, $5, $7); }
	;

elem
	: number {}
	| fill {}
	| rnd {}
	| drnd {}
	| seqinc {}
	| seqdec {}
	| dinc {}
	| ddec {}
	| inline_comment {}
	;

%%

int compile_packets(char *file)
{
	yyin = fopen(file, "r");
	if (!yyin)
		panic("Cannot open file!\n");
	yyparse();
	return 0;
}

void yyerror(const char *err)
{
	panic("Syntax error at line %d: '%s'! %s!\n",
	      yylineno, yytext, err);
}

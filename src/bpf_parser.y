/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

%{

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <errno.h>

#include "bpf.h"
#include "xmalloc.h"
#include "bpf_parser.h"
#include "bpf_parser.tab.h"
#include "compiler.h"
#include "die.h"

#define MAX_INSTRUCTIONS	256

static int curr_inst = 0;

static struct sock_fprog out[MAX_INSTRUCTIONS];

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
	int number;
	char *label;
}

%token OP_LDB OP_LDH OP_LD OP_LDX OP_ST OP_STX OP_JMP OP_JEQ OP_JGT OP_JGE
%token OP_JSET OP_ADD OP_SUB OP_MUL OP_DIV OP_AND OP_OR OP_LSH OP_RSH OP_RET
%token OP_TAX OP_TXA

%token AD_COLON AD_PLUS AD_BROP AD_BRCL

%token number_hex number_dec label

%type <number> number_hex number_dec number do_ldb
%type <label> label do_label

%%

prog: {}
	| prog line { }
	;

line: instr { }
	| labeled_instr { }
	;

labeled_instr: do_label instr { }
	;

instr: do_ldb { }
	| do_ldh { }
	| do_ld { }
	| do_ldx { }
	| do_st { }
	| do_stx { }
	| do_jmp { }
	| do_jeq { }
	| do_jgt { }
	| do_jge { }
	| do_jset { }
	| do_add { }
	| do_sub { }
	| do_mul { }
	| do_div { }
	| do_and { }
	| do_or { }
	| do_lsh { }
	| do_rsh { }
	| do_ret { }
	| do_tax { }
	| do_txa { }
	;

number: number_dec { $$ = $1; }
	| number_hex { $$ = $1; }
	;

do_label: label AD_COLON { info("got:%s\n", $1); }
	;

do_ldb: OP_LDB AD_BROP 'x' AD_PLUS number AD_BRCL { info("got:%d\n", $5); }
	| OP_LDB AD_BROP number AD_BRCL { info("got:%d\n", $3); }
	;

do_ldh: OP_LDH { }
	;

do_ld: OP_LD { }
	;

do_ldx: OP_LDX { }
	;

do_st: OP_ST { }
	;

do_stx: OP_STX { }
	;

do_jmp: OP_JMP { }
	;

do_jeq: OP_JEQ { }
	;

do_jgt: OP_JGT { }
	;

do_jge: OP_JGE { }
	;

do_jset: OP_JSET { }
	;

do_add: OP_ADD { }
	;

do_sub: OP_SUB { }
	;

do_mul: OP_MUL { }
	;

do_div: OP_DIV { }
	;

do_and: OP_AND { }
	;

do_or: OP_OR { }
	;

do_lsh: OP_LSH { }
	;

do_rsh: OP_RSH { }
	;

do_ret: OP_RET { }
	;

do_tax: OP_TAX { }
	;

do_txa: OP_TXA { }
	;

%%

int compile_filter(char *file, int verbose)
{
	yyin = fopen(file, "r");
	if (!yyin)
		panic("Cannot open file!\n");
	memset(out, 0, sizeof(out));
	yyparse();
	if (bpf_validate(out) == 0)
		panic("Semantic error! BPF validation failed!\n");
	return 0;
}

void yyerror(const char *err)
{
	panic("Syntax error at line %d: %s! %s!\n",
	      yylineno, yytext, err);
}


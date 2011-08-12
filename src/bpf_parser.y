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

/* Opcode token */
%token OP_LDB OP_LDH OP_LD OP_LDX OP_ST OP_STX OP_JMP OP_JEQ OP_JGT OP_JGE
%token OP_JSET OP_ADD OP_SUB OP_MUL OP_DIV OP_AND OP_OR OP_LSH OP_RSH OP_RET
%token OP_TAX OP_TXA

/* Addressing token */
%token AD_COLON AD_COMMA AD_MEMST AD_BLEFT AD_BRIGHT AD_PLUS AD_BELEFT
%token AD_BERIGHT AD_MUL AD_NSIGN AD_INDEX AD_LEN

%token <number> AD_HEX_NUMBER
%token <number> AD_DEC_NUMBER
%token <label> AD_LABEL

%type <number> program

%%

program: AD_HEX_NUMBER { curr_inst = $1; }
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


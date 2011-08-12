/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

%{

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "bpf_parser.tab.h"
#include "xmalloc.h"

%}

%option align
%option nounput
%option noyywrap
%option noreject
%option 8bit
%option caseless
%option noinput

%%

	/* BPF opcodes */
"ldb"		{ return OP_LDB; }
"ldh"		{ return OP_LDH; }
"ld"		{ return OP_LD; }
"ldx"		{ return OP_LDX; }
"st"		{ return OP_ST; }
"stx"		{ return OP_STX; }
"jmp"		{ return OP_JMP; }
"jeq"		{ return OP_JEQ; }
"jgt"		{ return OP_JGT; }
"jge"		{ return OP_JGE; }
"jset"		{ return OP_JSET; }
"add"		{ return OP_ADD; }
"sub"		{ return OP_SUB; }
"mul"		{ return OP_MUL; }
"div"		{ return OP_DIV; }
"and"		{ return OP_AND; }
"or"		{ return OP_OR; }
"lsh"		{ return OP_LSH; }
"rsh"		{ return OP_RSH; }
"ret"		{ return OP_RET; }
"tax"		{ return OP_TAX; }
"txa"		{ return OP_TXA; }

	/* Content */
":"		{ return AD_COLON; }
","		{ return AD_COMMA; }
"M["		{ return AD_MEMST; }
[^M]"["		{ return AD_BLEFT; }
"]"		{ return AD_BRIGHT; }
"+"		{ return AD_PLUS; }
"4*("		{ return AD_BELEFT; }
"&0xf)"		{ return AD_BERIGHT; }
"*"		{ return AD_MUL; }
"#"		{ return AD_NSIGN; }
"x"		{ return AD_INDEX; }
"len"		{ return AD_LEN; }
"0x"[0-9a-f]+	{ yylval.number = strtoul(yytext, NULL, 16);
		  return AD_HEX_NUMBER; }
[0-9]+		{ yylval.number = strtoul(yytext, NULL, 10);
		  return AD_DEC_NUMBER; }
[A-Z0-9]+	{ yylval.label = xstrdup(yytext);
		  return AD_LABEL; }

	/* Special chars */
";"[^\n]*	/* NOP, Comment */
\n		{ yylineno++; }
[ \t]+		/* NOP */ 

%%

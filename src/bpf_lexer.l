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

digit		[0-9]
digit_s		[1-9]
digit_n		[0]
hex		[a-fA-F0-9]
hex_x		[x]
number_dec	{digit_n}|{digit_s}{digit}*
number_hex	{digit_n}{hex_x}{hex}+
label_s		[a-zA-Z]
label_me	[a-zA-Z0-9_]+
label		{label_s}{label_me}+

%%

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

{number_hex}	{ yylval.number = strtoul(yytext, NULL, 16);
		  return number_hex; }

{number_dec}	{ yylval.number = strtoul(yytext, NULL, 10);
		  return number_dec; }

{label}		{ yylval.label = xstrdup(yytext);
		  return label; }

":"		{ return AD_COLON; }
"+"		{ return AD_PLUS; }
"["		{ return AD_BROP; }
"]"		{ return AD_BRCL; }

";"[^\n]*	{/* NOP */}
"\n"		{ yylineno++; }
[ \t]+		{/* NOP */ }

%%

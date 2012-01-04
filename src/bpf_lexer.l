/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL, version 2.
 */

%{

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "bpf_parser.tab.h"
#include "xmalloc.h"

extern void yyerror(const char *);

%}

%option align
%option nounput
%option noyywrap
%option noreject
%option 8bit
%option caseless
%option noinput
%option nodefault

digit		[0-9]
digit_s		[1-9]
digit_n		[0]
hex		[a-fA-F0-9]
hex_x		[x]
number_dec	{digit_n}|{digit_s}{digit}*
number_hex	{digit_n}{hex_x}{hex}+
label_s		[a-zA-Z]
label_me	[a-zA-Z0-9_]
label		{label_s}{label_me}+

%%

"ldb"		{ return OP_LDB; }
"ldh"		{ return OP_LDH; }
"ld"		{ return OP_LD; }
"ldx"		{ return OP_LDX; }
"ldxb"		{ return OP_LDXB; }
"st"		{ return OP_ST; }
"stx"		{ return OP_STX; }
"jmp"|"ja"	{ return OP_JMP; }
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
"len"|"pktlen"	{ return K_PKT_LEN; }
"proto"		{ return K_PROTO; }
"type"		{ return K_TYPE; }
"ifidx"		{ return K_IFIDX; }
"nla"		{ return K_NLATTR; }
"nlan"		{ return K_NLATTR_NEST; }
"mark"		{ return K_MARK; }
"queue"		{ return K_QUEUE; }
"hatype"	{ return K_HATYPE; }
"rxhash"	{ return K_RXHASH; }
"cpu"		{ return K_CPU; }

":"		{ return ':'; }
","		{ return ','; }
"#"		{ return '#'; }
"["		{ return '['; }
"]"		{ return ']'; }
"("		{ return '('; }
")"		{ return ')'; }
"x"		{ return 'x'; }
"a"		{ return 'a'; }
"+"		{ return '+'; }
"M"		{ return 'M'; }
"*"		{ return '*'; }
"&"		{ return '&'; }
"/*"([^\*]|\*[^/])*"*/" { return K_COMMENT; }

{number_hex}	{ yylval.number = strtoul(yytext, NULL, 16);
		  return number_hex; }

{number_dec}	{ yylval.number = strtol(yytext, NULL, 10);
		  return number_dec; }

{label}		{ yylval.label = xstrdup(yytext);
		  return label; }

";"[^\n]*	{/* NOP */}
"\n"		{ yylineno++; }
[ \t]+		{/* NOP */ }
.		{ printf("Unknown character '%s'", yytext);
		  yyerror("lex Unknown character"); }

%%

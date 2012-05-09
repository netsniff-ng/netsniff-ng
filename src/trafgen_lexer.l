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
#include <string.h>
#include <ctype.h>

#include "trafgen_parser.tab.h"
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
bindigit	[0-1]
bindigit_b	[b]
hex		[a-fA-F0-9]
hex_x		[x]

number_dec	{digit_n}|{digit_s}{digit}*
number_oct	{digit_n}{digit}+
number_hex	{digit_n}{hex_x}{hex}+
number_bin	{digit_n}{bindigit_b}{bindigit}+
number_ascii	[a-zA-Z]

%%

"fill"		{ return K_FILL; }
"rnd"		{ return K_RND; }
"drnd"		{ return K_DRND; }
"dinc"		{ return K_DINC; }
"ddec"		{ return K_DDEC; }
"seqinc"	{ return K_SEQINC; }
"seqdec"	{ return K_SEQDEC; }

"{"		{ return '{'; }
"}"		{ return '}'; }
"("		{ return '('; }
")"		{ return ')'; }
"["		{ return '['; }
"]"		{ return ']'; }
","		{ return ','; }
"\n"		{ yylineno++; return K_NEWL; }
[ \t\r]+	{ return K_WHITE; }

"/*"([^\*]|\*[^/])*"*/" { return K_COMMENT; }

{number_hex}	{ yylval.number = strtoul(yytext, NULL, 16);
		  return number_hex; }

{number_dec}	{ yylval.number = strtol(yytext, NULL, 10);
		  return number_dec; }

{number_oct}	{ yylval.number = strtol(yytext, NULL, 8);
		  return number_oct; }

{number_bin}	{ yylval.number = strtol(yytext + 2, NULL, 2);
		  return number_bin; }

{number_ascii}	{ yylval.number = (uint8_t) (*yytext);
		  return number_ascii; }

"'"."'"		{ yylval.number = (uint8_t) (*(yytext + 1));
		  return number_ascii; }

";"[^\n]*	{/* NOP */}
"#"[^\n]*	{/* NOP */}
.		{ printf("Unknown character '%s'", yytext);
		  yyerror("lex Unknown character"); }

%%

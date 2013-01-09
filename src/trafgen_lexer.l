/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2012 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL, version 2.
 */

/* lex-func-prefix: yy */

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

number_oct	([0][0-9]+)
number_hex	([0][x][a-fA-F0-9]+)
number_bin	([0][b][0-1]+)
number_dec	(([0])|([-+]?[1-9][0-9]*))
number_ascii	([a-zA-Z])

%%

"cpu"		{ return K_CPU; }
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
":"		{ return ':'; }
"\n"		{ yylineno++; }
([ \t\r\n]+)?	{ return K_WHITE; }

"/*"([^\*]|\*[^/])*"*/" { return K_COMMENT; }

{number_hex}	{ yylval.number = strtoul(yytext, NULL, 16);
		  return number; }

{number_dec}	{ yylval.number = strtol(yytext, NULL, 10);
		  return number; }

{number_oct}	{ yylval.number = strtol(yytext + 1, NULL, 8);
		  return number; }

{number_bin}	{ yylval.number = strtol(yytext + 2, NULL, 2);
		  return number; }

{number_ascii}	{ yylval.number = (uint8_t) (*yytext);
		  return number; }

"'"."'"		{ yylval.number = (uint8_t) (*(yytext + 1));
		  return number; }

";"[^\n]*	{/* NOP */}
"#"[^\n]*	{/* NOP */}
.		{ printf("Unknown character '%s'", yytext);
		  yyerror("lex Unknown character"); }

%%

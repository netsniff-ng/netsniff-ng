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

number_oct	([0][0-9]+)
number_hex	([0][x][a-fA-F0-9]+)
number_bin	([0][b][0-1]+)
number_dec	(([0])|([-+]?[1-9][0-9]*))

label		[a-zA-Z_][a-zA-Z0-9_]+

%%

"ldb"		{ return OP_LDB; }
"ldh"		{ return OP_LDH; }
"ld"		{ return OP_LD; }
"ldi"		{ return OP_LDI; }
"ldx"		{ return OP_LDX; }
"ldxi"		{ return OP_LDXI; }
"ldxb"		{ return OP_LDXB; }
"st"		{ return OP_ST; }
"stx"		{ return OP_STX; }
"jmp"|"ja"	{ return OP_JMP; }
"jeq"		{ return OP_JEQ; }
"jneq"|"jne"	{ return OP_JNEQ; }
"jlt"		{ return OP_JLT; }
"jle"		{ return OP_JLE; }
"jgt"		{ return OP_JGT; }
"jge"		{ return OP_JGE; }
"jset"		{ return OP_JSET; }
"add"		{ return OP_ADD; }
"sub"		{ return OP_SUB; }
"mul"		{ return OP_MUL; }
"div"		{ return OP_DIV; }
"mod"		{ return OP_MOD; }
"neg"		{ return OP_NEG; }
"and"		{ return OP_AND; }
"xor"		{ return OP_XOR; }
"or"		{ return OP_OR; }
"lsh"		{ return OP_LSH; }
"rsh"		{ return OP_RSH; }
"ret"		{ return OP_RET; }
"tax"		{ return OP_TAX; }
"txa"		{ return OP_TXA; }

"#"?("len"|"pktlen")	{ return K_PKT_LEN; }
"#"?("pto"|"proto")	{ return K_PROTO; }
"#"?("type")		{ return K_TYPE; }
"#"?("poff")		{ return K_POFF; }
"#"?("ifx"|"ifidx")	{ return K_IFIDX; }
"#"?("nla")		{ return K_NLATTR; }
"#"?("nlan")		{ return K_NLATTR_NEST; }
"#"?("mark")		{ return K_MARK; }
"#"?("que"|"queue"|"Q")	{ return K_QUEUE; }
"#"?("hat"|"hatype")	{ return K_HATYPE; }
"#"?("rxh"|"rxhash")	{ return K_RXHASH; }
"#"?("cpu")		{ return K_CPU; }
"#"?("vlant"|"vlan_tci") { return K_VLANT; }
"#"?("vlana"|"vlan_acc") { return K_VLANP; }
"#"?("vlanp") 		 { return K_VLANP; }

":"		{ return ':'; }
","		{ return ','; }
"#"		{ return '#'; }
"%"		{ return '%'; }
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

{number_hex}	{ yylval.number = strtoul(yytext, NULL, 16);
		  return number; }

{number_oct}	{ yylval.number = strtol(yytext + 1, NULL, 8);
		  return number; }

{number_bin}	{ yylval.number = strtol(yytext + 2, NULL, 2);
		  return number; }

{number_dec}	{ yylval.number = strtol(yytext, NULL, 10);
		  return number; }

{label}		{ yylval.label = xstrdup(yytext);
		  return label; }

"/*"([^\*]|\*[^/])*"*/" { /* NOP */ }
";"[^\n]*	{/* NOP */}
^#.*		{/* NOP */}
"\n"		{ yylineno++; }
[ \t]+		{/* NOP */ }
.		{ printf("Unknown character '%s'", yytext);
		  yyerror("lex Unknown character"); }

%%

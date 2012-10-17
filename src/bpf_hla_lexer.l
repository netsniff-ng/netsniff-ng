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

#include "bpf_hla_parser.tab.h"
#include "bpf_symtab.h"
#include "built_in.h"

void bpf_hla_lex_init(void);

struct res_keywords {
	const char *key;
	int token;
};

#define KEYPAIR(k,t)	{ .key = (k), .token = (t)}
static const struct res_keywords keytab[] = {
	KEYPAIR("def",  K_DEF),
	KEYPAIR("pkt",  K_PKT),
	KEYPAIR("ret",  K_RET),
	KEYPAIR("if",   K_IF),
	KEYPAIR("elif", K_ELIF),
	KEYPAIR("else", K_ELSE),
};

void bpf_hla_lex_init(void)
{
	int i;
	for (i = 0; i < array_size(keytab); ++i)
		bpf_symtab_insert(keytab[i].key, keytab[i].token);
}

#define YY_USER_INIT	bpf_hla_lex_init();

extern void zzerror(const char *);

%}

%option align
%option nounput
%option noyywrap
%option noreject
%option 8bit
%option caseless
%option noinput
%option nodefault

alpha		[A-Za-z]
alphanum	[A-Za-z0-9]

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

%%

{alpha}{alphanum}* {
		zzlval.idx = bpf_symtab_find(zztext);
		if (zzlval.idx < 0) {
			zzlval.idx = bpf_symtab_insert(zztext, K_NAME);
			return K_NAME;
		  } else {
			return bpf_symtab_type(zzlval.idx);
		}}

"("		{ return '('; }
")"		{ return ')'; }
"{"		{ return '{'; }
"}"		{ return '}'; }
"="		{ return '='; }
";"		{ return ';'; }
"+"		{ return '+'; }
"-"		{ return '-'; }
"&"		{ return '&'; }
"|"		{ return '|'; }
"^"		{ return '^'; }
"!"		{ return '!'; }
"<"		{ return '<'; }
">"		{ return '>'; }
"*"		{ return '*'; }
"/"		{ return '/'; }
"%"		{ return '%'; }

{number_hex}	{ zzlval.number = strtoul(zztext, NULL, 16);
		  return number_hex; }

{number_dec}	{ zzlval.number = strtol(zztext, NULL, 10);
		  return number_dec; }

{number_oct}	{ zzlval.number = strtol(zztext, NULL, 8);
		  return number_oct; }

{number_bin}	{ zzlval.number = strtol(zztext + 2, NULL, 2);
		  return number_bin; }

"/*"([^\*]|\*[^/])*"*/" { /* NOP */ }
";"[^\n]*	{/* NOP */}
"\n"		{ zzlineno++; }
[ \t]+		{/* NOP */ }
.		{ printf("Unknown character '%s'", zztext);
		  zzerror("lex Unknown character"); }

%%

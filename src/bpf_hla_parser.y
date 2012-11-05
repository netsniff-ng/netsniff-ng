/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2012 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL, version 2.
 */

/* yaac-func-prefix: zz */

/*
    TODO:
	- intermediate representation
	- code optimization (symbolic reduction?)
	- linearization (jumps, etc)
	- bpf emitter
 */

%{

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>

#include "bpf.h"
#include "bpf_hla_parser.tab.h"
#include "bpf_symtab.h"
#include "xmalloc.h"
#include "xutils.h"
#include "built_in.h"
#include "die.h"

#define YYERROR_VERBOSE		0
#define YYDEBUG			0
#define YYENABLE_NLS		1
#define YYLTYPE_IS_TRIVIAL	1
#define ENABLE_NLS		1

extern FILE *zzin;
extern int zzlex(void);
extern void zzerror(const char *);
extern int zzlineno;
extern char *zztext;

int compile_hla_filter(char *file, int verbose, int debug);

static unsigned int num_vars = 0;
static unsigned int num_ifs = 0;

%}

%union {
	int idx;
	long int number;
}

%token K_NAME K_DEF K_PKT K_RET K_IF K_ELIF K_ELSE
%token K_MACRO_IPV4 K_MACRO_IPV6 K_MACRO_IP K_MACRO_UDP K_MACRO_TCP

%token '(' ')' '{' '}' '=' ';' '+' '-' '&' '|' '^' '!' '<' '>' '*' '/' '%' ','

%token number_hex number_dec number_oct number_bin

%type <idx> K_NAME var
%type <number> number_hex number_dec number_oct number_bin number

%%

program
	: declaration_list { printf("_entry:\n"); } statement_list
	| short_ret /* for short filter statements */
	;

declaration_list
	: declaration { num_vars++; } declaration_list
	| /* empty */
	;

statement_list
	: statement statement_list
	| statement
	;

declaration
	: K_DEF K_NAME ';' { 
		if (bpf_symtab_declared($2)) {
			panic("Variable \"%s\" already declared (l%d)\n",
			      bpf_symtab_name($2), zzlineno);
		} else {
			printf("; @var %s\n", bpf_symtab_name($2));
			bpf_symtab_declare($2); 
		}}
	;

block
	: condition
	;

statement
	: assignment ';'
	| return ';'
	| block
	;

short_ret
	: expression
	;

return
	: K_RET { printf("  ret a\n"); }
	| K_RET number { printf("  ret #%ld\n", $2); }
	| K_RET var { printf("  ret a\n"); }
	| K_RET expression { printf("  ret macro\n"); }
	;

macro
	: K_MACRO_IPV4 { printf("ipv4\n"); }
	| K_MACRO_IPV6 { printf("ipv6\n"); }
	| K_MACRO_IP { printf("ip\n"); }
	| K_MACRO_UDP { printf("udp\n"); }
	| K_MACRO_TCP { printf("tcp\n"); }
	;

condition
	: { num_ifs++; } K_IF '(' expression ')' '{'
		{ printf("jpt_f%u:\n", num_ifs); }
	  statement_list '}' condition_contd
	;

condition_contd
	: K_ELIF '(' expression ')' '{' statement_list '}' condition_contd
	| K_ELSE '{' { printf("jpt_e%u:\n", num_ifs); } statement_list '}'
	| /* None */
	;

assignment
	: var '=' expression { printf("; @asn %s\n", bpf_symtab_name($1)); }
	| var '=' K_PKT '(' number ',' number ')' {
			switch ($7) {
			case 1:
				printf("  ldb [%ld]\n", $5);
				break;
			case 2:
				printf("  ldh [%ld]\n", $5);
				break;
			case 4:
				printf("  ld [%ld]\n", $5);
				break;
			default:
				panic("Invalid argument (l%d)\n", zzlineno);
			}
		}
	;

expression
	: term
	| '!' term { printf("; @!\n"); }
	| term '+' term { printf("; @+\n"); }
	| term '-' term { printf("; @-\n"); }
	| term '/' term { printf("; @/\n"); }
	| term '*' term { printf("; @*\n"); }
	| term '%' term { printf("; @\n"); }
	| term '&' term { printf("; @&\n"); }
	| term '|' term { printf("; @|\n"); }
	| term '^' term { printf("; @^\n"); }
	| term '<' term { printf("; @<\n"); }
	| term '>' term { printf("; @>\n"); }
	| term '=' '=' term { printf("; @==\n"); }
	| term '&' '&' term { printf("; @&&\n"); }
	| term '|' '|' term { printf("; @||\n"); }
	| term '<' '<' term { printf("; @<<\n"); }
	| term '>' '>' term { printf("; @>>\n"); }
	;

term
	: number { printf("; @num %ld\n", $1); }
	| var { printf("; @var %s\n", bpf_symtab_name($1)); }
	| macro
	| '(' expression ')'
	;

var
	: K_NAME {
		if (!bpf_symtab_declared($1))
			panic("Variable \"%s\" not declared (l%d)\n", 
			      bpf_symtab_name($1), zzlineno);
		$$ = $1; }
	;

number
	: number_dec { $$ = $1; }
	| number_hex { $$ = $1; }
	| number_oct { $$ = $1; }
	| number_bin { $$ = $1; }
	;

%%

static void stage_1_compile(void)
{
	zzparse();
}

int compile_hla_filter(char *file, int verbose, int debug)
{
	int fd;
	fpos_t pos;
	char file_tmp[128];

	if (!strncmp("-", file, strlen("-")))
		zzin = stdin;
	else
		zzin = fopen(file, "r");
	if (!zzin)
		panic("Cannot open file!\n");
	if (!debug) {
		fd = dup(fileno(stdout));

		slprintf(file_tmp, sizeof(file_tmp), ".%s", file);
		if (freopen(file_tmp, "w", stdout) == NULL)
			panic("Cannot reopen file!\n");
	}

	stage_1_compile();

	if (!debug) {
		fflush(stdout);
		dup2(fd, fileno(stdout));

		close(fd);
		clearerr(stdout);
		fsetpos(stdout, &pos);
	}

	fclose(zzin);

	bpf_symtab_cleanup();
	if (debug)
		die();

	return 0;
}

void zzerror(const char *err)
{
	panic("Syntax error at line %d: %s! %s!\n",
	      zzlineno, zztext, err);
} 

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

%}

%union {
	int idx;
	long int number;
}

%token K_NAME K_DEF K_PKT K_RET K_IF K_ELIF K_ELSE
%token K_MACRO_IPV4 K_MACRO_IPV6 K_MACRO_IP K_MACRO_UDP K_MACRO_TCP

%token number

%token '(' ')' '{' '}' '=' ';' '+' '-' '&' '|' '^' '!' '<' '>' '*' '/' '%' ','

%type <number> number

%%

program
	: { printf("Not supported yet!\n"); }
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

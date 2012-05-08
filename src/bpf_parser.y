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
#include <stdbool.h>
#include <signal.h>
#include <stdint.h>
#include <errno.h>

#include "bpf.h"
#include "xmalloc.h"
#include "bpf_parser.tab.h"
#include "built_in.h"
#include "die.h"

#define MAX_INSTRUCTIONS	4096

int compile_filter(char *file, int verbose);

static int curr_instr = 0;

static struct sock_filter out[MAX_INSTRUCTIONS];

static char *labels[MAX_INSTRUCTIONS];

static char *labels_jt[MAX_INSTRUCTIONS];
static char *labels_jf[MAX_INSTRUCTIONS];
static char *labels_k[MAX_INSTRUCTIONS];

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

static inline void set_curr_instr(uint16_t code, uint8_t jt, uint8_t jf, uint32_t k)
{
	if (curr_instr >= MAX_INSTRUCTIONS)
		panic("Exceeded maximal number of instructions!\n");

	out[curr_instr].code = code;
	out[curr_instr].jt = jt;
	out[curr_instr].jf = jf;
	out[curr_instr].k = k;

	curr_instr++;
}

static inline void set_curr_label(char *label)
{
	if (curr_instr >= MAX_INSTRUCTIONS)
		panic("Exceeded maximal number of instructions!\n");

	labels[curr_instr] = label;
}

#define JTL 1
#define JFL 2
#define JKL 3

static inline void set_jmp_label(char *label, int which)
{
	if (curr_instr >= MAX_INSTRUCTIONS)
		panic("Exceeded maximal number of instructions!\n");

	bug_on(which != JTL && which != JFL && which != JKL);

	if (which == JTL)
		labels_jt[curr_instr] = label;
	else if (which == JFL)
		labels_jf[curr_instr] = label;
	else
		labels_k[curr_instr] = label;
}

static int find_intr_offset_or_panic(char *label_to_search)
{
	int i, max = curr_instr, ret = -ENOENT;

	bug_on(!label_to_search);

	for (i = 0; i < max; ++i) {
		if (labels[i] != NULL) {
			/* Both are \0-terminated! */
			if (!strcmp(label_to_search, labels[i])) {
				ret = i;
				break;
			}
		}
	}

	if (ret == -ENOENT)
		panic("No such label!\n");

	return ret;
}

%}

%union {
	char *label;
	long int number;
}

%token OP_LDB OP_LDH OP_LD OP_LDX OP_ST OP_STX OP_JMP OP_JEQ OP_JGT OP_JGE
%token OP_JSET OP_ADD OP_SUB OP_MUL OP_DIV OP_AND OP_OR OP_LSH OP_RSH OP_RET
%token OP_TAX OP_TXA OP_LDXB K_PKT_LEN K_PROTO K_TYPE K_IFIDX K_NLATTR
%token K_NLATTR_NEST K_MARK K_QUEUE K_HATYPE K_RXHASH K_CPU K_COMMENT

%token ':' ',' '[' ']' '(' ')' 'x' 'a' '+' 'M' '*' '&' '#'

%token number_hex number_dec label comment

%type <number> number_hex number_dec number
%type <label> label

%%

prog
	: {}
	| prog line { }
	;

line
	: instr { }
	| labeled_instr { }
	;

labeled_instr
	: do_label instr { }
	;

instr
	: do_ldb { }
	| do_ldh { }
	| do_ld { }
	| do_ldx { }
	| do_st { }
	| do_stx { }
	| do_jmp { }
	| do_jeq { }
	| do_jgt { }
	| do_jge { }
	| do_jset { }
	| do_add { }
	| do_sub { }
	| do_mul { }
	| do_div { }
	| do_and { }
	| do_or { }
	| do_lsh { }
	| do_rsh { }
	| do_ret { }
	| do_tax { }
	| do_txa { }
	| do_comment { }
	;

number
	: number_dec { $$ = $1; }
	| number_hex { $$ = $1; }
	;

do_comment
	: K_COMMENT { }
	;

do_label
	: label ':' { set_curr_label($1); }
	;

do_ldb
	: OP_LDB '[' 'x' '+' number ']' {
		set_curr_instr(BPF_LD | BPF_B | BPF_IND, 0, 0, $5); }
	| OP_LDB '[' number ']' {
		set_curr_instr(BPF_LD | BPF_B | BPF_ABS, 0, 0, $3); }
	| OP_LDB '#' K_PROTO {
		set_curr_instr(BPF_LD | BPF_B | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_PROTOCOL); }
	| OP_LDB '#' K_TYPE {
		set_curr_instr(BPF_LD | BPF_B | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_PKTTYPE); }
	| OP_LDB '#' K_IFIDX {
		set_curr_instr(BPF_LD | BPF_B | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_IFINDEX); }
	| OP_LDB '#' K_NLATTR {
		set_curr_instr(BPF_LD | BPF_B | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_NLATTR); }
	| OP_LDB '#' K_NLATTR_NEST {
		set_curr_instr(BPF_LD | BPF_B | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_NLATTR_NEST); }
	| OP_LDB '#' K_MARK {
		set_curr_instr(BPF_LD | BPF_B | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_MARK); }
	| OP_LDB '#' K_QUEUE {
		set_curr_instr(BPF_LD | BPF_B | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_QUEUE); }
	| OP_LDB '#' K_HATYPE {
		set_curr_instr(BPF_LD | BPF_B | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_HATYPE); }
	| OP_LDB '#' K_RXHASH {
		set_curr_instr(BPF_LD | BPF_B | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_RXHASH); }
	| OP_LDB '#' K_CPU {
		set_curr_instr(BPF_LD | BPF_B | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_CPU); }
	;

do_ldh
	: OP_LDH '[' 'x' '+' number ']' {
		set_curr_instr(BPF_LD | BPF_H | BPF_IND, 0, 0, $5); }
	| OP_LDH '[' number ']' {
		set_curr_instr(BPF_LD | BPF_H | BPF_ABS, 0, 0, $3); }
	| OP_LDH '#' K_PROTO {
		set_curr_instr(BPF_LD | BPF_H | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_PROTOCOL); }
	| OP_LDH '#' K_TYPE {
		set_curr_instr(BPF_LD | BPF_H | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_PKTTYPE); }
	| OP_LDH '#' K_IFIDX {
		set_curr_instr(BPF_LD | BPF_H | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_IFINDEX); }
	| OP_LDH '#' K_NLATTR {
		set_curr_instr(BPF_LD | BPF_H | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_NLATTR); }
	| OP_LDH '#' K_NLATTR_NEST {
		set_curr_instr(BPF_LD | BPF_H | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_NLATTR_NEST); }
	| OP_LDH '#' K_MARK {
		set_curr_instr(BPF_LD | BPF_H | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_MARK); }
	| OP_LDH '#' K_QUEUE {
		set_curr_instr(BPF_LD | BPF_H | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_QUEUE); }
	| OP_LDH '#' K_HATYPE {
		set_curr_instr(BPF_LD | BPF_H | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_HATYPE); }
	| OP_LDH '#' K_RXHASH {
		set_curr_instr(BPF_LD | BPF_H | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_RXHASH); }
	| OP_LDH '#' K_CPU {
		set_curr_instr(BPF_LD | BPF_H | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_CPU); }
	;

do_ld
	: OP_LD '#' number {
		set_curr_instr(BPF_LD | BPF_IMM, 0, 0, $3); }
	| OP_LD '#' K_PKT_LEN {
		set_curr_instr(BPF_LD | BPF_W | BPF_LEN, 0, 0, 0); }
	| OP_LD '#' K_PROTO {
		set_curr_instr(BPF_LD | BPF_W | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_PROTOCOL); }
	| OP_LD '#' K_TYPE {
		set_curr_instr(BPF_LD | BPF_W | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_PKTTYPE); }
	| OP_LD '#' K_IFIDX {
		set_curr_instr(BPF_LD | BPF_W | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_IFINDEX); }
	| OP_LD '#' K_NLATTR {
		set_curr_instr(BPF_LD | BPF_W | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_NLATTR); }
	| OP_LD '#' K_NLATTR_NEST {
		set_curr_instr(BPF_LD | BPF_W | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_NLATTR_NEST); }
	| OP_LD '#' K_MARK {
		set_curr_instr(BPF_LD | BPF_W | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_MARK); }
	| OP_LD '#' K_QUEUE {
		set_curr_instr(BPF_LD | BPF_W | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_QUEUE); }
	| OP_LD '#' K_HATYPE {
		set_curr_instr(BPF_LD | BPF_W | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_HATYPE); }
	| OP_LD '#' K_RXHASH {
		set_curr_instr(BPF_LD | BPF_W | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_RXHASH); }
	| OP_LD '#' K_CPU {
		set_curr_instr(BPF_LD | BPF_W | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_CPU); }
	| OP_LD 'M' '[' number ']' {
		set_curr_instr(BPF_LD | BPF_MEM, 0, 0, $4); }
	| OP_LD '[' 'x' '+' number ']' {
		set_curr_instr(BPF_LD | BPF_W | BPF_IND, 0, 0, $5); }
	| OP_LD '[' number ']' {
		set_curr_instr(BPF_LD | BPF_W | BPF_ABS, 0, 0, $3); }
	;

do_ldx
	: OP_LDX '#' number {
		set_curr_instr(BPF_LDX | BPF_IMM, 0, 0, $3); }
	| OP_LDX 'M' '[' number ']' {
		set_curr_instr(BPF_LDX | BPF_MEM, 0, 0, $4); }
	| OP_LDXB number '*' '(' '[' number ']' '&' number ')' {
		if ($2 != 4 || $9 != 0xf) {
			panic("ldxb offset not supported!\n");
		} else {
			set_curr_instr(BPF_LDX | BPF_MSH | BPF_B, 0, 0, $6); } }
	| OP_LDX number '*' '(' '[' number ']' '&' number ')' {
		if ($2 != 4 || $9 != 0xf) {
			panic("ldxb offset not supported!\n");
		} else {
			set_curr_instr(BPF_LDX | BPF_MSH | BPF_B, 0, 0, $6); } }
	;

do_st
	: OP_ST 'M' '[' number ']' {
		set_curr_instr(BPF_ST, 0, 0, $4); }
	;

do_stx
	: OP_STX 'M' '[' number ']' {
		set_curr_instr(BPF_STX, 0, 0, $4); }
	;

do_jmp
	: OP_JMP label {
		set_jmp_label($2, JKL);
		set_curr_instr(BPF_JMP | BPF_JA, 0, 0, 0); }
	;

do_jeq
	: OP_JEQ '#' number ',' label ',' label {
		set_jmp_label($5, JTL);
		set_jmp_label($7, JFL);
		set_curr_instr(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, $3); }
	| OP_JEQ 'x' ',' label ',' label {
		set_jmp_label($4, JTL);
		set_jmp_label($6, JFL);
		set_curr_instr(BPF_JMP | BPF_JEQ | BPF_X, 0, 0, 0); }
	;

do_jgt
	: OP_JGT '#' number ',' label ',' label {
		set_jmp_label($5, JTL);
		set_jmp_label($7, JFL);
		set_curr_instr(BPF_JMP | BPF_JGT | BPF_K, 0, 0, $3); }  
	| OP_JGT 'x' ',' label ',' label {
		set_jmp_label($4, JTL);
		set_jmp_label($6, JFL);
		set_curr_instr(BPF_JMP | BPF_JGT | BPF_X, 0, 0, 0); }
	;

do_jge
	: OP_JGE '#' number ',' label ',' label {
		set_jmp_label($5, JTL);
		set_jmp_label($7, JFL);
		set_curr_instr(BPF_JMP | BPF_JGE | BPF_K, 0, 0, $3); }  
	| OP_JGE 'x' ',' label ',' label {
		set_jmp_label($4, JTL);
		set_jmp_label($6, JFL);
		set_curr_instr(BPF_JMP | BPF_JGE | BPF_X, 0, 0, 0); }
	;

do_jset
	: OP_JSET '#' number ',' label ',' label {
		set_jmp_label($5, JTL);
		set_jmp_label($7, JFL);
		set_curr_instr(BPF_JMP | BPF_JSET | BPF_K, 0, 0, $3); }  
	| OP_JSET 'x' ',' label ',' label {
		set_jmp_label($4, JTL);
		set_jmp_label($6, JFL);
		set_curr_instr(BPF_JMP | BPF_JSET | BPF_X, 0, 0, 0); }
	;

do_add
	: OP_ADD '#' number {
		set_curr_instr(BPF_ALU | BPF_ADD | BPF_K, 0, 0, $3); }
	| OP_ADD 'x' {
		set_curr_instr(BPF_ALU | BPF_ADD | BPF_X, 0, 0, 0); }
	;

do_sub
	: OP_SUB '#' number {
		set_curr_instr(BPF_ALU | BPF_SUB | BPF_K, 0, 0, $3); }
	| OP_SUB 'x' {
		set_curr_instr(BPF_ALU | BPF_SUB | BPF_X, 0, 0, 0); }
	;

do_mul
	: OP_MUL '#' number {
		set_curr_instr(BPF_ALU | BPF_MUL | BPF_K, 0, 0, $3); }
	| OP_MUL 'x' {
		set_curr_instr(BPF_ALU | BPF_MUL | BPF_X, 0, 0, 0); }
	;

do_div
	: OP_DIV '#' number {
		set_curr_instr(BPF_ALU | BPF_DIV | BPF_K, 0, 0, $3); }
	| OP_DIV 'x' {
		set_curr_instr(BPF_ALU | BPF_DIV | BPF_X, 0, 0, 0); }
	;

do_and
	: OP_AND '#' number {
		set_curr_instr(BPF_ALU | BPF_AND | BPF_K, 0, 0, $3); }
	| OP_AND 'x' {
		set_curr_instr(BPF_ALU | BPF_AND | BPF_X, 0, 0, 0); }
	;

do_or
	: OP_OR '#' number {
		set_curr_instr(BPF_ALU | BPF_OR | BPF_K, 0, 0, $3); }
	| OP_OR 'x' {
		set_curr_instr(BPF_ALU | BPF_OR | BPF_X, 0, 0, 0); }
	;

do_lsh
	: OP_LSH '#' number {
		set_curr_instr(BPF_ALU | BPF_LSH | BPF_K, 0, 0, $3); }
	| OP_LSH 'x' {
		set_curr_instr(BPF_ALU | BPF_LSH | BPF_X, 0, 0, 0); }
	;

do_rsh
	: OP_RSH '#' number {
		set_curr_instr(BPF_ALU | BPF_RSH | BPF_K, 0, 0, $3); }
	| OP_RSH 'x' {
		set_curr_instr(BPF_ALU | BPF_RSH | BPF_X, 0, 0, 0); }
	;

do_ret
	: OP_RET 'a' {
		set_curr_instr(BPF_RET | BPF_A, 0, 0, 0); }
	| OP_RET '#' number {
		set_curr_instr(BPF_RET | BPF_K, 0, 0, $3); }
	;

do_tax
	: OP_TAX {
		set_curr_instr(BPF_MISC | BPF_TAX, 0, 0, 0); }
	;

do_txa
	: OP_TXA {
		set_curr_instr(BPF_MISC | BPF_TXA, 0, 0, 0); }
	;

%%

static void stage_1_inline(void)
{
	yyparse();
}

static void stage_2_label_reduce(void)
{
	int i, max = curr_instr, off;

	/* 1. reduce k jumps */
	for (i = 0; i < max; ++i) {
		if (labels_k[i] != NULL) {
			off = find_intr_offset_or_panic(labels_k[i]);
			out[i].k = (uint32_t) (off - i - 1);
		}
	}

	/* 1. reduce jt jumps */
	for (i = 0; i < max; ++i) {
		if (labels_jt[i] != NULL) {
			off = find_intr_offset_or_panic(labels_jt[i]);
			out[i].jt = (uint8_t) (off - i -1);
		}
	}

	/* 1. reduce jf jumps */
	for (i = 0; i < max; ++i) {
		if (labels_jf[i] != NULL) {
			off = find_intr_offset_or_panic(labels_jf[i]);
			out[i].jf = (uint8_t) (off - i - 1);
		}
	}
}

int compile_filter(char *file, int verbose)
{
	int i;
	struct sock_fprog res;

	yyin = fopen(file, "r");
	if (!yyin)
		panic("Cannot open file!\n");

	memset(out, 0, sizeof(out));
	memset(labels, 0, sizeof(labels));
	memset(labels_jf, 0, sizeof(labels_jf));
	memset(labels_jt, 0, sizeof(labels_jt));
	memset(labels_k, 0, sizeof(labels_k));

	stage_1_inline();
	stage_2_label_reduce();

	res.filter = out;
	res.len = curr_instr;

	if (verbose) {
		printf("Generated program:\n");
		bpf_dump_all(&res);
	}
	if (verbose) {
		printf("Validating: ");
		fflush(stdout);
	}
	if (bpf_validate(&res) == 0) {
		if (verbose)
			whine("semantic error! BPF validation failed!\n");
		else
			panic("Semantic error! BPF validation failed! "
			      "Try -V for debugging output!\n");
	} else if (verbose)
		printf("is runnable!\n");
	if (verbose)
		printf("Result:\n");
	for (i = 0; i < res.len; ++i) {
		printf("{ 0x%x, %u, %u, 0x%08x },\n",
		       res.filter[i].code, res.filter[i].jt,
		       res.filter[i].jf, res.filter[i].k);
		if (labels[i] != NULL)
			xfree(labels[i]);
		if (labels_jt[i] != NULL)
			xfree(labels_jt[i]);
		if (labels_jf[i] != NULL)
			xfree(labels_jf[i]);
		if (labels_k[i] != NULL)
			xfree(labels_k[i]);
	}

	fclose(yyin);
	return 0;
}

void yyerror(const char *err)
{
	panic("Syntax error at line %d: %s! %s!\n",
	      yylineno, yytext, err);
}

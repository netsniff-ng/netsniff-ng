/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL, version 2.
 */

/* yaac-func-prefix: yy */

%{

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <stdint.h>
#include <errno.h>
#include <libgen.h>
#include <linux/filter.h>

#include "bpf.h"
#include "str.h"
#include "xmalloc.h"
#include "bpf_parser.tab.h"
#include "built_in.h"
#include "die.h"

int compile_filter(char *file, int verbose, int bypass, int format,
		   bool invoke_cpp);

static int curr_instr = 0;

static struct sock_filter out[BPF_MAXINSNS];

static char *labels[BPF_MAXINSNS];
static char *labels_jt[BPF_MAXINSNS];
static char *labels_jf[BPF_MAXINSNS];
static char *labels_k[BPF_MAXINSNS];

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

static inline void check_max_instr(void)
{
	if (curr_instr >= BPF_MAXINSNS)
		panic("Exceeded maximal number of instructions!\n");
}

static inline void set_curr_instr(uint16_t code, uint8_t jt, uint8_t jf, uint32_t k)
{
	check_max_instr();

	out[curr_instr].code = code;
	out[curr_instr].jt = jt;
	out[curr_instr].jf = jf;
	out[curr_instr].k = k;

	curr_instr++;
}

static inline void set_curr_label(char *label)
{
	check_max_instr();

	labels[curr_instr] = label;
}

#define JTL		1
#define JFL		2
#define JKL		3

static inline void set_jmp_label(char *label, int which)
{
	check_max_instr();

	switch (which) {
	case JTL:
		labels_jt[curr_instr] = label;
		break;
	case JFL:
		labels_jf[curr_instr] = label;
		break;
	case JKL:
		labels_k[curr_instr] = label;
		break;
	default:
		bug();
	}
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
%token OP_JSET OP_ADD OP_SUB OP_MUL OP_DIV OP_AND OP_OR OP_XOR OP_LSH OP_RSH
%token OP_RET OP_TAX OP_TXA OP_LDXB OP_MOD OP_NEG OP_JNEQ OP_JLT OP_JLE OP_LDI
%token OP_LDXI

%token K_PKT_LEN K_PROTO K_TYPE K_NLATTR K_NLATTR_NEST K_MARK K_QUEUE K_HATYPE
%token K_RXHASH K_CPU K_IFIDX K_VLANT K_VLANP K_POFF

%token ':' ',' '[' ']' '(' ')' 'x' 'a' '+' 'M' '*' '&' '#' '%'

%token number label

%type <number> number
%type <label> label

%%

prog
	: line
	| prog line
	;

line
	: instr
	| labelled_instr
	;

labelled_instr
	: labelled instr
	;

instr
	: ldb
	| ldh
	| ld
	| ldi
	| ldx
	| ldxi
	| st
	| stx
	| jmp
	| jeq
	| jneq
	| jlt
	| jle
	| jgt
	| jge
	| jset
	| add
	| sub
	| mul
	| div
	| mod
	| neg
	| and
	| or
	| xor
	| lsh
	| rsh
	| ret
	| tax
	| txa
	;

labelled
	: label ':' { set_curr_label($1); }
	;

ldb
	: OP_LDB '[' 'x' '+' number ']' {
		set_curr_instr(BPF_LD | BPF_B | BPF_IND, 0, 0, $5); }
	| OP_LDB '[' '%' 'x' '+' number ']' {
		set_curr_instr(BPF_LD | BPF_B | BPF_IND, 0, 0, $6); }
	| OP_LDB '[' number ']' {
		set_curr_instr(BPF_LD | BPF_B | BPF_ABS, 0, 0, $3); }
	| OP_LDB K_PROTO {
		set_curr_instr(BPF_LD | BPF_B | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_PROTOCOL); }
	| OP_LDB K_TYPE {
		set_curr_instr(BPF_LD | BPF_B | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_PKTTYPE); }
	| OP_LDB K_IFIDX {
		set_curr_instr(BPF_LD | BPF_B | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_IFINDEX); }
	| OP_LDB K_NLATTR {
		set_curr_instr(BPF_LD | BPF_B | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_NLATTR); }
	| OP_LDB K_NLATTR_NEST {
		set_curr_instr(BPF_LD | BPF_B | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_NLATTR_NEST); }
	| OP_LDB K_MARK {
		set_curr_instr(BPF_LD | BPF_B | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_MARK); }
	| OP_LDB K_QUEUE {
		set_curr_instr(BPF_LD | BPF_B | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_QUEUE); }
	| OP_LDB K_HATYPE {
		set_curr_instr(BPF_LD | BPF_B | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_HATYPE); }
	| OP_LDB K_RXHASH {
		set_curr_instr(BPF_LD | BPF_B | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_RXHASH); }
	| OP_LDB K_CPU {
		set_curr_instr(BPF_LD | BPF_B | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_CPU); }
	| OP_LDB K_VLANT {
		set_curr_instr(BPF_LD | BPF_B | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_VLAN_TAG); }
	| OP_LDB K_VLANP {
		set_curr_instr(BPF_LD | BPF_B | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT); }
	| OP_LDB K_POFF {
		set_curr_instr(BPF_LD | BPF_B | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_PAY_OFFSET); }
	;

ldh
	: OP_LDH '[' 'x' '+' number ']' {
		set_curr_instr(BPF_LD | BPF_H | BPF_IND, 0, 0, $5); }
	| OP_LDH '[' '%' 'x' '+' number ']' {
		set_curr_instr(BPF_LD | BPF_H | BPF_IND, 0, 0, $6); }
	| OP_LDH '[' number ']' {
		set_curr_instr(BPF_LD | BPF_H | BPF_ABS, 0, 0, $3); }
	| OP_LDH K_PROTO {
		set_curr_instr(BPF_LD | BPF_H | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_PROTOCOL); }
	| OP_LDH K_TYPE {
		set_curr_instr(BPF_LD | BPF_H | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_PKTTYPE); }
	| OP_LDH K_IFIDX {
		set_curr_instr(BPF_LD | BPF_H | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_IFINDEX); }
	| OP_LDH K_NLATTR {
		set_curr_instr(BPF_LD | BPF_H | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_NLATTR); }
	| OP_LDH K_NLATTR_NEST {
		set_curr_instr(BPF_LD | BPF_H | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_NLATTR_NEST); }
	| OP_LDH K_MARK {
		set_curr_instr(BPF_LD | BPF_H | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_MARK); }
	| OP_LDH K_QUEUE {
		set_curr_instr(BPF_LD | BPF_H | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_QUEUE); }
	| OP_LDH K_HATYPE {
		set_curr_instr(BPF_LD | BPF_H | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_HATYPE); }
	| OP_LDH K_RXHASH {
		set_curr_instr(BPF_LD | BPF_H | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_RXHASH); }
	| OP_LDH K_CPU {
		set_curr_instr(BPF_LD | BPF_H | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_CPU); }
	| OP_LDH K_VLANT {
		set_curr_instr(BPF_LD | BPF_H | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_VLAN_TAG); }
	| OP_LDH K_VLANP {
		set_curr_instr(BPF_LD | BPF_H | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT); }
	| OP_LDH K_POFF {
		set_curr_instr(BPF_LD | BPF_H | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_PAY_OFFSET); }
	;

ldi
	: OP_LDI '#' number {
		set_curr_instr(BPF_LD | BPF_IMM, 0, 0, $3); }
	| OP_LDI number {
		set_curr_instr(BPF_LD | BPF_IMM, 0, 0, $2); }
	;

ld
	: OP_LD '#' number {
		set_curr_instr(BPF_LD | BPF_IMM, 0, 0, $3); }
	| OP_LD K_PKT_LEN {
		set_curr_instr(BPF_LD | BPF_W | BPF_LEN, 0, 0, 0); }
	| OP_LD K_PROTO {
		set_curr_instr(BPF_LD | BPF_W | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_PROTOCOL); }
	| OP_LD K_TYPE {
		set_curr_instr(BPF_LD | BPF_W | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_PKTTYPE); }
	| OP_LD K_IFIDX {
		set_curr_instr(BPF_LD | BPF_W | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_IFINDEX); }
	| OP_LD K_NLATTR {
		set_curr_instr(BPF_LD | BPF_W | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_NLATTR); }
	| OP_LD K_NLATTR_NEST {
		set_curr_instr(BPF_LD | BPF_W | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_NLATTR_NEST); }
	| OP_LD K_MARK {
		set_curr_instr(BPF_LD | BPF_W | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_MARK); }
	| OP_LD K_QUEUE {
		set_curr_instr(BPF_LD | BPF_W | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_QUEUE); }
	| OP_LD K_HATYPE {
		set_curr_instr(BPF_LD | BPF_W | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_HATYPE); }
	| OP_LD K_RXHASH {
		set_curr_instr(BPF_LD | BPF_W | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_RXHASH); }
	| OP_LD K_CPU {
		set_curr_instr(BPF_LD | BPF_W | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_CPU); }
	| OP_LD K_VLANT {
		set_curr_instr(BPF_LD | BPF_W | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_VLAN_TAG); }
	| OP_LD K_VLANP {
		set_curr_instr(BPF_LD | BPF_W | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT); }
	| OP_LD K_POFF {
		set_curr_instr(BPF_LD | BPF_W | BPF_ABS, 0, 0,
			       SKF_AD_OFF + SKF_AD_PAY_OFFSET); }
	| OP_LD 'M' '[' number ']' {
		set_curr_instr(BPF_LD | BPF_MEM, 0, 0, $4); }
	| OP_LD '[' 'x' '+' number ']' {
		set_curr_instr(BPF_LD | BPF_W | BPF_IND, 0, 0, $5); }
	| OP_LD '[' '%' 'x' '+' number ']' {
		set_curr_instr(BPF_LD | BPF_W | BPF_IND, 0, 0, $6); }
	| OP_LD '[' number ']' {
		set_curr_instr(BPF_LD | BPF_W | BPF_ABS, 0, 0, $3); }
	;

ldxi
	: OP_LDXI '#' number {
		set_curr_instr(BPF_LDX | BPF_IMM, 0, 0, $3); }
	| OP_LDXI number {
		set_curr_instr(BPF_LDX | BPF_IMM, 0, 0, $2); }
	;

ldx
	: OP_LDX '#' number {
		set_curr_instr(BPF_LDX | BPF_IMM, 0, 0, $3); }
	| OP_LDX K_PKT_LEN {
		set_curr_instr(BPF_LDX | BPF_W | BPF_LEN, 0, 0, 0); }
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

st
	: OP_ST 'M' '[' number ']' {
		set_curr_instr(BPF_ST, 0, 0, $4); }
	;

stx
	: OP_STX 'M' '[' number ']' {
		set_curr_instr(BPF_STX, 0, 0, $4); }
	;

jmp
	: OP_JMP label {
		set_jmp_label($2, JKL);
		set_curr_instr(BPF_JMP | BPF_JA, 0, 0, 0); }
	;

jeq
	: OP_JEQ '#' number ',' label ',' label {
		set_jmp_label($5, JTL);
		set_jmp_label($7, JFL);
		set_curr_instr(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, $3); }
	| OP_JEQ 'x' ',' label ',' label {
		set_jmp_label($4, JTL);
		set_jmp_label($6, JFL);
		set_curr_instr(BPF_JMP | BPF_JEQ | BPF_X, 0, 0, 0); }
	| OP_JEQ '%' 'x' ',' label ',' label {
		set_jmp_label($5, JTL);
		set_jmp_label($7, JFL);
		set_curr_instr(BPF_JMP | BPF_JEQ | BPF_X, 0, 0, 0); }
	| OP_JEQ '#' number ',' label {
		set_jmp_label($5, JTL);
		set_curr_instr(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, $3); }
	| OP_JEQ 'x' ',' label {
		set_jmp_label($4, JTL);
		set_curr_instr(BPF_JMP | BPF_JEQ | BPF_X, 0, 0, 0); }
	| OP_JEQ '%' 'x' ',' label {
		set_jmp_label($5, JTL);
		set_curr_instr(BPF_JMP | BPF_JEQ | BPF_X, 0, 0, 0); }
	;

jneq
	: OP_JNEQ '#' number ',' label {
		set_jmp_label($5, JFL);
		set_curr_instr(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, $3); }
	| OP_JNEQ 'x' ',' label {
		set_jmp_label($4, JFL);
		set_curr_instr(BPF_JMP | BPF_JEQ | BPF_X, 0, 0, 0); }
	| OP_JNEQ '%' 'x' ',' label {
		set_jmp_label($5, JFL);
		set_curr_instr(BPF_JMP | BPF_JEQ | BPF_X, 0, 0, 0); }
	;

jlt
	: OP_JLT '#' number ',' label {
		set_jmp_label($5, JFL);
		set_curr_instr(BPF_JMP | BPF_JGE | BPF_K, 0, 0, $3); }  
	| OP_JLT 'x' ',' label {
		set_jmp_label($4, JFL);
		set_curr_instr(BPF_JMP | BPF_JGE | BPF_X, 0, 0, 0); }
	| OP_JLT '%' 'x' ',' label {
		set_jmp_label($5, JFL);
		set_curr_instr(BPF_JMP | BPF_JGE | BPF_X, 0, 0, 0); }
	;

jle
	: OP_JLE '#' number ',' label {
		set_jmp_label($5, JFL);
		set_curr_instr(BPF_JMP | BPF_JGT | BPF_K, 0, 0, $3); }  
	| OP_JLE 'x' ',' label {
		set_jmp_label($4, JFL);
		set_curr_instr(BPF_JMP | BPF_JGT | BPF_X, 0, 0, 0); }
	| OP_JLE '%' 'x' ',' label {
		set_jmp_label($5, JFL);
		set_curr_instr(BPF_JMP | BPF_JGT | BPF_X, 0, 0, 0); }
	;

jgt
	: OP_JGT '#' number ',' label ',' label {
		set_jmp_label($5, JTL);
		set_jmp_label($7, JFL);
		set_curr_instr(BPF_JMP | BPF_JGT | BPF_K, 0, 0, $3); }  
	| OP_JGT 'x' ',' label ',' label {
		set_jmp_label($4, JTL);
		set_jmp_label($6, JFL);
		set_curr_instr(BPF_JMP | BPF_JGT | BPF_X, 0, 0, 0); }
	| OP_JGT '%' 'x' ',' label ',' label {
		set_jmp_label($5, JTL);
		set_jmp_label($7, JFL);
		set_curr_instr(BPF_JMP | BPF_JGT | BPF_X, 0, 0, 0); }
	| OP_JGT '#' number ',' label {
		set_jmp_label($5, JTL);
		set_curr_instr(BPF_JMP | BPF_JGT | BPF_K, 0, 0, $3); }  
	| OP_JGT 'x' ',' label {
		set_jmp_label($4, JTL);
		set_curr_instr(BPF_JMP | BPF_JGT | BPF_X, 0, 0, 0); }
	| OP_JGT '%' 'x' ',' label {
		set_jmp_label($5, JTL);
		set_curr_instr(BPF_JMP | BPF_JGT | BPF_X, 0, 0, 0); }
	;

jge
	: OP_JGE '#' number ',' label ',' label {
		set_jmp_label($5, JTL);
		set_jmp_label($7, JFL);
		set_curr_instr(BPF_JMP | BPF_JGE | BPF_K, 0, 0, $3); }
	| OP_JGE 'x' ',' label ',' label {
		set_jmp_label($4, JTL);
		set_jmp_label($6, JFL);
		set_curr_instr(BPF_JMP | BPF_JGE | BPF_X, 0, 0, 0); }
	| OP_JGE '%' 'x' ',' label ',' label {
		set_jmp_label($5, JTL);
		set_jmp_label($7, JFL);
		set_curr_instr(BPF_JMP | BPF_JGE | BPF_X, 0, 0, 0); }
	| OP_JGE '#' number ',' label {
		set_jmp_label($5, JTL);
		set_curr_instr(BPF_JMP | BPF_JGE | BPF_K, 0, 0, $3); }
	| OP_JGE 'x' ',' label {
		set_jmp_label($4, JTL);
		set_curr_instr(BPF_JMP | BPF_JGE | BPF_X, 0, 0, 0); }
	| OP_JGE '%' 'x' ',' label {
		set_jmp_label($5, JTL);
		set_curr_instr(BPF_JMP | BPF_JGE | BPF_X, 0, 0, 0); }
	;

jset
	: OP_JSET '#' number ',' label ',' label {
		set_jmp_label($5, JTL);
		set_jmp_label($7, JFL);
		set_curr_instr(BPF_JMP | BPF_JSET | BPF_K, 0, 0, $3); }
	| OP_JSET 'x' ',' label ',' label {
		set_jmp_label($4, JTL);
		set_jmp_label($6, JFL);
		set_curr_instr(BPF_JMP | BPF_JSET | BPF_X, 0, 0, 0); }
	| OP_JSET '%' 'x' ',' label ',' label {
		set_jmp_label($5, JTL);
		set_jmp_label($7, JFL);
		set_curr_instr(BPF_JMP | BPF_JSET | BPF_X, 0, 0, 0); }
	| OP_JSET '#' number ',' label {
		set_jmp_label($5, JTL);
		set_curr_instr(BPF_JMP | BPF_JSET | BPF_K, 0, 0, $3); }
	| OP_JSET 'x' ',' label {
		set_jmp_label($4, JTL);
		set_curr_instr(BPF_JMP | BPF_JSET | BPF_X, 0, 0, 0); }
	| OP_JSET '%' 'x' ',' label {
		set_jmp_label($5, JTL);
		set_curr_instr(BPF_JMP | BPF_JSET | BPF_X, 0, 0, 0); }
	;

add
	: OP_ADD '#' number {
		set_curr_instr(BPF_ALU | BPF_ADD | BPF_K, 0, 0, $3); }
	| OP_ADD 'x' {
		set_curr_instr(BPF_ALU | BPF_ADD | BPF_X, 0, 0, 0); }
	| OP_ADD '%' 'x' {
		set_curr_instr(BPF_ALU | BPF_ADD | BPF_X, 0, 0, 0); }
	;

sub
	: OP_SUB '#' number {
		set_curr_instr(BPF_ALU | BPF_SUB | BPF_K, 0, 0, $3); }
	| OP_SUB 'x' {
		set_curr_instr(BPF_ALU | BPF_SUB | BPF_X, 0, 0, 0); }
	| OP_SUB '%' 'x' {
		set_curr_instr(BPF_ALU | BPF_SUB | BPF_X, 0, 0, 0); }
	;

mul
	: OP_MUL '#' number {
		set_curr_instr(BPF_ALU | BPF_MUL | BPF_K, 0, 0, $3); }
	| OP_MUL 'x' {
		set_curr_instr(BPF_ALU | BPF_MUL | BPF_X, 0, 0, 0); }
	| OP_MUL '%' 'x' {
		set_curr_instr(BPF_ALU | BPF_MUL | BPF_X, 0, 0, 0); }
	;

div
	: OP_DIV '#' number {
		set_curr_instr(BPF_ALU | BPF_DIV | BPF_K, 0, 0, $3); }
	| OP_DIV 'x' {
		set_curr_instr(BPF_ALU | BPF_DIV | BPF_X, 0, 0, 0); }
	| OP_DIV '%' 'x' {
		set_curr_instr(BPF_ALU | BPF_DIV | BPF_X, 0, 0, 0); }
	;

mod
	: OP_MOD '#' number {
		set_curr_instr(BPF_ALU | BPF_MOD | BPF_K, 0, 0, $3); }
	| OP_MOD 'x' {
		set_curr_instr(BPF_ALU | BPF_MOD | BPF_X, 0, 0, 0); }
	| OP_MOD '%' 'x' {
		set_curr_instr(BPF_ALU | BPF_MOD | BPF_X, 0, 0, 0); }
	;

neg
	: OP_NEG {
		set_curr_instr(BPF_ALU | BPF_NEG, 0, 0, 0); }
	;

and
	: OP_AND '#' number {
		set_curr_instr(BPF_ALU | BPF_AND | BPF_K, 0, 0, $3); }
	| OP_AND 'x' {
		set_curr_instr(BPF_ALU | BPF_AND | BPF_X, 0, 0, 0); }
	| OP_AND '%' 'x' {
		set_curr_instr(BPF_ALU | BPF_AND | BPF_X, 0, 0, 0); }
	;

or
	: OP_OR '#' number {
		set_curr_instr(BPF_ALU | BPF_OR | BPF_K, 0, 0, $3); }
	| OP_OR 'x' {
		set_curr_instr(BPF_ALU | BPF_OR | BPF_X, 0, 0, 0); }
	| OP_OR '%' 'x' {
		set_curr_instr(BPF_ALU | BPF_OR | BPF_X, 0, 0, 0); }
	;

xor
	: OP_XOR '#' number {
		set_curr_instr(BPF_ALU | BPF_XOR | BPF_K, 0, 0, $3); }
	| OP_XOR 'x' {
		set_curr_instr(BPF_ALU | BPF_XOR | BPF_X, 0, 0, 0); }
	| OP_XOR '%' 'x' {
		set_curr_instr(BPF_ALU | BPF_XOR | BPF_X, 0, 0, 0); }
	;

lsh
	: OP_LSH '#' number {
		set_curr_instr(BPF_ALU | BPF_LSH | BPF_K, 0, 0, $3); }
	| OP_LSH 'x' {
		set_curr_instr(BPF_ALU | BPF_LSH | BPF_X, 0, 0, 0); }
	| OP_LSH '%' 'x' {
		set_curr_instr(BPF_ALU | BPF_LSH | BPF_X, 0, 0, 0); }
	;

rsh
	: OP_RSH '#' number {
		set_curr_instr(BPF_ALU | BPF_RSH | BPF_K, 0, 0, $3); }
	| OP_RSH 'x' {
		set_curr_instr(BPF_ALU | BPF_RSH | BPF_X, 0, 0, 0); }
	| OP_RSH '%' 'x' {
		set_curr_instr(BPF_ALU | BPF_RSH | BPF_X, 0, 0, 0); }
	;

ret
	: OP_RET 'a' {
		set_curr_instr(BPF_RET | BPF_A, 0, 0, 0); }
	| OP_RET '%' 'a' {
		set_curr_instr(BPF_RET | BPF_A, 0, 0, 0); }
	| OP_RET 'x' {
		set_curr_instr(BPF_RET | BPF_X, 0, 0, 0); }
	| OP_RET '%' 'x' {
		set_curr_instr(BPF_RET | BPF_X, 0, 0, 0); }
	| OP_RET '#' number {
		set_curr_instr(BPF_RET | BPF_K, 0, 0, $3); }
	;

tax
	: OP_TAX {
		set_curr_instr(BPF_MISC | BPF_TAX, 0, 0, 0); }
	;

txa
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

static void pretty_printer_c(const struct sock_fprog *prog)
{
	int i;

	for (i = 0; i < prog->len; ++i) {
		printf("{ 0x%x, %u, %u, 0x%08x },\n",
		       prog->filter[i].code, prog->filter[i].jt,
		       prog->filter[i].jf, prog->filter[i].k);
	}
}

static void pretty_printer_xt_bpf(const struct sock_fprog *prog)
{
	int i;

	printf("%d,", prog->len);
	for (i = 0; i < prog->len; ++i) {
		printf("%u %u %u %u,",
		       prog->filter[i].code, prog->filter[i].jt,
		       prog->filter[i].jf, prog->filter[i].k);
	}

	fflush(stdout);
}

static void pretty_printer_tcpdump(const struct sock_fprog *prog)
{
	int i;

	for (i = 0; i < prog->len; ++i) {
		printf("%u %u %u %u\n",
		       prog->filter[i].code, prog->filter[i].jt,
		       prog->filter[i].jf, prog->filter[i].k);
	}
}

static void pretty_printer(const struct sock_fprog *prog, int format)
{
	switch (format) {
	case 0:
		pretty_printer_c(prog);
		break;
	case 1:
		pretty_printer_xt_bpf(prog);
		break;
	case 2:
		pretty_printer_tcpdump(prog);
		break;
	default:
		bug();
	}
}

int compile_filter(char *file, int verbose, int bypass, int format,
		   bool invoke_cpp)
{
	int i;
	struct sock_fprog res;
	char tmp_file[128];

	memset(tmp_file, 0, sizeof(tmp_file));

	if (invoke_cpp) {
		char cmd[256], *dir, *base, *a, *b;

		dir = dirname((a = xstrdup(file)));
		base = basename((b = xstrdup(file)));

		slprintf(tmp_file, sizeof(tmp_file), "%s/.tmp-%u-%s", dir, rand(), base);
		slprintf(cmd, sizeof(cmd), "cpp -I" ETCDIRE_STRING " %s > %s",
			 file, tmp_file);
		if (system(cmd) != 0)
			panic("Failed to invoke C preprocessor!\n");

		file = tmp_file;
		xfree(a);
		xfree(b);
	}

	if (!strncmp("-", file, strlen("-")))
		yyin = stdin;
	else
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

	if (!bypass) {
		if (verbose) {
			printf("Validating: ");
			fflush(stdout);
		}

		if (__bpf_validate(&res) == 0) {
			if (verbose)
				printf("Semantic error! BPF validation failed!\n");
			else
				panic("Semantic error! BPF validation failed! "
				      "Try -V for debugging output!\n");
		} else if (verbose) {
			printf("is runnable!\n");
		}
	}

	if (verbose)
		printf("Result:\n");

	pretty_printer(&res, format);

	for (i = 0; i < res.len; ++i) {
		free(labels[i]);
		free(labels_jt[i]);
		free(labels_jf[i]);
		free(labels_k[i]);
	}

	fclose(yyin);
	if (invoke_cpp)
		unlink(tmp_file);

	return 0;
}

void yyerror(const char *err)
{
	panic("Syntax error at line %d: %s! %s!\n",
	      yylineno, yytext, err);
}

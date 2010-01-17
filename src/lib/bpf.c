/* XXX: Coding Style - use the tool indent with the following (Linux kernel
 *                     code indents)
 *
 * indent -nbad -bap -nbc -bbo -hnl -br -brs -c33 -cd33 -ncdb -ce -ci4   \
 *        -cli0 -d0 -di1 -nfc1 -i8 -ip0 -l120 -lp -npcs -nprs -npsl -sai \
 *        -saf -saw -ncs -nsc -sob -nfca -cp33 -ss -ts8 -il1
 *
 *
 * netsniff-ng
 *
 * High performance network sniffer for packet inspection
 *
 * Copyright (C) 2009, 2010  Daniel Borkmann <danborkmann@googlemail.com>
 *
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation; either version 2 of the License, or (at 
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License 
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
 *
 * Note: Your kernel has to be compiled with CONFIG_PACKET_MMAP=y option in 
 *       order to use this.
 */

/*
 * Copyright (c) 1990, 1991, 1992, 1994, 1995, 1996
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/*
 * The instruction encodings.
 */
/* instruction classes */
#define BPF_CLASS(code) ((code) & 0x07)
#define		BPF_LD		0x00
#define		BPF_LDX		0x01
#define		BPF_ST		0x02
#define		BPF_STX		0x03
#define		BPF_ALU		0x04
#define		BPF_JMP		0x05
#define		BPF_RET		0x06
#define		BPF_MISC	0x07

/* ld/ldx fields */
#define BPF_SIZE(code)	((code) & 0x18)
#define		BPF_W		0x00
#define		BPF_H		0x08
#define		BPF_B		0x10
#define BPF_MODE(code)	((code) & 0xe0)
#define		BPF_IMM 	0x00
#define		BPF_ABS		0x20
#define		BPF_IND		0x40
#define		BPF_MEM		0x60
#define		BPF_LEN		0x80
#define		BPF_MSH		0xa0

/* alu/jmp fields */
#define BPF_OP(code)	((code) & 0xf0)
#define		BPF_ADD		0x00
#define		BPF_SUB		0x10
#define		BPF_MUL		0x20
#define		BPF_DIV		0x30
#define		BPF_OR		0x40
#define		BPF_AND		0x50
#define		BPF_LSH		0x60
#define		BPF_RSH		0x70
#define		BPF_NEG		0x80
#define		BPF_JA		0x00
#define		BPF_JEQ		0x10
#define		BPF_JGT		0x20
#define		BPF_JGE		0x30
#define		BPF_JSET	0x40
#define BPF_SRC(code)	((code) & 0x08)
#define		BPF_K		0x00
#define		BPF_X		0x08

/* ret - BPF_K and BPF_X also apply */
#define BPF_RVAL(code)	((code) & 0x18)
#define		BPF_A		0x10

/* misc */
#define BPF_MISCOP(code) ((code) & 0xf8)
#define		BPF_TAX		0x00
#define		BPF_TXA		0x80

#include <stdio.h>
#include <assert.h>

#include <linux/filter.h>

#include <netsniff-ng/bpf.h>
#include <netsniff-ng/macros.h>

/**
 * bpf_dump - Prints bpf program in human readable format. Switch-case code taken 
 *            with the above copyright.
 * @bpf:     bpf program
 */
char *bpf_dump(const struct sock_filter bpf, int n)
{
	int v;
	const char *fmt, *op;

	static char image[256];
	char operand[64];

	v = bpf.k;

	switch (bpf.code) {
	default:
		op = "unimp";
		fmt = "0x%x";
		v = bpf.code;
		break;

	case BPF_RET | BPF_K:
		op = "ret";
		fmt = "#%d";
		break;

	case BPF_RET | BPF_A:
		op = "ret";
		fmt = "";
		break;

	case BPF_LD | BPF_W | BPF_ABS:
		op = "ld";
		fmt = "[%d]";
		break;

	case BPF_LD | BPF_H | BPF_ABS:
		op = "ldh";
		fmt = "[%d]";
		break;

	case BPF_LD | BPF_B | BPF_ABS:
		op = "ldb";
		fmt = "[%d]";
		break;

	case BPF_LD | BPF_W | BPF_LEN:
		op = "ld";
		fmt = "#pktlen";
		break;

	case BPF_LD | BPF_W | BPF_IND:
		op = "ld";
		fmt = "[x + %d]";
		break;

	case BPF_LD | BPF_H | BPF_IND:
		op = "ldh";
		fmt = "[x + %d]";
		break;

	case BPF_LD | BPF_B | BPF_IND:
		op = "ldb";
		fmt = "[x + %d]";
		break;

	case BPF_LD | BPF_IMM:
		op = "ld";
		fmt = "#0x%x";
		break;

	case BPF_LDX | BPF_IMM:
		op = "ldx";
		fmt = "#0x%x";
		break;

	case BPF_LDX | BPF_MSH | BPF_B:
		op = "ldxb";
		fmt = "4*([%d]&0xf)";
		break;

	case BPF_LD | BPF_MEM:
		op = "ld";
		fmt = "M[%d]";
		break;

	case BPF_LDX | BPF_MEM:
		op = "ldx";
		fmt = "M[%d]";
		break;

	case BPF_ST:
		op = "st";
		fmt = "M[%d]";
		break;

	case BPF_STX:
		op = "stx";
		fmt = "M[%d]";
		break;

	case BPF_JMP | BPF_JA:
		op = "ja";
		fmt = "%d";
		v = n + 1 + bpf.k;
		break;

	case BPF_JMP | BPF_JGT | BPF_K:
		op = "jgt";
		fmt = "#0x%x";
		break;

	case BPF_JMP | BPF_JGE | BPF_K:
		op = "jge";
		fmt = "#0x%x";
		break;

	case BPF_JMP | BPF_JEQ | BPF_K:
		op = "jeq";
		fmt = "#0x%x";
		break;

	case BPF_JMP | BPF_JSET | BPF_K:
		op = "jset";
		fmt = "#0x%x";
		break;

	case BPF_JMP | BPF_JGT | BPF_X:
		op = "jgt";
		fmt = "x";
		break;

	case BPF_JMP | BPF_JGE | BPF_X:
		op = "jge";
		fmt = "x";
		break;

	case BPF_JMP | BPF_JEQ | BPF_X:
		op = "jeq";
		fmt = "x";
		break;

	case BPF_JMP | BPF_JSET | BPF_X:
		op = "jset";
		fmt = "x";
		break;

	case BPF_ALU | BPF_ADD | BPF_X:
		op = "add";
		fmt = "x";
		break;

	case BPF_ALU | BPF_SUB | BPF_X:
		op = "sub";
		fmt = "x";
		break;

	case BPF_ALU | BPF_MUL | BPF_X:
		op = "mul";
		fmt = "x";
		break;

	case BPF_ALU | BPF_DIV | BPF_X:
		op = "div";
		fmt = "x";
		break;

	case BPF_ALU | BPF_AND | BPF_X:
		op = "and";
		fmt = "x";
		break;

	case BPF_ALU | BPF_OR | BPF_X:
		op = "or";
		fmt = "x";
		break;

	case BPF_ALU | BPF_LSH | BPF_X:
		op = "lsh";
		fmt = "x";
		break;

	case BPF_ALU | BPF_RSH | BPF_X:
		op = "rsh";
		fmt = "x";
		break;

	case BPF_ALU | BPF_ADD | BPF_K:
		op = "add";
		fmt = "#%d";
		break;

	case BPF_ALU | BPF_SUB | BPF_K:
		op = "sub";
		fmt = "#%d";
		break;

	case BPF_ALU | BPF_MUL | BPF_K:
		op = "mul";
		fmt = "#%d";
		break;

	case BPF_ALU | BPF_DIV | BPF_K:
		op = "div";
		fmt = "#%d";
		break;

	case BPF_ALU | BPF_AND | BPF_K:
		op = "and";
		fmt = "#0x%x";
		break;

	case BPF_ALU | BPF_OR | BPF_K:
		op = "or";
		fmt = "#0x%x";
		break;

	case BPF_ALU | BPF_LSH | BPF_K:
		op = "lsh";
		fmt = "#%d";
		break;

	case BPF_ALU | BPF_RSH | BPF_K:
		op = "rsh";
		fmt = "#%d";
		break;

	case BPF_ALU | BPF_NEG:
		op = "neg";
		fmt = "";
		break;

	case BPF_MISC | BPF_TAX:
		op = "tax";
		fmt = "";
		break;

	case BPF_MISC | BPF_TXA:
		op = "txa";
		fmt = "";
		break;
	}

	snprintf(operand, sizeof(operand), fmt, v);
	snprintf(image, sizeof(image),
		 (BPF_CLASS(bpf.code) == BPF_JMP &&
		  BPF_OP(bpf.code) != BPF_JA) ?
		 "(%03d) %-8s %-16s jt %d\tjf %d" : "(%03d) %-8s %s", n, op, operand, n + 1 + bpf.jt, n + 1 + bpf.jf);
	return image;
}

/**
 * bpf_dump_all - Returns non-wireless bitrate in Mb/s (via ethtool)
 * @bpf:         bpf program
 * @len:         len of bpf
 */
void bpf_dump_all(struct sock_filter *bpf, int len)
{
	int i;

	assert(bpf && len > 0);

	for (i = 0; i < len; ++i) {
		info(" %s\n", bpf_dump(bpf[i], i));
	}

	info("\n");
}

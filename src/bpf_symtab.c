/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2012 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bpf_symtab.h"
#include "die.h"
#include "xmalloc.h"

struct sym_entry {
	char *name; 
	int type, declared;
};

#define MAX_SYMBOLS	512

static struct sym_entry symbol_table[MAX_SYMBOLS];
static size_t symbol_used = 0;

int bpf_symtab_find(const char *name)
{
	int i;

	for (i = 0; i < symbol_used; ++i)
		if (!strcmp(symbol_table[i].name, name))
			return i;
	return -1;
}

void bpf_symtab_cleanup(void)
{
	int i;

	for (i = 0; i < symbol_used; ++i)
		xfree(symbol_table[i].name);
}

int bpf_symtab_insert(const char *name, int type)
{
	if (symbol_used >= MAX_SYMBOLS)
		panic("Symbol table overflow, %zu entries!\n", symbol_used);

	symbol_table[symbol_used].name = xstrdup(name);
	symbol_table[symbol_used].type = type;
	symbol_table[symbol_used].declared = 0;

	return symbol_used++;
}

int bpf_symtab_type(int idx)
{
	if (idx < 0 || idx >= symbol_used)
		return -1;

	return symbol_table[idx].type;
}

void bpf_symtab_declare(int idx)
{
	if (idx < 0 || idx >= symbol_used)
		return;

	symbol_table[idx].declared = 1;
}

int bpf_symtab_declared(int idx)
{
	if (idx < 0 || idx >= symbol_used)
		return -1;

	return symbol_table[idx].declared;
}

const char *bpf_symtab_name(int idx)
{
	if (idx < 0 || idx >= symbol_used)
		return NULL;

	return symbol_table[idx].name;
}

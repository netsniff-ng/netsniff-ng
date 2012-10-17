/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2012 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL, version 2.
 */

#ifndef	BPF_SYMTAB_H
#define	BPF_SYMTAB_H

extern int bpf_symtab_insert(const char *name, int type);
extern void bpf_symtab_declare(int idx);
extern int bpf_symtab_find(const char *name);
extern const char *bpf_symtab_name(int idx);
extern int bpf_symtab_type(int idx);
extern int bpf_symtab_declared(int idx);
extern void bpf_symtab_cleanup(void);

#endif /* BPF_SYMTAB_H */

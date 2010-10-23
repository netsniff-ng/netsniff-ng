/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef BPF_H
#define BPF_H

#include <linux/filter.h>
#include <stdint.h>

typedef uint32_t bpf_u_int32;

extern void bpf_dump_all(struct sock_fprog *bpf);
extern int bpf_validate(const struct sock_fprog *bpf);
extern uint32_t bpf_run_filter(const struct sock_fprog *bpf, uint8_t *packet,
			       size_t plen);
extern void bpf_attach_to_sock(int sock, struct sock_fprog *bpf);
extern void bpf_detach_from_sock(int sock);
extern void bpf_parse_rules(char *rulefile, struct sock_fprog *bpf);

#endif /* BPF_H */

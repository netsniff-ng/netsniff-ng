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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "die.h"

typedef uint32_t bpf_u_int32;

extern void bpf_dump_all(struct sock_fprog *bpf);
extern int bpf_validate(const struct sock_fprog *bpf);
extern uint32_t bpf_run_filter(const struct sock_fprog *bpf, uint8_t *packet,
			       size_t plen);
extern void bpf_attach_to_sock(int sock, struct sock_fprog *bpf);
extern void bpf_detach_from_sock(int sock);
extern void bpf_parse_rules(char *rulefile, struct sock_fprog *bpf);

/* For bleeding edge kernels! A JIT compiler for BPF. */
static inline void enable_kernel_bpf_jit_compiler(void)
{
	int fd;
	ssize_t ret;
	char *file = "/proc/sys/net/core/bpf_jit_enable";
	fd = open(file, O_WRONLY);
	if (fd < 0)
		return;
	ret = write(fd, "1", strlen("1") + 1);
	if (ret > 0) {
		info("BPF JIT COMPILER\n");
	}
        close(fd);
}

#endif /* BPF_H */

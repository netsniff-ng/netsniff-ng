#ifndef BPF_I_H
#define BPF_I_H

#include <linux/filter.h>
#include <stdint.h>
#include <stdlib.h>

#include "bpf_insns.h"
#include "bpf_ext.h"
#include "config.h"
#include "die.h"

extern void bpf_dump_op_table(void);
extern void bpf_dump_all(struct sock_fprog *bpf);
extern int __bpf_validate(const struct sock_fprog *bpf);
extern uint32_t bpf_run_filter(const struct sock_fprog *bpf, uint8_t *packet,
			       size_t plen);
extern void bpf_attach_to_sock(int sock, struct sock_fprog *bpf);
extern void bpf_detach_from_sock(int sock);
extern int enable_kernel_bpf_jit_compiler(void);
extern void bpf_parse_rules(char *rulefile, struct sock_fprog *bpf, uint32_t link_type);
#if defined(HAVE_TCPDUMP_LIKE_FILTER) && defined(NEED_TCPDUMP_LIKE_FILTER)
extern void bpf_try_compile(const char *rulefile, struct sock_fprog *bpf,
			    uint32_t link_type);
#else
static inline void bpf_try_compile(const char *rulefile,
				   struct sock_fprog *bpf __maybe_unused,
				   uint32_t link_type __maybe_unused)
{
	panic("Cannot open file %s!\n", rulefile);
}
#endif
static inline void bpf_release(struct sock_fprog *bpf)
{
	free(bpf->filter);
}

#endif /* BPF_I_H */

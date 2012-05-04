/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef BPF_H
#define BPF_H

#include <linux/filter.h>
#include <stdint.h>
#include <stdlib.h>

#include "xmalloc.h"

extern void bpf_dump_all(struct sock_fprog *bpf);
extern int bpf_validate(const struct sock_fprog *bpf);
extern uint32_t bpf_run_filter(const struct sock_fprog *bpf, uint8_t *packet,
			       size_t plen);
extern void bpf_attach_to_sock(int sock, struct sock_fprog *bpf);
extern void bpf_detach_from_sock(int sock);
extern void enable_kernel_bpf_jit_compiler(void);
extern void bpf_parse_rules(char *rulefile, struct sock_fprog *bpf);

static inline void bpf_release(struct sock_fprog *bpf)
{
	free(bpf->filter);
}

/*
 * The instruction encodings.
 */
/* instruction classes */
#define BPF_CLASS(code) ((code) & 0x07)
#define	BPF_LD		0x00
#define	BPF_LDX		0x01
#define	BPF_ST		0x02
#define	BPF_STX		0x03
#define	BPF_ALU		0x04
#define	BPF_JMP		0x05
#define	BPF_RET		0x06
#define	BPF_MISC	0x07

/* ld/ldx fields */
#define BPF_SIZE(code)	((code) & 0x18)
#define	BPF_W		0x00
#define	BPF_H		0x08
#define	BPF_B		0x10
#define BPF_MODE(code)	((code) & 0xe0)
#define	BPF_IMM 	0x00
#define	BPF_ABS		0x20
#define	BPF_IND		0x40
#define	BPF_MEM		0x60
#define	BPF_LEN		0x80
#define	BPF_MSH		0xa0

/* alu/jmp fields */
#define BPF_OP(code)	((code) & 0xf0)
#define	BPF_ADD		0x00
#define	BPF_SUB		0x10
#define	BPF_MUL		0x20
#define	BPF_DIV		0x30
#define	BPF_OR		0x40
#define	BPF_AND		0x50
#define	BPF_LSH		0x60
#define	BPF_RSH		0x70
#define	BPF_NEG		0x80
#define	BPF_JA		0x00
#define	BPF_JEQ		0x10
#define	BPF_JGT		0x20
#define	BPF_JGE		0x30
#define	BPF_JSET	0x40
#define BPF_SRC(code)	((code) & 0x08)
#define	BPF_K		0x00
#define	BPF_X		0x08

/* ret - BPF_K and BPF_X also apply */
#define BPF_RVAL(code)	((code) & 0x18)
#define	BPF_A		0x10

/* misc */
#define BPF_MISCOP(code) ((code) & 0xf8)
#define	BPF_TAX		0x00
#define	BPF_TXA		0x80

/* Hidden Linux kernel BPF extensions */
/*
 * RATIONALE. Negative offsets are invalid in BPF.
 * We use them to reference ancillary data.
 * Unlike introduction new instructions, it does not break
 * existing compilers/optimizers.
 */

#ifndef SKF_AD_OFF
# define SKF_AD_OFF		(-0x1000)
#endif
#ifndef SKF_AD_PROTOCOL
# define SKF_AD_PROTOCOL 	0
#endif
#ifndef SKF_AD_PKTTYPE
# define SKF_AD_PKTTYPE 	4
#endif
#ifndef SKF_AD_IFINDEX
# define SKF_AD_IFINDEX 	8
#endif
#ifndef SKF_AD_NLATTR
# define SKF_AD_NLATTR		12
#endif
#ifndef SKF_AD_NLATTR_NEST
# define SKF_AD_NLATTR_NEST	16
#endif
#ifndef SKF_AD_MARK
# define SKF_AD_MARK 		20
#endif
#ifndef SKF_AD_QUEUE
# define SKF_AD_QUEUE		24
#endif
#ifndef SKF_AD_HATYPE
# define SKF_AD_HATYPE		28
#endif
#ifndef SKF_AD_RXHASH
# define SKF_AD_RXHASH		32
#endif
#ifndef SKF_AD_CPU
# define SKF_AD_CPU		36
#endif

#endif /* BPF_H */

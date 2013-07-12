/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2013 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <pcap.h>
#include <linux/filter.h>

#include "xmalloc.h"
#include "config.h"
#include "bpf.h"
#include "die.h"

void bpf_try_compile(const char *rulefile, struct sock_fprog *bpf, uint32_t link_type)
{
	int i, ret;
	const struct bpf_insn *ins;
	struct sock_filter *out;
	struct bpf_program _bpf;

	ret = pcap_compile_nopcap(65535, link_type, &_bpf, rulefile, 1, 0xffffffff);
	if (ret < 0)
		panic("Cannot compile filter %s\n", rulefile);

	bpf->len = _bpf.bf_len;
	bpf->filter = xrealloc(bpf->filter, 1, bpf->len * sizeof(*out));

	for (i = 0, ins = _bpf.bf_insns, out = bpf->filter; i < bpf->len;
	     ++i, ++ins, ++out) {
		out->code = ins->code;
		out->jt = ins->jt;
		out->jf = ins->jf;
		out->k = ins->k;

		if (out->code == 0x06 && out->k > 0)
			out->k = 0xFFFFFFFF;
	}

	pcap_freecode(&_bpf);

	if (__bpf_validate(bpf) == 0)
		panic("This is not a valid BPF program!\n");
}

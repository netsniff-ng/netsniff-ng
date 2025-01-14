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
	pcap_t *pcap_handle;
	struct sock_filter *out;
	struct bpf_program _bpf;
	const struct bpf_insn *ins;

	pcap_handle = pcap_open_dead(link_type, 65535);
	if (!pcap_handle)
		panic("Cannot open fake pcap_t for compiling BPF code");

	ret = pcap_compile(pcap_handle, &_bpf, rulefile, 1, PCAP_NETMASK_UNKNOWN);
	pcap_close(pcap_handle);
	if (ret < 0)
		panic("Cannot compile filter: %s\n", rulefile);

	bpf->len = _bpf.bf_len;
	bpf->filter = xrealloc(bpf->filter, bpf->len * sizeof(*out));

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

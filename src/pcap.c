/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

#include <errno.h>
#include "pcap.h"
#include "compiler.h"

struct pcap_file_ops *pcap_ops[PCAP_OPS_MAX] = {0};

int pcap_ops_group_register(struct pcap_file_ops *ops,
			    enum pcap_ops_groups group)
{
	if (!ops)
		return -EINVAL;
	if (pcap_ops[group])
		return -EBUSY;
	pcap_ops[group] = ops;
	barrier();
	return 0;
}

void pcap_ops_group_unregister(enum pcap_ops_groups group)
{
	pcap_ops[group] = NULL;
}


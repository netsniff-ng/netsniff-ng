/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2014 Tobias Klauser.
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <unistd.h>
#include <libnl3/netlink/msg.h>
#include <libgen.h>

#include "pkt_buff.h"
#include "proto.h"
#include "protos.h"

static void nlmsg(struct pkt_buff *pkt)
{
	struct nlmsghdr *hdr = (struct nlmsghdr *) pkt_pull(pkt, sizeof(*hdr));
	char type[32];
	char flags[128];
	char procname[1024];

	if (hdr == NULL)
		return;

	/* Look up the process name if message is not coming from the kernel.
	 *
	 * Note that the port id is not necessarily equal to the PID of the
	 * receiving process (e.g. if the application is multithreaded or using
	 * multiple sockets). In these cases we're not able to find a matching
	 * PID and the information will not be printed.
	 */
	if (hdr->nlmsg_pid != 0) {
		char path[1024];
		int ret;

		snprintf(path, sizeof(path), "/proc/%u/exe", hdr->nlmsg_pid);
		ret = readlink(path, procname, sizeof(procname) - 1);
		if (ret < 0)
			procname[0] = '\0';
	} else
		snprintf(procname, sizeof(procname), "kernel");

	tprintf(" [ NLMSG ");
	tprintf("Len %u, ", hdr->nlmsg_len);
	tprintf("Type 0x%.4x (%s%s%s), ", hdr->nlmsg_type,
		colorize_start(bold),
		nl_nlmsgtype2str(hdr->nlmsg_type, type, sizeof(type)),
		colorize_end());
	tprintf("Flags 0x%.4x (%s%s%s), ", hdr->nlmsg_flags,
		colorize_start(bold),
		nl_nlmsg_flags2str(hdr->nlmsg_flags, flags, sizeof(flags)),
		colorize_end());
	tprintf("Seq-Nr %u, ", hdr->nlmsg_seq);
	tprintf("PID %u", hdr->nlmsg_pid);
	if (procname[0])
		tprintf(" (%s%s%s)", colorize_start(bold), basename(procname),
			colorize_end());
	tprintf(" ]\n");
}

static void nlmsg_less(struct pkt_buff *pkt)
{
	struct nlmsghdr *hdr = (struct nlmsghdr *) pkt_pull(pkt, sizeof(*hdr));
	char type[32];

	if (hdr == NULL)
		return;

	tprintf(" NLMSG %u (%s%s%s)", hdr->nlmsg_type, colorize_start(bold),
		nl_nlmsgtype2str(hdr->nlmsg_type, type, sizeof(type)),
		colorize_end());
}

struct protocol nlmsg_ops = {
	.print_full = nlmsg,
	.print_less = nlmsg_less,
};

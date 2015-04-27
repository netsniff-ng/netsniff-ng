/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2014 Tobias Klauser.
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <libgen.h>
#include <netlink/msg.h>

#include "pkt_buff.h"
#include "proto.h"
#include "protos.h"

static const char *nlmsg_family2str(uint16_t family)
{
	switch (family) {
	case NETLINK_ROUTE:		return "routing";
	case NETLINK_UNUSED:		return "unused";
	case NETLINK_USERSOCK:		return "user-mode socket";
	case NETLINK_FIREWALL:		return "unused, formerly ip_queue";
/* NETLINK_INET_DIAG was renamed to NETLINK_SOCK_DIAG in Linux kernel 3.10 */
#if defined(NETLINK_SOCK_DIAG)
	case NETLINK_SOCK_DIAG:		return "socket monitoring";
#elif defined(NETLINK_INET_DIAG)
	case NETLINK_INET_DIAG:		return "INET socket monitoring";
#endif
	case NETLINK_NFLOG:		return "netfilter ULOG";
	case NETLINK_XFRM:		return "IPsec";
	case NETLINK_SELINUX:		return "SELinux event notification";
	case NETLINK_ISCSI:		return "Open-iSCSI";
	case NETLINK_AUDIT:		return "auditing";
	case NETLINK_FIB_LOOKUP:	return "FIB lookup";
	case NETLINK_CONNECTOR:		return "Kernel connector";
	case NETLINK_NETFILTER:		return "Netfilter";
	case NETLINK_IP6_FW:		return "unused, formerly ip6_queue";
	case NETLINK_DNRTMSG:		return "DECnet routing";
	case NETLINK_KOBJECT_UEVENT:	return "Kernel messages";
	case NETLINK_GENERIC:		return "Generic";
	case NETLINK_SCSITRANSPORT:	return "SCSI transports";
	case NETLINK_ECRYPTFS:		return "ecryptfs";
	case NETLINK_RDMA:		return "RDMA";
	case NETLINK_CRYPTO:		return "Crypto layer";
	default:			return "Unknown";
	}
}

static void nlmsg(struct pkt_buff *pkt)
{
	struct nlmsghdr *hdr = (struct nlmsghdr *) pkt_pull(pkt, sizeof(*hdr));
	char type[32];
	char flags[128];
	char procname[PATH_MAX];

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
			ret = 0;
		procname[ret] = '\0';
	} else
		snprintf(procname, sizeof(procname), "kernel");

	tprintf(" [ NLMSG ");
	tprintf("Family %d (%s%s%s), ", ntohs(pkt->proto), colorize_start(bold),
		nlmsg_family2str(ntohs(pkt->proto)), colorize_end());
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

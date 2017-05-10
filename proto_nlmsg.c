/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2014 Tobias Klauser.
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <libgen.h>
#include <netlink/msg.h>
#include <netlink/route/link.h>
#include <netlink/route/addr.h>
#include <arpa/inet.h>

#include "dev.h"
#include "pkt_buff.h"
#include "proc.h"
#include "proto.h"
#include "protos.h"
#include "timer.h"

#define INFINITY 0xFFFFFFFFU

#define RTA_LEN(attr) ((int)RTA_PAYLOAD(attr))
#define RTA_INT(attr) (*(int *)RTA_DATA(attr))
#define RTA_UINT(attr) (*(unsigned int *)RTA_DATA(attr))
#define RTA_UINT8(attr) (*(uint8_t *)RTA_DATA(attr))
#define RTA_UINT32(attr) (*(uint32_t *)RTA_DATA(attr))
#define RTA_STR(attr) ((char *)RTA_DATA(attr))

#ifndef NDA_RTA
#define NDA_RTA(r) \
	((struct rtattr*)(((char*)(r)) + NLMSG_ALIGN(sizeof(struct ndmsg))))
#endif

#ifndef NDA_PAYLOAD
#define NDA_PAYLOAD(n)	NLMSG_PAYLOAD(n,sizeof(struct ndmsg))
#endif

#ifndef NLA_LENGTH
#define NLA_LENGTH(len)	(NLA_ALIGN(sizeof(struct nlattr)) + (len))
#endif

#ifndef NLA_DATA
#define NLA_DATA(nla)   ((void*)(((char*)(nla)) + NLA_LENGTH(0)))
#endif

#ifndef NLA_PAYLOAD
#define NLA_PAYLOAD(nla) ((int)((nla)->nla_len) - NLA_LENGTH(0))
#endif

#define NLA_LEN(attr) ((int)NLA_PAYLOAD(attr))
#define NLA_INT(attr) (*(int *)NLA_DATA(attr))
#define NLA_UINT(attr) (*(unsigned int *)NLA_DATA(attr))
#define NLA_UINT8(attr) (*(uint8_t *)NLA_DATA(attr))
#define NLA_UINT16(attr) (*(uint16_t *)NLA_DATA(attr))
#define NLA_UINT32(attr) (*(uint32_t *)NLA_DATA(attr))
#define NLA_STR(attr) ((char *)NLA_DATA(attr))

#ifndef GEN_NLA
#define GEN_NLA(n) ((struct nlattr*)(((char*)(n)) + GENL_HDRLEN))
#endif

#ifndef NLA_OK
#define NLA_OK(nla,len)                            \
	((len) >= (int)sizeof(struct nlattr) &&    \
	(nla)->nla_len >= sizeof(struct nlattr) && \
	(nla)->nla_len <= (len))
#endif

#ifndef NLA_NEXT
#define NLA_NEXT(nla,attrlen)                    \
	((attrlen) -= NLA_ALIGN((nla)->nla_len), \
	(struct nlattr*)(((char*)(nla)) + NLA_ALIGN((nla)->nla_len)))
#endif

#define rta_fmt(attr, fmt, ...) \
	tprintf("\tA: "fmt, ##__VA_ARGS__); \
	tprintf(", Len %d\n", RTA_LEN(attr));

#define nla_fmt(attr, fmt, ...) \
	tprintf("\tA: "fmt, ##__VA_ARGS__); \
	tprintf(", Len %d\n", NLA_LEN(attr));

#define nla_fmt_nested(attr, fmt, ...) \
	tprintf("[ "fmt, ##__VA_ARGS__); \
	tprintf(", Len %d] ", NLA_LEN(attr));

#define nla_fmt_nested_start(attr, fmt, ...)    \
	tprintf("\t    A: "fmt, ##__VA_ARGS__); \
	tprintf(", Len %d ", NLA_LEN(attr));

#define nla_fmt_nested_end() tprintf("\n")

struct flag_name {
	const char *name;
	unsigned int flag;
};

static const char *flags2str(struct flag_name *tbl, unsigned int flags,
		char *buf, int len)
{
	int bits_stay = flags;

	memset(buf, 0, len);

	for (; tbl && tbl->name; tbl++) {
		if (!(tbl->flag & flags))
			continue;

		bits_stay &= ~tbl->flag;
		strncat(buf, tbl->name, len - strlen(buf) - 1);

		if (bits_stay & flags)
			strncat(buf, ",", len - strlen(buf) - 1);
	}

	return buf;
}

static void nlmsg_print_raw(struct nlmsghdr *hdr)
{
	u32 len = hdr->nlmsg_len;

	if (len) {
		_ascii((uint8_t *) hdr + NLMSG_HDRLEN, len - NLMSG_HDRLEN);
		_hex((uint8_t *) hdr + NLMSG_HDRLEN, len - NLMSG_HDRLEN);
	}
}

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
#if defined(NETLINK_CRYPTO)
	case NETLINK_CRYPTO:		return "Crypto layer";
#endif
	default:			return "Unknown";
	}
}

static const char *nlmsg_rtnl_type2str(uint16_t type)
{
	switch (type) {
	case RTM_NEWLINK:	return "new link";
	case RTM_DELLINK:	return "del link";
	case RTM_GETLINK:	return "get link";
	case RTM_SETLINK:	return "set link";

	case RTM_NEWADDR:	return "new addr";
	case RTM_DELADDR:	return "del addr";
	case RTM_GETADDR:	return "get addr";

	case RTM_NEWROUTE:	return "new route";
	case RTM_DELROUTE:	return "del route";
	case RTM_GETROUTE:	return "get route";

	case RTM_NEWNEIGH:	return "new neigh";
	case RTM_DELNEIGH:	return "del neigh";
	case RTM_GETNEIGH:	return "get neigh";

	case RTM_NEWRULE:	return "new rule";
	case RTM_DELRULE:	return "del rule";
	case RTM_GETRULE:	return "get rule";

	case RTM_NEWQDISC:	return "new tc qdisc";
	case RTM_DELQDISC:	return "del tc qdisc";
	case RTM_GETQDISC:	return "get tc qdisc";

	case RTM_NEWTCLASS:	return "new tc class";
	case RTM_DELTCLASS:	return "del tc class";
	case RTM_GETTCLASS:	return "get tc class";

	case RTM_NEWTFILTER:	return "new tc filter";
	case RTM_DELTFILTER:	return "del tc filter";
	case RTM_GETTFILTER:	return "get tc filter";

	case RTM_NEWACTION:	return "new tc action";
	case RTM_DELACTION:	return "del tc action";
	case RTM_GETACTION:	return "get tc action";

	case RTM_NEWPREFIX:	return "new prefix";

	case RTM_GETMULTICAST:	return "get mcast addr";

	case RTM_GETANYCAST:	return "get anycast addr";

	case RTM_NEWNEIGHTBL:	return "new neigh table";
	case RTM_GETNEIGHTBL:	return "get neigh table";
	case RTM_SETNEIGHTBL:	return "set neigh table";

	case RTM_NEWNDUSEROPT:	return "new ndisc user option";

	case RTM_NEWADDRLABEL:	return "new addr label";
	case RTM_DELADDRLABEL:	return "del addr label";
	case RTM_GETADDRLABEL:	return "get addr label";

	case RTM_GETDCB:	return "get data-center-bridge";
	case RTM_SETDCB:	return "set data-center-bridge";

#if defined(RTM_NEWNETCONF)
	case RTM_NEWNETCONF:	return "new netconf";
	case RTM_GETNETCONF:	return "get netconf";
#endif

#if defined(RTM_NEWMDB)
	case RTM_NEWMDB:	return "new bridge mdb";
	case RTM_DELMDB: 	return "del bridge mdb";
	case RTM_GETMDB: 	return "get bridge mdb";
#endif
	default:		return NULL;
	}
}

static const char *nlmsg_genl_type2str(uint16_t type)
{
	switch (type) {
	case GENL_ID_CTRL:	return "nlctrl";
#if defined(GENL_ID_PCMRAID)
	case GENL_ID_PCMRAID:	return "pcmraid";
#endif
#if defined(GENL_ID_VFS_DQUOT)
	case GENL_ID_VFS_DQUOT:	return "vfs dquot";
#endif
	/* only dynamic family IDs should be used starting with Linux 4.10 */
	default:		return "dynamic";
	}
}

static char *nlmsg_type2str(uint16_t proto, uint16_t type, char *buf, int len)
{
	const char *name = NULL;

	if (proto == NETLINK_ROUTE && type < RTM_MAX)
		name = nlmsg_rtnl_type2str(type);
	else if (proto == NETLINK_GENERIC)
		name = nlmsg_genl_type2str(type);

	if (name) {
		strncpy(buf, name, len);
		return buf;
	}

	return nl_nlmsgtype2str(type, buf, len);
}

static const char *addr_family2str(uint16_t family)
{
	switch (family) {
	case AF_INET:	return "ipv4";
	case AF_INET6:	return "ipv6";
	case AF_DECnet:	return "decnet";
	case AF_IPX:	return "ipx";
	default:	return "Unknown";
	}
}

static const char *addr2str(uint16_t af, const void *addr, char *buf, int blen)
{
	if (af == AF_INET || af == AF_INET6)
		return inet_ntop(af, addr, buf, blen);

	return "???";
}

static const char *scope2str(uint8_t scope)
{
	switch (scope) {
	case RT_SCOPE_UNIVERSE: return "global";
	case RT_SCOPE_LINK: return "link";
	case RT_SCOPE_HOST: return "host";
	case RT_SCOPE_NOWHERE: return "nowhere";

	default: return "Unknown";
	}
}

static void rtnl_print_ifinfo(struct nlmsghdr *hdr)
{
	struct ifinfomsg *ifi = NLMSG_DATA(hdr);
	struct rtattr *attr = IFLA_RTA(ifi);
	uint32_t attrs_len = IFLA_PAYLOAD(hdr);
	char flags[256];
	char if_addr[64] = {};
	char *af_link = "unknown";

	if (hdr->nlmsg_len < NLMSG_LENGTH(sizeof(*ifi)))
		return;

	if (ifi->ifi_family == AF_UNSPEC)
		af_link = "unspec";
	else if (ifi->ifi_family == AF_BRIDGE)
		af_link = "bridge";

	tprintf(" [ Link Family %d (%s%s%s)", ifi->ifi_family,
			colorize_start(bold), af_link, colorize_end());
	tprintf(", Type %d (%s%s%s)", ifi->ifi_type,
			colorize_start(bold),
			device_type2str(ifi->ifi_type),
			colorize_end());
	tprintf(", Index %d", ifi->ifi_index);
	tprintf(", Flags 0x%x (%s%s%s)", ifi->ifi_flags,
			colorize_start(bold),
			rtnl_link_flags2str(ifi->ifi_flags, flags,
				sizeof(flags)),
			colorize_end());
	tprintf(", Change 0x%x (%s%s%s) ]\n", ifi->ifi_change,
			colorize_start(bold),
			rtnl_link_flags2str(ifi->ifi_change, flags,
				sizeof(flags)),
			colorize_end());

	for (; RTA_OK(attr, attrs_len); attr = RTA_NEXT(attr, attrs_len)) {
		switch (attr->rta_type) {
		case IFLA_ADDRESS:
			rta_fmt(attr, "Address %s",
					device_addr2str(RTA_DATA(attr),
						RTA_LEN(attr), ifi->ifi_type,
						if_addr, sizeof(if_addr)));
			break;
		case IFLA_BROADCAST:
			rta_fmt(attr, "Broadcast %s",
					device_addr2str(RTA_DATA(attr),
						RTA_LEN(attr), ifi->ifi_type,
						if_addr, sizeof(if_addr)));
			break;
		case IFLA_IFNAME:
			rta_fmt(attr, "Name %s%s%s",
					colorize_start(bold), RTA_STR(attr),
					colorize_end());
			break;
		case IFLA_MTU:
			rta_fmt(attr, "MTU %d", RTA_INT(attr));
			break;
		case IFLA_LINK:
			rta_fmt(attr, "Link %d", RTA_INT(attr));
			break;
		case IFLA_QDISC:
			rta_fmt(attr, "QDisc %s", RTA_STR(attr));
			break;
		case IFLA_OPERSTATE:
			{
				uint8_t st = RTA_UINT8(attr);
				char states[256];

				rta_fmt(attr, "Operation state 0x%x (%s%s%s)",
						st,
						colorize_start(bold),
						rtnl_link_operstate2str(st,
							states, sizeof(states)),
						colorize_end());
			}
			break;
		case IFLA_LINKMODE:
			{
				uint8_t mode = RTA_UINT8(attr);
				char str[32];

				rta_fmt(attr, "Mode 0x%x (%s%s%s)", mode,
						colorize_start(bold),
						rtnl_link_mode2str(mode, str,
							sizeof(str)),
						colorize_end());
			}
			break;
		case IFLA_GROUP:
			rta_fmt(attr, "Group %d", RTA_INT(attr));
			break;
		case IFLA_TXQLEN:
			rta_fmt(attr, "Tx queue len %d", RTA_INT(attr));
			break;
		case IFLA_NET_NS_PID:
			rta_fmt(attr, "Network namespace pid %d",
					RTA_INT(attr));
			break;
		case IFLA_NET_NS_FD:
			rta_fmt(attr, "Network namespace fd %d", RTA_INT(attr));
			break;
		default:
			rta_fmt(attr, "0x%x", attr->rta_type);
			break;
		}
	}
}

static void rtnl_print_ifaddr(struct nlmsghdr *hdr)
{
	struct ifaddrmsg *ifa = NLMSG_DATA(hdr);
	uint32_t attrs_len = IFA_PAYLOAD(hdr);
	struct rtattr *attr = IFA_RTA(ifa);
	struct ifa_cacheinfo *ci;
	char addr_str[256];
	char flags[256];

	if (hdr->nlmsg_len < NLMSG_LENGTH(sizeof(*ifa)))
		return;

	tprintf(" [ Address Family %d (%s%s%s)", ifa->ifa_family,
			colorize_start(bold),
			addr_family2str(ifa->ifa_family),
			colorize_end());
	tprintf(", Prefix Len %d", ifa->ifa_prefixlen);
	tprintf(", Flags %d (%s%s%s)", ifa->ifa_flags,
			colorize_start(bold),
			rtnl_addr_flags2str(ifa->ifa_flags, flags,
				sizeof(flags)),
			colorize_end());
	tprintf(", Scope %d (%s%s%s)", ifa->ifa_scope,
			colorize_start(bold),
			scope2str(ifa->ifa_scope),
			colorize_end());
	tprintf(", Link Index %d ]\n", ifa->ifa_index);

	for (; RTA_OK(attr, attrs_len); attr = RTA_NEXT(attr, attrs_len)) {
		switch (attr->rta_type) {
		case IFA_LOCAL:
			rta_fmt(attr, "Local %s", addr2str(ifa->ifa_family,
				RTA_DATA(attr), addr_str, sizeof(addr_str)));
			break;
		case IFA_ADDRESS:
			rta_fmt(attr, "Address %s", addr2str(ifa->ifa_family,
				RTA_DATA(attr), addr_str, sizeof(addr_str)));
			break;
		case IFA_BROADCAST:
			rta_fmt(attr, "Broadcast %s",
					addr2str(ifa->ifa_family,
						RTA_DATA(attr), addr_str,
						sizeof(addr_str)));
			break;
		case IFA_MULTICAST:
			rta_fmt(attr, "Multicast %s",
					addr2str(ifa->ifa_family,
						RTA_DATA(attr), addr_str,
						sizeof(addr_str)));
			break;
		case IFA_ANYCAST:
			rta_fmt(attr, "Anycast %s", addr2str(ifa->ifa_family,
				RTA_DATA(attr), addr_str, sizeof(addr_str)));
			break;
#ifdef IFA_FLAGS
		case IFA_FLAGS:
			rta_fmt(attr, "Flags %d (%s%s%s)", RTA_INT(attr),
				colorize_start(bold),
				rtnl_addr_flags2str(RTA_INT(attr),
					flags, sizeof(flags)),
				colorize_end());
			break;
#endif
		case IFA_LABEL:
			rta_fmt(attr, "Label %s", RTA_STR(attr));
			break;
		case IFA_CACHEINFO:
			ci = RTA_DATA(attr);
			tprintf("\tA: Cache (");

			if (ci->ifa_valid == INFINITY)
				tprintf("valid lft(forever)");
			else
				tprintf("valid lft(%us)", ci->ifa_valid);

			if (ci->ifa_prefered == INFINITY)
				tprintf(", prefrd lft(forever)");
			else
				tprintf(", prefrd lft(%us)", ci->ifa_prefered);

			tprintf(", created on(%.2fs)", (double)ci->cstamp / 100);
			tprintf(", updated on(%.2fs))", (double)ci->cstamp / 100);
			tprintf(", Len %d\n", RTA_LEN(attr));
			break;
		default:
			rta_fmt(attr, "0x%x", attr->rta_type);
			break;
		}
	}
}

static const char *route_table2str(uint8_t table)
{
	switch (table) {
	case RT_TABLE_UNSPEC: return "unspec";
	case RT_TABLE_COMPAT: return "compat";
	case RT_TABLE_DEFAULT: return "default";
	case RT_TABLE_MAIN: return "main";
	case RT_TABLE_LOCAL: return "local";

	default: return "Unknown";
	}
}

static const char *route_proto2str(uint8_t proto)
{
	switch (proto) {
	case RTPROT_UNSPEC: return "unspec";
	case RTPROT_REDIRECT: return "redirect";
	case RTPROT_KERNEL: return "kernel";
	case RTPROT_BOOT: return "boot";
	case RTPROT_STATIC: return "static";
	case RTPROT_GATED: return "gated";
	case RTPROT_RA: return "ra";
	case RTPROT_MRT: return "mrt";
	case RTPROT_ZEBRA: return "zebra";
	case RTPROT_BIRD: return "bird";
	case RTPROT_DNROUTED: return "DECnet";
	case RTPROT_XORP: return "xorp";
	case RTPROT_NTK: return "netsukuku";
	case RTPROT_DHCP: return "dhcpc";
#ifdef RTPROT_MROUTED
	case RTPROT_MROUTED: return "mrouted";
#endif

	default: return "Unknown";
	}
}

static const char *route_type2str(uint8_t type)
{
	switch (type) {
	case RTN_UNSPEC: return "unspec";
	case RTN_UNICAST: return "unicast";
	case RTN_LOCAL: return "local";
	case RTN_BROADCAST: return "broadcast";
	case RTN_ANYCAST: return "anycast";
	case RTN_MULTICAST: return "multicast";
	case RTN_BLACKHOLE: return "blackhole";
	case RTN_UNREACHABLE: return "unreach";
	case RTN_PROHIBIT: return "prohibit";
	case RTN_THROW: return "throw";
	case RTN_NAT: return "nat";
	case RTN_XRESOLVE: return "xresolve";
	default: return "Unknown";
	}
}

static struct flag_name route_flags[] = {
	{ "notify", RTM_F_NOTIFY },
	{ "cloned", RTM_F_CLONED },
	{ "equalize", RTM_F_EQUALIZE },
	{ "prefix", RTM_F_PREFIX },
	{ "dead", RTNH_F_DEAD },
	{ "pervasive", RTNH_F_PERVASIVE },
	{ "onlink", RTNH_F_ONLINK },
	{ NULL, 0 },
};

static void rtnl_print_route(struct nlmsghdr *hdr)
{
	struct rtmsg *rtm = NLMSG_DATA(hdr);
	uint32_t attrs_len = RTM_PAYLOAD(hdr);
	struct rtattr *attr = RTM_RTA(rtm);
	struct rta_cacheinfo *ci;
	int hz = get_user_hz();
	char addr_str[256];
	char flags[256];

	if (hdr->nlmsg_len < NLMSG_LENGTH(sizeof(*rtm)))
		return;

	tprintf(" [ Route Family %d (%s%s%s)", rtm->rtm_family,
			colorize_start(bold),
			addr_family2str(rtm->rtm_family),
			colorize_end());
	tprintf(", Dst Len %d", rtm->rtm_dst_len);
	tprintf(", Src Len %d", rtm->rtm_src_len);
	tprintf(", ToS %d", rtm->rtm_tos);
	tprintf(", Table %d (%s%s%s)", rtm->rtm_table,
			colorize_start(bold),
			route_table2str(rtm->rtm_table),
			colorize_end());
	tprintf(", Proto %d (%s%s%s)", rtm->rtm_protocol,
			colorize_start(bold),
			route_proto2str(rtm->rtm_protocol),
			colorize_end());
	tprintf(", Scope %d (%s%s%s)", rtm->rtm_scope,
			colorize_start(bold),
			scope2str(rtm->rtm_scope),
			colorize_end());
	tprintf(", Type %d (%s%s%s)", rtm->rtm_type,
			colorize_start(bold),
			route_type2str(rtm->rtm_type),
			colorize_end());
	tprintf(", Flags 0x%x (%s%s%s) ]\n", rtm->rtm_flags,
			colorize_start(bold),
			flags2str(route_flags, rtm->rtm_flags, flags,
				sizeof(flags)),
			colorize_end());

	for (; RTA_OK(attr, attrs_len); attr = RTA_NEXT(attr, attrs_len)) {
		switch (attr->rta_type) {
		case RTA_DST:
			rta_fmt(attr, "Dst %s", addr2str(rtm->rtm_family,
				RTA_DATA(attr), addr_str, sizeof(addr_str)));
			break;
		case RTA_SRC:
			rta_fmt(attr, "Src %s", addr2str(rtm->rtm_family,
				RTA_DATA(attr), addr_str, sizeof(addr_str)));
			break;
		case RTA_IIF:
			rta_fmt(attr, "Iif %d", RTA_INT(attr));
			break;
		case RTA_OIF:
			rta_fmt(attr, "Oif %d", RTA_INT(attr));
			break;
		case RTA_GATEWAY:
			rta_fmt(attr, "Gateway %s", addr2str(rtm->rtm_family,
				RTA_DATA(attr), addr_str, sizeof(addr_str)));
			break;
		case RTA_PRIORITY:
			rta_fmt(attr, "Priority %u", RTA_UINT32(attr));
			break;
		case RTA_PREFSRC:
			rta_fmt(attr, "Pref Src %s", addr2str(rtm->rtm_family,
				RTA_DATA(attr), addr_str, sizeof(addr_str)));
			break;
#if defined(RTA_MARK)
		case RTA_MARK:
			rta_fmt(attr, "Mark 0x%x", RTA_UINT(attr));
			break;
#endif
		case RTA_FLOW:
			rta_fmt(attr, "Flow 0x%x", RTA_UINT(attr));
			break;
		case RTA_TABLE:
			rta_fmt(attr, "Table %d (%s%s%s)", RTA_UINT32(attr),
				colorize_start(bold),
				route_table2str(RTA_UINT32(attr)),
				colorize_end());
			break;
		case RTA_CACHEINFO:
			ci = RTA_DATA(attr);
			tprintf("\tA: Cache (");
			tprintf("expires(%ds)", ci->rta_expires / hz);
			tprintf(", error(%d)", ci->rta_error);
			tprintf(", users(%d)", ci->rta_clntref);
			tprintf(", used(%d)", ci->rta_used);
			tprintf(", last use(%ds)", ci->rta_lastuse / hz);
			tprintf(", id(%d)", ci->rta_id);
			tprintf(", ts(%d)", ci->rta_ts);
			tprintf(", ts age(%ds))", ci->rta_tsage);
			tprintf(", Len %d\n", RTA_LEN(attr));
			break;
		default:
			rta_fmt(attr, "0x%x", attr->rta_type);
			break;
		}
	}
}

static struct flag_name neigh_states[] = {
	{ "incomplete", NUD_INCOMPLETE },
	{ "reachable", NUD_REACHABLE },
	{ "stale", NUD_STALE },
	{ "delay", NUD_DELAY },
	{ "probe", NUD_PROBE },
	{ "failed", NUD_FAILED },
	{ "noarp", NUD_NOARP },
	{ "permanent", NUD_PERMANENT },
	{ "none", NUD_NONE },
	{ NULL, 0 },
};

/* Copied from linux/neighbour.h */
#ifndef NTF_USE
# define NTF_USE		0x01
#endif
#ifndef NTF_SELF
# define NTF_SELF		0x02
#endif
#ifndef NTF_MASTER
# define NTF_MASTER		0x04
#endif
#ifndef NTF_PROXY
# define NTF_PROXY		0x08
#endif
#ifndef NTF_EXT_LEARNED
# define NTF_EXT_LEARNED	0x10
#endif
#ifndef NTF_ROUTER
# define NTF_ROUTER		0x80
#endif

static struct flag_name neigh_flags[] = {
	{ "use", NTF_USE },
	{ "self", NTF_SELF },
	{ "master", NTF_MASTER },
	{ "proxy", NTF_PROXY },
	{ "ext learned", NTF_EXT_LEARNED },
	{ "router", NTF_ROUTER },
	{ NULL, 0 },
};

static void rtnl_print_neigh(struct nlmsghdr *hdr)
{
	struct ndmsg *ndm = NLMSG_DATA(hdr);
	uint32_t attrs_len = NDA_PAYLOAD(hdr);
	struct rtattr *attr = NDA_RTA(ndm);
	struct nda_cacheinfo *ci;
	int hz = get_user_hz();
	char addr_str[256];
	char hw_addr[30];
	char states[256];
	char flags[256];

	if (hdr->nlmsg_len < NLMSG_LENGTH(sizeof(*ndm)))
		return;

	tprintf(" [ Neigh Family %d (%s%s%s)", ndm->ndm_family,
			colorize_start(bold),
			addr_family2str(ndm->ndm_family),
			colorize_end());
	tprintf(", Link Index %d", ndm->ndm_ifindex);
	tprintf(", State %d (%s%s%s)", ndm->ndm_state,
			colorize_start(bold),
			flags2str(neigh_states, ndm->ndm_state, states,
				sizeof(states)),
			colorize_end());
	tprintf(", Flags %d (%s%s%s)", ndm->ndm_flags,
			colorize_start(bold),
			flags2str(neigh_flags, ndm->ndm_flags, flags,
				sizeof(flags)),
			colorize_end());
	tprintf(", Type %d (%s%s%s)", ndm->ndm_type,
			colorize_start(bold),
			route_type2str(ndm->ndm_type),
			colorize_end());
	tprintf(" ]\n");

	for (; RTA_OK(attr, attrs_len); attr = RTA_NEXT(attr, attrs_len)) {
		switch (attr->rta_type) {
		case NDA_DST:
			rta_fmt(attr, "Address %s", addr2str(ndm->ndm_family,
						RTA_DATA(attr), addr_str,
						sizeof(addr_str)));
			break;
		case NDA_LLADDR:
			rta_fmt(attr, "HW Address %s",
					device_addr2str(RTA_DATA(attr),
						RTA_LEN(attr), 0, hw_addr,
						sizeof(hw_addr)));
			break;
		case NDA_PROBES:
			rta_fmt(attr, "Probes %d", RTA_UINT32(attr));
			break;
		case NDA_CACHEINFO:
			ci = RTA_DATA(attr);
			tprintf("\tA: Cache (");
			tprintf("confirmed(%ds)", ci->ndm_confirmed / hz);
			tprintf(", used(%ds)", ci->ndm_used / hz);
			tprintf(", updated(%ds)", ci->ndm_updated / hz);
			tprintf(", refcnt(%d))", ci->ndm_refcnt);
			tprintf(", Len %d\n", RTA_LEN(attr));
			break;
		default:
			rta_fmt(attr, "0x%x", attr->rta_type);
			break;
		}
	}
}

static void rtnl_msg_print(struct nlmsghdr *hdr)
{
	switch (hdr->nlmsg_type) {
	case RTM_NEWLINK:
	case RTM_DELLINK:
	case RTM_GETLINK:
	case RTM_SETLINK:
		rtnl_print_ifinfo(hdr);
		break;
	case RTM_NEWADDR:
	case RTM_DELADDR:
	case RTM_GETADDR:
		rtnl_print_ifaddr(hdr);
		break;
	case RTM_NEWROUTE:
	case RTM_DELROUTE:
	case RTM_GETROUTE:
		rtnl_print_route(hdr);
		break;
	case RTM_NEWNEIGH:
	case RTM_DELNEIGH:
	case RTM_GETNEIGH:
		rtnl_print_neigh(hdr);
		break;
	}
}

static const char *genl_cmd2str(uint8_t table)
{
	switch (table) {
	case CTRL_CMD_UNSPEC: return "unspec";
	case CTRL_CMD_NEWFAMILY: return "new family";
	case CTRL_CMD_DELFAMILY: return "del family";
	case CTRL_CMD_GETFAMILY: return "get family";
	case CTRL_CMD_NEWOPS: return "new ops";
	case CTRL_CMD_DELOPS: return "del ops";
	case CTRL_CMD_GETOPS: return "get ops";
	case CTRL_CMD_NEWMCAST_GRP: return "new mcast group";
	case CTRL_CMD_DELMCAST_GRP: return "del mcast group";
	case CTRL_CMD_GETMCAST_GRP: return "get mcast group";

	default: return "Unknown";
	}
}

static struct flag_name genl_ops_flags[] = {
	{ "admin", GENL_ADMIN_PERM },
	{ "doit", GENL_CMD_CAP_DO },
	{ "dumpit", GENL_CMD_CAP_DUMP },
	{ "policy", GENL_CMD_CAP_HASPOL },
	{ NULL, 0 },
};

static void genl_print_ops_attr(struct nlattr *attr, uint32_t attr_len)
{
	char str[256];
	uint32_t flags;

	for (; NLA_OK(attr, attr_len); attr = NLA_NEXT(attr, attr_len)) {
		switch (attr->nla_type) {
		case CTRL_ATTR_OP_ID:
			nla_fmt_nested(attr, "Id 0x%x", NLA_UINT32(attr));
			break;

		case CTRL_ATTR_OP_FLAGS:
			flags = NLA_UINT32(attr);

			nla_fmt_nested(attr, "Flags 0x%x (%s%s%s)", flags,
			colorize_start(bold),
			flags2str(genl_ops_flags, flags, str, sizeof(str)),
			colorize_end());
			break;
		default:
			nla_fmt_nested(attr, "0x%x", attr->nla_type);
			break;
		}
	}
}

static void genl_print_ops_list(struct nlattr *attr, uint32_t attr_len)
{
	for (; NLA_OK(attr, attr_len); attr = NLA_NEXT(attr, attr_len)) {
		nla_fmt_nested_start(attr, "0x%x", attr->nla_type);
		genl_print_ops_attr(NLA_DATA(attr), NLA_LEN(attr));
		nla_fmt_nested_end();
	}
}

static void genl_print_mcast_group(struct nlattr *attr, uint32_t attr_len)
{
	for (; NLA_OK(attr, attr_len); attr = NLA_NEXT(attr, attr_len)) {
		switch (attr->nla_type) {
		case CTRL_ATTR_MCAST_GRP_ID:
			nla_fmt_nested(attr, "Id 0x%x", NLA_UINT32(attr));
			break;

		case CTRL_ATTR_MCAST_GRP_NAME:
			nla_fmt_nested(attr, "Name %s", NLA_STR(attr));
			break;
		default:
			nla_fmt_nested(attr, "0x%x", attr->nla_type);
			break;
		}
	}
}

static void genl_print_mc_groups(struct nlattr *attr, uint32_t attr_len)
{
	for (; NLA_OK(attr, attr_len); attr = NLA_NEXT(attr, attr_len)) {
		nla_fmt_nested_start(attr, "0x%x", attr->nla_type);
		genl_print_mcast_group(NLA_DATA(attr), NLA_LEN(attr));
		nla_fmt_nested_end();
	}
}

static void genl_print_ctrl_attrs(struct nlmsghdr *hdr)
{
	struct genlmsghdr *genl = NLMSG_DATA(hdr);
	struct nlattr *attr = GEN_NLA(genl);
	uint32_t attrs_len = NLMSG_PAYLOAD(hdr, sizeof(struct genlmsghdr));

	for (; NLA_OK(attr, attrs_len); attr = NLA_NEXT(attr, attrs_len)) {
		switch (attr->nla_type) {
		case CTRL_ATTR_FAMILY_ID:
			nla_fmt(attr, "Family Id 0x%x", NLA_UINT16(attr));
			break;
		case CTRL_ATTR_FAMILY_NAME:
			nla_fmt(attr, "Family Name %s", NLA_STR(attr));
			break;
		case CTRL_ATTR_VERSION:
			nla_fmt(attr, "Version %u", NLA_UINT32(attr));
			break;
		case CTRL_ATTR_HDRSIZE:
			nla_fmt(attr, "Header size %u", NLA_UINT32(attr));
			break;
		case CTRL_ATTR_MAXATTR:
			nla_fmt(attr, "Max attr value 0x%x", NLA_UINT32(attr));
			break;
		case CTRL_ATTR_OPS:
			nla_fmt(attr, "Ops list");
			genl_print_ops_list(NLA_DATA(attr), NLA_LEN(attr));
			break;
		case CTRL_ATTR_MCAST_GROUPS:
			nla_fmt(attr, "Mcast groups");
			genl_print_mc_groups(NLA_DATA(attr), NLA_LEN(attr));
			break;
		default:
			nla_fmt(attr, "0x%x", attr->nla_type);
			break;
		}
	}
}

static void genl_msg_print(struct nlmsghdr *hdr)
{
	struct genlmsghdr *genl;

	if (hdr->nlmsg_type != GENL_ID_CTRL) {
		nlmsg_print_raw(hdr);
		return;
	}

	genl = NLMSG_DATA(hdr);

	tprintf(" [ Cmd %u (%s%s%s)", genl->cmd,
		colorize_start(bold), genl_cmd2str(genl->cmd), colorize_end());
	tprintf(", Version %u", genl->version);
	tprintf(", Reserved %u", genl->reserved);
	tprintf(" ]\n");

	genl_print_ctrl_attrs(hdr);
}

static void nlmsg_print(uint16_t family, struct nlmsghdr *hdr)
{
	u16 nlmsg_flags = hdr->nlmsg_flags;
	char type[32];
	char flags[128];
	char procname[PATH_MAX];

	/* Look up the process name if message is not coming from the kernel.
	 *
	 * Note that the port id is not necessarily equal to the PID of the
	 * receiving process (e.g. if the application is multithreaded or using
	 * multiple sockets). In these cases we're not able to find a matching
	 * PID and the information will not be printed.
	 */
	if (hdr->nlmsg_pid != 0) {
		if (proc_get_cmdline(hdr->nlmsg_pid, procname, sizeof(procname)) < 0)
			snprintf(procname, sizeof(procname), "unknown process");
	} else
		snprintf(procname, sizeof(procname), "kernel");

	tprintf(" [ NLMSG ");
	tprintf("Family %d (%s%s%s), ", family,
		colorize_start(bold),
		nlmsg_family2str(family),
		colorize_end());
	tprintf("Len %u, ", hdr->nlmsg_len);
	tprintf("Type 0x%.4x (%s%s%s), ", hdr->nlmsg_type,
		colorize_start(bold),
		nlmsg_type2str(family, hdr->nlmsg_type, type, sizeof(type)),
		colorize_end());
	tprintf("Flags 0x%.4x (%s%s%s), ", nlmsg_flags,
		colorize_start(bold),
		nlmsg_flags ? nl_nlmsg_flags2str(nlmsg_flags, flags, sizeof(flags)) : "none",
		colorize_end());
	tprintf("Seq-Nr %u, ", hdr->nlmsg_seq);
	tprintf("PID %u", hdr->nlmsg_pid);
	if (procname[0])
		tprintf(" (%s%s%s)", colorize_start(bold), basename(procname),
			colorize_end());
	tprintf(" ]\n");

	switch (family) {
	case NETLINK_ROUTE:
		rtnl_msg_print(hdr);
		break;
	case NETLINK_GENERIC:
		genl_msg_print(hdr);
		break;
	default:
		nlmsg_print_raw(hdr);
	}
}

static void nlmsg(struct pkt_buff *pkt)
{
	struct nlmsghdr *hdr = (struct nlmsghdr *) pkt_pull(pkt, NLMSG_HDRLEN);
	unsigned int trim_len = pkt_len(pkt);

	while (hdr) {
		trim_len -= hdr->nlmsg_len;
		nlmsg_print(ntohs(pkt->sll->sll_protocol), hdr);

		if (!pkt_pull(pkt, NLMSG_ALIGN(hdr->nlmsg_len) - NLMSG_HDRLEN))
			break;

		hdr = (struct nlmsghdr *) pkt_pull(pkt, NLMSG_HDRLEN);
		if (hdr == NULL)
			break;
		if (hdr->nlmsg_len == 0)
			break;

		if (hdr->nlmsg_type != NLMSG_DONE &&
		    (hdr->nlmsg_flags & NLM_F_MULTI))
			tprintf("\n");
	}

	/* mmaped packet? */
	if (hdr && hdr->nlmsg_len == 0)
		pkt_trim(pkt, trim_len);
}

static void nlmsg_less(struct pkt_buff *pkt)
{
	struct nlmsghdr *hdr = (struct nlmsghdr *) pkt_pull(pkt, NLMSG_HDRLEN);
	uint16_t family = ntohs(pkt->sll->sll_protocol);
	char type[32];

	if (hdr == NULL)
		return;

	tprintf(" NLMSG Family %d (%s%s%s), ", family,
		colorize_start(bold),
		nlmsg_family2str(family),
		colorize_end());
	tprintf("Type %u (%s%s%s)", hdr->nlmsg_type,
		colorize_start(bold),
		nlmsg_type2str(family, hdr->nlmsg_type, type, sizeof(type)),
		colorize_end());
}

struct protocol nlmsg_ops = {
	.print_full = nlmsg,
	.print_less = nlmsg_less,
};

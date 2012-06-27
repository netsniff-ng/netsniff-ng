/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2012 Daniel Borkmann.
 * Subject to the GPL, version 2.
 * Parts derived from iw, subject to ISC license.
 * Copyright 2007, 2008	Johannes Berg
 * Copyright 2007 Andy Lutomirski
 * Copyright 2007 Mike Kershaw
 * Copyright 2008-2009 Luis R. Rodriguez
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <linux/nl80211.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include "die.h"
#include "xutils.h"
#include "mac80211.h"
#include "xmalloc.h"
#include "built_in.h"

#ifdef HAVE_LIBNL_2_x
# define LIBNL_FAILURE	NLE_FAILURE
# define get_nl_errmsg	nl_geterror
#else
# define LIBNL_FAILURE	ENFILE
/* libnl 2.x compatibility code */
# define nl_sock	nl_handle

static inline struct nl_handle *nl_socket_alloc(void)
{
	return nl_handle_alloc();
}

static inline void nl_socket_free(struct nl_handle *h)
{
	nl_handle_destroy(h);
}

# define get_nl_errmsg	strerror

static inline int __genl_ctrl_alloc_cache(struct nl_handle *h,
					  struct nl_cache **cache)
{
	struct nl_cache *tmp = genl_ctrl_alloc_cache(h);
	if (!tmp)
		return -ENOMEM;
	*cache = tmp;
	return 0;
}

# define genl_ctrl_alloc_cache	__genl_ctrl_alloc_cache
#endif /* !HAVE_LIBNL_2_x */

struct nl80211_state {
	struct nl_sock *nl_sock;
	struct nl_cache *nl_cache;
	struct genl_family *nl80211;
};

static void get_mac80211_phydev(const char *device, char *phydev_path,
				size_t phydev_len)
{
	int ret;
	char *pathstr;
	ssize_t num;

	ret = asprintf(&pathstr, "/sys/class/net/%s/phy80211", device);
	if (ret < 0)
		panic("Can't generate path name string for /sys/class/net device");

	num = readlink(pathstr, phydev_path, phydev_len);
	if (num < 0) {
		if (errno == ENOENT || errno == EINVAL)
			panic("It's probably not a mac80211 device!\n");
		panic("Can't readlink %s: %s!\n", pathstr, strerror(errno));
	}

	xfree(pathstr);
	phydev_path[min(num, phydev_len - 1)] = 0;
}

static inline struct nl_msg *nl80211_nlmsg_xalloc(void)
{
	struct nl_msg *ret = nlmsg_alloc();
	if (!ret)
		panic("Cannot allocate nlmsg memory!\n");
	return ret;
}

static inline struct nl_handle *nl80211_nl_socket_xalloc(void)
{
	struct nl_handle *ret = nl_socket_alloc();
	if (!ret)
		panic("Cannot allocate nl socket memory!\n");
	return ret;
}

static void nl80211_init(struct nl80211_state *state, const char *device)
{
	int ret;

	state->nl_sock = nl80211_nl_socket_xalloc();

	ret = genl_connect(state->nl_sock);
	if (ret)
		panic("Cannot connect generic netlink!\n");

	ret = genl_ctrl_alloc_cache(state->nl_sock, &state->nl_cache);
	if (ret < 0)
		panic("Failed to allocate generic netlink cache: %s!",
		      get_nl_errmsg(-ret));

	state->nl80211 = genl_ctrl_search_by_name(state->nl_cache, "nl80211");
	if (!state->nl80211)
		panic("nl80211 not found in netlink cache!\n");
}

static void nl80211_cleanup(struct nl80211_state *state)
{
	genl_family_put(state->nl80211);

	nl_cache_free(state->nl_cache);
	nl_socket_free(state->nl_sock);
}

static int nl80211_add_mon_if(struct nl80211_state *state, const char *device,
			      const char *mondevice)
{
	int ifindex, ret;
	struct nl_msg *msg;

	ifindex = device_ifindex(device);

	msg = nl80211_nlmsg_xalloc();

	genlmsg_put(msg, 0, 0, genl_family_get_id(state->nl80211), 0,
		    0, NL80211_CMD_NEW_INTERFACE, 0);

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifindex);
	NLA_PUT_STRING(msg, NL80211_ATTR_IFNAME, mondevice);
	NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);

	ret = nl_send_auto_complete(state->nl_sock, msg);
	if (ret < 0) {
		if (ret == -LIBNL_FAILURE) {
			nlmsg_free(msg);
			return -EBUSY;
		}

		panic("Cannot send_auto_complete!\n");
	}

	ret = nl_wait_for_ack(state->nl_sock);
	if (ret < 0) {
		if (ret == -LIBNL_FAILURE) {
			nlmsg_free(msg);
			return -EBUSY;
		}

		panic("Waiting for netlink ack failed!\n");
	}

	nlmsg_free(msg);
	return 0;

nla_put_failure:
	panic("nla put failure!\n");
	return -EIO; /* dummy */
}

static int nl80211_del_mon_if(struct nl80211_state *state, const char *device,
			      const char *mondevice)
{
	int ifindex, ret;
	struct nl_msg *msg;

	ifindex = device_ifindex(mondevice);

	msg = nl80211_nlmsg_xalloc();

	genlmsg_put(msg, 0, 0, genl_family_get_id(state->nl80211), 0,
		    0, NL80211_CMD_DEL_INTERFACE, 0);

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifindex);

	ret = nl_send_auto_complete(state->nl_sock, msg);
	if (ret < 0)
		panic("Cannot send_auto_complete!\n");

	ret = nl_wait_for_ack(state->nl_sock);
	if (ret < 0)
		panic("Waiting for netlink ack failed!\n");

	nlmsg_free(msg);
	return 0;

nla_put_failure:
	panic("nla put failure!\n");
	return -EIO; /* dummy */
}

void enter_rfmon_mac80211(const char *device, char **mondev)
{
	int ret;
	short flags;
	uint32_t n;
	char phydev_path[256];
	struct nl80211_state nlstate;

	/* XXX: is this already a monN device? */
	get_mac80211_phydev(device, phydev_path, sizeof(phydev_path));
	nl80211_init(&nlstate, device);

	for (n = 0; n < UINT_MAX; n++) {
		char mondevice[32];

		slprintf(mondevice, sizeof(mondevice), "mon%u", n);
		ret = nl80211_add_mon_if(&nlstate, device, mondevice);
		if (ret == 0) {
			*mondev = xstrdup(mondevice);

			flags = device_get_flags(*mondev);
			flags |= IFF_UP | IFF_RUNNING;
			device_set_flags(*mondev, flags);

			nl80211_cleanup(&nlstate);
			return;
		}
	}

	panic("No free monN interfaces!\n");
}

void leave_rfmon_mac80211(const char *device, const char *mondev)
{
	short flags;
	struct nl80211_state nlstate;

	flags = device_get_flags(mondev);
	flags &= ~(IFF_UP | IFF_RUNNING);
	device_set_flags(mondev, flags);

	nl80211_init(&nlstate, device);
	nl80211_del_mon_if(&nlstate, device, mondev);
	nl80211_cleanup(&nlstate);
}

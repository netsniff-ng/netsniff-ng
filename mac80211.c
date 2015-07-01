/*
 * netsniff-ng - the packet sniffing beast
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
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/nl80211.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include "die.h"
#include "str.h"
#include "dev.h"
#include "mac80211.h"
#include "xmalloc.h"
#include "built_in.h"

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
	phydev_path[min_t(size_t, num, phydev_len - 1)] = 0;
}

static inline struct nl_msg *nl80211_nlmsg_xalloc(void)
{
	struct nl_msg *ret = nlmsg_alloc();
	if (!ret)
		panic("Cannot allocate nlmsg memory!\n");
	return ret;
}

static inline struct nl_sock *nl80211_nl_socket_xalloc(void)
{
	struct nl_sock *ret = nl_socket_alloc();
	if (!ret)
		panic("Cannot allocate nl socket memory!\n");
	return ret;
}

static void nl80211_init(struct nl80211_state *state)
{
	int ret;

	state->nl_sock = nl80211_nl_socket_xalloc();

	ret = genl_connect(state->nl_sock);
	if (ret)
		panic("Cannot connect generic netlink!\n");

	ret = genl_ctrl_alloc_cache(state->nl_sock, &state->nl_cache);
	if (ret < 0)
		panic("Failed to allocate generic netlink cache: %s!",
		      nl_geterror(-ret));

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

static int nl80211_wait_handler(struct nl_msg *msg __maybe_unused, void *arg)
{
	int *finished = arg;

	*finished = 1;

	return NL_STOP;
}

static int nl80211_error_handler(struct sockaddr_nl *nla __maybe_unused,
				 struct nlmsgerr *err,
				 void *arg __maybe_unused)
{
	panic("nl80211 returned with error (%d): %s\n", err->error,
	      nl_geterror(err->error));
}

static int nl80211_add_mon_if(struct nl80211_state *state, const char *device,
			      const char *mondevice)
{
	int ifindex, ret;
	struct nl_msg *msg;
	struct nl_cb *cb = NULL;
	int finished = 0;

	ifindex = device_ifindex(device);

	msg = nl80211_nlmsg_xalloc();

	genlmsg_put(msg, 0, 0, genl_family_get_id(state->nl80211), 0,
		    0, NL80211_CMD_NEW_INTERFACE, 0);

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifindex);
	NLA_PUT_STRING(msg, NL80211_ATTR_IFNAME, mondevice);
	NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);

	ret = nl_send_auto_complete(state->nl_sock, msg);
	if (ret < 0) {
		if (ret == -ENFILE) {
			nlmsg_free(msg);
			return -EBUSY;
		}

		panic("Cannot send_auto_complete!\n");
	}

	cb = nl_cb_alloc(NL_CB_CUSTOM);
	if (!cb)
		panic("Cannot alloc nl_cb!\n");

	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, nl80211_wait_handler, &finished);
	nl_cb_err(cb, NL_CB_CUSTOM, nl80211_error_handler, NULL);

	nl_recvmsgs(state->nl_sock, cb);

	if (!finished) {
		ret = nl_wait_for_ack(state->nl_sock);
		if (ret < 0) {
			if (ret == -ENFILE) {
				nlmsg_free(msg);
				return -EBUSY;
			}

			panic("Waiting for netlink ack failed!\n");
		}
	}

	nl_cb_put(cb);
	nlmsg_free(msg);
	return 0;

nla_put_failure:
	panic("nla put failure!\n");
	return -EIO; /* dummy */
}

static int nl80211_del_mon_if(struct nl80211_state *state,
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
	nl80211_init(&nlstate);

	for (n = 0; n < UINT_MAX; n++) {
		char mondevice[32];

		slprintf(mondevice, sizeof(mondevice), "mon%u", n);

		if (__device_ifindex(mondevice) > 0)
			continue;

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

void leave_rfmon_mac80211(const char *mondev)
{
	short flags;
	struct nl80211_state nlstate;

	flags = device_get_flags(mondev);
	flags &= ~(IFF_UP | IFF_RUNNING);
	device_set_flags(mondev, flags);

	nl80211_init(&nlstate);
	nl80211_del_mon_if(&nlstate, mondev);
	nl80211_cleanup(&nlstate);
}

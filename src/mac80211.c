/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2012 Daniel Borkmann.
 * Subject to the GPL, version 2.
 * Parts derived from iw, ISC license:
 * Copyright 2007, 2008	Johannes Berg
 * Copyright 2007 Andy Lutomirski
 * Copyright 2007 Mike Kershaw
 * Copyright 2008-2009 Luis R. Rodriguez
 */

#include <errno.h>
#include <string.h>
#include <linux/nl80211.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include "die.h"

#ifdef HAVE_LIBNL_2_x
# define get_nl_errmsg	nl_geterror
#else
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

static void nl80211_init(struct nl80211_state *state, const char *device)
{
	int ret;

	state->nl_sock = nl_socket_alloc();
	if (!state->nl_sock)
		panic("Failed to allocate netlink handle!\n");

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

#if 0
static int nl80211_add_mon_if(int sock, struct nl80211_state *state,
			      const char *device, const char *mondevice)
{
	int ifindex;
	struct nl_msg *msg;
	int err;

	ifindex = iface_get_id(sock_fd, device, handle->errbuf);
	if (ifindex == -1)
		return PCAP_ERROR;

	msg = nlmsg_alloc();
	if (!msg) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
		    "%s: failed to allocate netlink msg", device);
		return PCAP_ERROR;
	}

	genlmsg_put(msg, 0, 0, genl_family_get_id(state->nl80211), 0,
		    0, NL80211_CMD_NEW_INTERFACE, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifindex);
	NLA_PUT_STRING(msg, NL80211_ATTR_IFNAME, mondevice);
	NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);

	err = nl_send_auto_complete(state->nl_sock, msg);
	if (err < 0) {
#ifdef HAVE_LIBNL_2_x
		if (err == -NLE_FAILURE) {
#else
		if (err == -ENFILE) {
#endif
			/*
			 * Device not available; our caller should just
			 * keep trying.  (libnl 2.x maps ENFILE to
			 * NLE_FAILURE; it can also map other errors
			 * to that, but there's not much we can do
			 * about that.)
			 */
			nlmsg_free(msg);
			return 0;
		} else {
			/*
			 * Real failure, not just "that device is not
			 * available.
			 */
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			    "%s: nl_send_auto_complete failed adding %s interface: %s",
			    device, mondevice, get_nl_errmsg(-err));
			nlmsg_free(msg);
			return PCAP_ERROR;
		}
	}
	err = nl_wait_for_ack(state->nl_sock);
	if (err < 0) {
#ifdef HAVE_LIBNL_2_x
		if (err == -NLE_FAILURE) {
#else
		if (err == -ENFILE) {
#endif
			/*
			 * Device not available; our caller should just
			 * keep trying.  (libnl 2.x maps ENFILE to
			 * NLE_FAILURE; it can also map other errors
			 * to that, but there's not much we can do
			 * about that.)
			 */
			nlmsg_free(msg);
			return 0;
		} else {
			/*
			 * Real failure, not just "that device is not
			 * available.
			 */
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			    "%s: nl_wait_for_ack failed adding %s interface: %s",
			    device, mondevice, get_nl_errmsg(-err));
			nlmsg_free(msg);
			return PCAP_ERROR;
		}
	}

	/*
	 * Success.
	 */
	nlmsg_free(msg);
	return 1;

nla_put_failure:
	snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
	    "%s: nl_put failed adding %s interface",
	    device, mondevice);
	nlmsg_free(msg);
	return PCAP_ERROR;
}

static int
del_mon_if(pcap_t *handle, int sock_fd, struct nl80211_state *state,
    const char *device, const char *mondevice)
{
	int ifindex;
	struct nl_msg *msg;
	int err;

	ifindex = iface_get_id(sock_fd, mondevice, handle->errbuf);
	if (ifindex == -1)
		return PCAP_ERROR;

	msg = nlmsg_alloc();
	if (!msg) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
		    "%s: failed to allocate netlink msg", device);
		return PCAP_ERROR;
	}

	genlmsg_put(msg, 0, 0, genl_family_get_id(state->nl80211), 0,
		    0, NL80211_CMD_DEL_INTERFACE, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, ifindex);

	err = nl_send_auto_complete(state->nl_sock, msg);
	if (err < 0) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
		    "%s: nl_send_auto_complete failed deleting %s interface: %s",
		    device, mondevice, get_nl_errmsg(-err));
		nlmsg_free(msg);
		return PCAP_ERROR;
	}
	err = nl_wait_for_ack(state->nl_sock);
	if (err < 0) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
		    "%s: nl_wait_for_ack failed adding %s interface: %s",
		    device, mondevice, get_nl_errmsg(-err));
		nlmsg_free(msg);
		return PCAP_ERROR;
	}

	/*
	 * Success.
	 */
	nlmsg_free(msg);
	return 1;

nla_put_failure:
	snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
	    "%s: nl_put failed deleting %s interface",
	    device, mondevice);
	nlmsg_free(msg);
	return PCAP_ERROR;
}
#endif

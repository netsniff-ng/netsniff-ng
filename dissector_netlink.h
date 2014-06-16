/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2014 Tobias Klauser.
 * Subject to the GPL, version 2.
 */

#ifndef DISSECTOR_NETLINK_H
#define DISSECTOR_NETLINK_H

#include "protos.h"

extern void dissector_init_netlink(int fnttype);
extern void dissector_cleanup_netlink(void);

static inline struct protocol *dissector_get_netlink_entry_point(void)
{
	return &nlmsg_ops;
}

static inline struct protocol *dissector_get_netlink_exit_point(void)
{
	return &none_ops;
}

#endif /* DISSECTOR_NETLINK_H */

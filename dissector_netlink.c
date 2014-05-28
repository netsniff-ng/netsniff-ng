/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2014 Tobias Klauser.
 * Subject to the GPL, version 2.
 */

#include "dissector.h"
#include "dissector_netlink.h"

#ifdef HAVE_DISSECTOR_PROTOS
static inline void dissector_init_entry(int type)
{
	dissector_set_print_type(&nlmsg_ops, type);
}

static inline void dissector_init_exit(int type)
{
	dissector_set_print_type(&none_ops, type);
}
#else
static inline void dissector_init_entry(int type __maybe_unused) {}
static inline void dissector_init_exit(int type __maybe_unused) {}
#endif

void dissector_init_netlink(int fnttype)
{
	dissector_init_entry(fnttype);
	dissector_init_exit(fnttype);
}

void dissector_cleanup_netlink(void)
{
}

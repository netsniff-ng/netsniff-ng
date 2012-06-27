/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef DISSECTOR_ETH_H
#define DISSECTOR_ETH_H

#include "hash.h"
#include "proto.h"
#include "protos.h"
#include "tprintf.h"
#include "xutils.h"
#include "oui.h"

extern struct hash_table eth_lay2;
extern struct hash_table eth_lay3;

extern void dissector_init_ethernet(int fnttype);
extern void dissector_cleanup_ethernet(void);

extern char *lookup_port_udp(unsigned int id);
extern char *lookup_port_tcp(unsigned int id);
extern char *lookup_ether_type(unsigned int id);

#ifdef __WITH_PROTOS
static inline struct protocol *dissector_get_ethernet_entry_point(void)
{
	return &ethernet_ops;
}

static inline struct protocol *dissector_get_ethernet_exit_point(void)
{
	return &none_ops;
}
#else
static inline struct protocol *dissector_get_ethernet_entry_point(void)
{
	return NULL;
}

static inline struct protocol *dissector_get_ethernet_exit_point(void)
{
	return NULL;
}
#endif /* __WITH_PROTOS */
#endif /* DISSECTOR_ETH_H */

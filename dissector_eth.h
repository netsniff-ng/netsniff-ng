/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef DISSECTOR_ETH_H
#define DISSECTOR_ETH_H

#include "hash.h"
#include "protos.h"

extern struct hash_table eth_lay2;
extern struct hash_table eth_lay3;

extern void dissector_init_ethernet(int fnttype);
extern void dissector_cleanup_ethernet(void);

static inline struct protocol *dissector_get_ethernet_entry_point(void)
{
	return &ethernet_ops;
}

static inline struct protocol *dissector_get_ethernet_exit_point(void)
{
	return &none_ops;
}

#endif /* DISSECTOR_ETH_H */

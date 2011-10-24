/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef DISSECTOR_ETHERNET_H
#define DISSECTOR_ETHERNET_H

#include "hash.h"
#include "protos/proto_struct.h"
#include "tprintf.h"
#include "tty.h"

extern struct hash_table eth_lay2;
extern struct hash_table eth_lay3;
extern struct hash_table eth_lay4;

extern void dissector_init_ethernet(int fnttype);
extern void dissector_cleanup_ethernet(void);

extern char *lookup_vendor(unsigned int id);
extern char *lookup_port_udp(unsigned int id);
extern char *lookup_port_tcp(unsigned int id);
extern char *lookup_ether_type(unsigned int id);

extern struct protocol ethernet_ops;
extern struct protocol hex_ops;

static inline struct protocol *dissector_get_ethernet_entry_point(void)
{
	return &ethernet_ops;
}

static inline struct protocol *dissector_get_ethernet_exit_point(void)
{
	return &hex_ops;
}

#endif /* DISSECTOR_ETHERNET_H */

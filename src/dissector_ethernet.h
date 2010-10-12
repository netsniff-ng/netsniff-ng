/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef DISSECTOR_ETHERNET_H
#define DISSECTOR_ETHERNET_H

#include "hash.h"
#include "protos/proto_struct.h"
#include "tprintf.h"
#include "tty.h"

extern struct hash_table ethernet_level2;
extern struct hash_table ethernet_level3;
extern struct hash_table ethernet_level4;

extern struct hash_table ethernet_ether_types;
extern struct hash_table ethernet_ports_udp;
extern struct hash_table ethernet_ports_tcp;
extern struct hash_table ethernet_oui;

extern void dissector_init_ethernet(int fnttype);
extern struct protocol *dissector_get_ethernet_entry_point(void);
extern struct protocol *dissector_get_ethernet_exit_point(void);
extern void dissector_cleanup_ethernet(void);

extern char *lookup_vendor(unsigned int id);
extern char *lookup_port_udp(unsigned int id);
extern char *lookup_port_tcp(unsigned int id);
extern char *lookup_ether_type(unsigned int id);

#endif /* DISSECTOR_ETHERNET_H */

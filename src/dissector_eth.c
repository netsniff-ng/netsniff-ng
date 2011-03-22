/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

#include <stdint.h>

#include "hash.h"
#include "protos.h"
#include "dissector.h"
#include "dissector_eth.h"
#define __DATA__
#include "oui.h"
#include "ports_udp.h"
#include "ports_tcp.h"
#include "ether_types.h"
#undef __DATA__

/* The entry proto to jump into */
#define DISSECTOR_ETHERNET_ENTRY_OPS ethernet_ops
/* The exit proto to jump into */
#define DISSECTOR_ETHERNET_EXIT_OPS hex_ops

/* We call this level since level != layer */
struct hash_table ethernet_level2;
struct hash_table ethernet_level3;
struct hash_table ethernet_level4;

struct hash_table ethernet_ether_types;
struct hash_table ethernet_ports_udp;
struct hash_table ethernet_ports_tcp;
struct hash_table ethernet_oui;

char *lookup_vendor(unsigned int id)
{
	struct vendor_id *entry = lookup_hash(id, &ethernet_oui);
	while (entry && id != entry->id)
		entry = entry->next;
	return (entry && id == entry->id ? entry->vendor : "Unknown");
}

char *lookup_port_udp(unsigned int id)
{
	struct port_udp *entry = lookup_hash(id, &ethernet_ports_udp);
	while (entry && id != entry->id)
		entry = entry->next;
	return (entry && id == entry->id ? entry->port : "Unknown");
}

char *lookup_port_tcp(unsigned int id)
{
	struct port_tcp *entry = lookup_hash(id, &ethernet_ports_tcp);
	while (entry && id != entry->id)
		entry = entry->next;
	return (entry && id == entry->id ? entry->port : "Unknown");
}

char *lookup_ether_type(unsigned int id)
{
	struct ether_type *entry = lookup_hash(id, &ethernet_ether_types);
	while (entry && id != entry->id)
		entry = entry->next;
	return (entry && id == entry->id ? entry->type : "Unknown");
}

static inline void dissector_init_entry(int (*fnt)(void *ptr))
{
	fnt(&DISSECTOR_ETHERNET_ENTRY_OPS);
}

static inline void dissector_init_exit(int (*fnt)(void *ptr))
{
	fnt(&DISSECTOR_ETHERNET_EXIT_OPS);
}

static inline void dissector_init_level2(int (*fnt)(void *ptr))
{
	init_hash(&ethernet_level2);
	INSERT_HASH_PROTOS(arp_ops, ethernet_level2);
	INSERT_HASH_PROTOS(vlan_ops, ethernet_level2);
	INSERT_HASH_PROTOS(ipv4_ops, ethernet_level2);
	INSERT_HASH_PROTOS(ipv6_ops, ethernet_level2);
	for_each_hash(&ethernet_level2, fnt);
}

static inline void dissector_init_level3(int (*fnt)(void *ptr))
{
	init_hash(&ethernet_level3);
	INSERT_HASH_PROTOS(icmp_ops, ethernet_level3);
	INSERT_HASH_PROTOS(udp_ops, ethernet_level3);
	INSERT_HASH_PROTOS(tcp_ops, ethernet_level3);
	for_each_hash(&ethernet_level3, fnt);
}

static inline void dissector_init_level4(int (*fnt)(void *ptr))
{
	init_hash(&ethernet_level4);
	for_each_hash(&ethernet_level4, fnt);
}

inline struct protocol *dissector_get_ethernet_entry_point(void)
{
	return &DISSECTOR_ETHERNET_ENTRY_OPS;
}

inline struct protocol *dissector_get_ethernet_exit_point(void)
{
	return &DISSECTOR_ETHERNET_EXIT_OPS;
}

static inline void dissector_init_oui(void)
{
	void **pos;
	size_t i, len = sizeof(vendor_db) / sizeof(struct vendor_id);

	init_hash(&ethernet_oui);
	for (i = 0; i < len; ++i) {
		pos = insert_hash(vendor_db[i].id, &vendor_db[i],
				  &ethernet_oui);
		if (pos) {
			vendor_db[i].next = *pos;
			*pos = &vendor_db[i];
		}
	}
}

static inline void dissector_init_ports_udp(void)
{
	void **pos;
	size_t i, len = sizeof(ports_udp) / sizeof(struct port_udp);

	init_hash(&ethernet_ports_udp);
	for (i = 0; i < len; ++i) {
		pos = insert_hash(ports_udp[i].id, &ports_udp[i],
				  &ethernet_ports_udp);
		if (pos) {
			ports_udp[i].next = *pos;
			*pos = &ports_udp[i];
		}
	}
}

static inline void dissector_init_ports_tcp(void)
{
	void **pos;
	size_t i, len = sizeof(ports_tcp) / sizeof(struct port_tcp);

	init_hash(&ethernet_ports_tcp);
	for (i = 0; i < len; ++i) {
		pos = insert_hash(ports_tcp[i].id, &ports_tcp[i],
				  &ethernet_ports_tcp);
		if (pos) {
			ports_tcp[i].next = *pos;
			*pos = &ports_tcp[i];
		}
	}
}

static inline void dissector_init_ether_types(void)
{
	void **pos;
	size_t i, len = sizeof(ether_types) / sizeof(struct ether_type);

	init_hash(&ethernet_ether_types);
	for (i = 0; i < len; ++i) {
		pos = insert_hash(ether_types[i].id, &ether_types[i],
				  &ethernet_ether_types);
		if (pos) {
			ether_types[i].next = *pos;
			*pos = &ether_types[i];
		}
	}
}

void dissector_init_ethernet(int fnttype)
{
	int (*fnt)(void *ptr) = NULL;

	switch (fnttype) {
	case FNTTYPE_PRINT_NORM:
		fnt = dissector_set_print_norm;
		break;
	case FNTTYPE_PRINT_LESS:
		fnt = dissector_set_print_less;
		break;
	case FNTTYPE_PRINT_HEX1:
	case FNTTYPE_PRINT_HEX2:
	case FNTTYPE_PRINT_CHR1:
	case FNTTYPE_PRINT_NOPA:
	case FNTTYPE_PRINT_PAAC:
	case FNTTYPE_PRINT_REGX:
	default:
	case FNTTYPE_PRINT_NONE:
		fnt = dissector_set_print_none;
		break;
	};

	dissector_init_entry(fnt);
	dissector_init_level2(fnt);
	dissector_init_level3(fnt);
	dissector_init_level4(fnt);
	dissector_init_exit(fnt);

	dissector_init_oui();
	dissector_init_ports_udp();
	dissector_init_ports_tcp();
	dissector_init_ether_types();
}

void dissector_cleanup_ethernet(void)
{
	free_hash(&ethernet_level2);
	free_hash(&ethernet_level3);
	free_hash(&ethernet_level4);

	free_hash(&ethernet_ether_types);
	free_hash(&ethernet_ports_udp);
	free_hash(&ethernet_ports_tcp);
	free_hash(&ethernet_oui);
}

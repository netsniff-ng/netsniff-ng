/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdint.h>

#include "hash.h"
#include "oui.h"
#include "str.h"
#include "proto.h"
#include "protos.h"
#include "dissector.h"
#include "dissector_eth.h"
#include "xmalloc.h"

struct hash_table eth_lay2;
struct hash_table eth_lay3;

static struct hash_table eth_ether_types;
static struct hash_table eth_ports_udp;
static struct hash_table eth_ports_tcp;

struct port {
	unsigned int id;
	char *port;
	struct port *next;
};

#define __do_lookup_inline(id, struct_name, hash_ptr, struct_member)	\
	({								\
		struct struct_name *entry = lookup_hash(id, hash_ptr);	\
									\
		while (entry && id != entry->id)			\
			entry = entry->next;				\
									\
		(entry && id == entry->id ? entry->struct_member : NULL); \
	})

char *lookup_port_udp(unsigned int id)
{
	return __do_lookup_inline(id, port, &eth_ports_udp, port);
}

char *lookup_port_tcp(unsigned int id)
{
	return __do_lookup_inline(id, port, &eth_ports_tcp, port);
}

char *lookup_ether_type(unsigned int id)
{
	return __do_lookup_inline(id, port, &eth_ether_types, port);
}

#ifdef HAVE_DISSECTOR_PROTOS
static inline void dissector_init_entry(int type)
{
	dissector_set_print_type(&ethernet_ops, type);
}

static inline void dissector_init_exit(int type)
{
	dissector_set_print_type(&none_ops, type);
}

static void dissector_init_layer_2(int type)
{
	init_hash(&eth_lay2);
	INSERT_HASH_PROTOS(arp_ops, eth_lay2);
	INSERT_HASH_PROTOS(lldp_ops, eth_lay2);
	INSERT_HASH_PROTOS(vlan_ops, eth_lay2);
	INSERT_HASH_PROTOS(ipv4_ops, eth_lay2);
	INSERT_HASH_PROTOS(ipv6_ops, eth_lay2);
	INSERT_HASH_PROTOS(QinQ_ops, eth_lay2);
	INSERT_HASH_PROTOS(mpls_uc_ops, eth_lay2);
	for_each_hash_int(&eth_lay2, dissector_set_print_type, type);
}

static void dissector_init_layer_3(int type)
{
	init_hash(&eth_lay3);
	INSERT_HASH_PROTOS(icmpv4_ops, eth_lay3);
	INSERT_HASH_PROTOS(icmpv6_ops, eth_lay3);
	INSERT_HASH_PROTOS(igmp_ops, eth_lay3);
	INSERT_HASH_PROTOS(ip_auth_ops, eth_lay3);
	INSERT_HASH_PROTOS(ip_esp_ops, eth_lay3);
	INSERT_HASH_PROTOS(ipv6_dest_opts_ops, eth_lay3);
	INSERT_HASH_PROTOS(ipv6_fragm_ops, eth_lay3);
	INSERT_HASH_PROTOS(ipv6_hop_by_hop_ops, eth_lay3);
	INSERT_HASH_PROTOS(ipv6_in_ipv4_ops, eth_lay3);
	INSERT_HASH_PROTOS(ipv6_mobility_ops, eth_lay3);
	INSERT_HASH_PROTOS(ipv6_no_next_header_ops, eth_lay3);
	INSERT_HASH_PROTOS(ipv6_routing_ops, eth_lay3);
	INSERT_HASH_PROTOS(tcp_ops, eth_lay3);
	INSERT_HASH_PROTOS(udp_ops, eth_lay3);
	for_each_hash_int(&eth_lay3, dissector_set_print_type, type);
}
#else
static inline void dissector_init_entry(int type __maybe_unused) {}
static inline void dissector_init_exit(int type __maybe_unused) {}
static void dissector_init_layer_2(int type __maybe_unused) {}
static void dissector_init_layer_3(int type __maybe_unused) {}
#endif

enum ports {
	PORTS_UDP,
	PORTS_TCP,
	PORTS_ETHER,
};

static void dissector_init_ports(enum ports which)
{
	FILE *fp;
	char buff[128], *ptr, *file, *end;
	struct hash_table *table;
	struct port *p;
	void **pos;

	switch (which) {
	case PORTS_UDP:
		file = ETCDIRE_STRING "/udp.conf";
		table = &eth_ports_udp;
		break;
	case PORTS_TCP:
		file = ETCDIRE_STRING "/tcp.conf";
		table = &eth_ports_tcp;
		break;
	case PORTS_ETHER:
		file = ETCDIRE_STRING "/ether.conf";
		table = &eth_ether_types;
		break;
	default:
		bug();
	}

	fp = fopen(file, "r");
	if (!fp)
		panic("No %s found!\n", file);

	memset(buff, 0, sizeof(buff));

	while (fgets(buff, sizeof(buff), fp) != NULL) {
		buff[sizeof(buff) - 1] = 0;
		ptr = buff;

		p = xmalloc(sizeof(*p));
		p->id = strtol(ptr, &end, 0);
		/* not a valid line, skip */
		if (p->id == 0 && end == ptr) {
			xfree(p);
			continue;
		}

		ptr = strstr(buff, ", ");
		/* likewise */
		if (!ptr) {
			xfree(p);
			continue;
		}

		ptr += strlen(", ");
		ptr = strtrim_right(ptr, '\n');
		ptr = strtrim_right(ptr, ' ');

		p->port = xstrdup(ptr);
		p->next = NULL;

		pos = insert_hash(p->id, p, table);
		if (pos) {
			p->next = *pos;
			*pos = p;
		}

		memset(buff, 0, sizeof(buff));
	}

	fclose(fp);
}

static int dissector_cleanup_ports(void *ptr)
{
	struct port *tmp, *p = ptr;

	if (!ptr)
		return 0;

	while ((tmp = p->next)) {
		xfree(p->port);
		xfree(p);
		p = tmp;
	}

	xfree(p->port);
	xfree(p);

	return 0;
}

void dissector_init_ethernet(int fnttype)
{
	dissector_init_entry(fnttype);
	dissector_init_layer_2(fnttype);
	dissector_init_layer_3(fnttype);
	dissector_init_exit(fnttype);

#ifdef __WITH_PROTOS
	dissector_init_oui();
#endif
	dissector_init_ports(PORTS_UDP);
	dissector_init_ports(PORTS_TCP);
	dissector_init_ports(PORTS_ETHER);
}

void dissector_cleanup_ethernet(void)
{
	free_hash(&eth_lay2);
	free_hash(&eth_lay3);

	for_each_hash(&eth_ether_types, dissector_cleanup_ports);
	for_each_hash(&eth_ports_udp, dissector_cleanup_ports);
	for_each_hash(&eth_ports_tcp, dissector_cleanup_ports);

	free_hash(&eth_ether_types);
	free_hash(&eth_ports_udp);
	free_hash(&eth_ports_tcp);

#ifdef __WITH_PROTOS
	dissector_cleanup_oui();
#endif
}

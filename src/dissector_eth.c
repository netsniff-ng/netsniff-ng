/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdint.h>

#include "hash.h"
#include "protos.h"
#include "pkt_buff.h"
#include "dissector.h"
#include "dissector_eth.h"
#include "xmalloc.h"
#include "xstring.h"

struct hash_table eth_lay2;
struct hash_table eth_lay3;
struct hash_table eth_lay4;

static struct hash_table eth_ether_types;
static struct hash_table eth_ports_udp;
static struct hash_table eth_ports_tcp;
static struct hash_table eth_oui;

struct vendor_id {
	unsigned int id;
	char *vendor;
	struct vendor_id *next;
};

struct port_tcp {
	unsigned int id;
	char *port;
	struct port_tcp *next;
};

struct port_udp {
	unsigned int id;
	char *port;
	struct port_udp *next;
};

struct ether_type {
	unsigned int id;
	char *type;
	struct ether_type *next;
};

/* Note: this macro only applies to the lookup_* functions here in this file,
 * mainly to remove redundand code. */
#define __do_lookup_inline(id, struct_name, hash_ptr, struct_member)	      \
	({								      \
		struct struct_name *entry = lookup_hash(id, hash_ptr);	      \
		while (entry && id != entry->id)			      \
			entry = entry->next;				      \
		(entry && id == entry->id ? entry->struct_member : "Unknown");\
	})

char *lookup_vendor(unsigned int id)
{
	return __do_lookup_inline(id, vendor_id, &eth_oui, vendor);
}

char *lookup_port_udp(unsigned int id)
{
	return __do_lookup_inline(id, port_udp, &eth_ports_udp, port);
}

char *lookup_port_tcp(unsigned int id)
{
	return __do_lookup_inline(id, port_tcp, &eth_ports_tcp, port);
}

char *lookup_ether_type(unsigned int id)
{
	return __do_lookup_inline(id, ether_type, &eth_ether_types, type);
}

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
	INSERT_HASH_PROTOS(vlan_ops, eth_lay2);
	INSERT_HASH_PROTOS(ipv4_ops, eth_lay2);
	INSERT_HASH_PROTOS(ipv6_ops, eth_lay2);
	for_each_hash_int(&eth_lay2, dissector_set_print_type, type);
}

static void dissector_init_layer_3(int type)
{
	init_hash(&eth_lay3);
	INSERT_HASH_PROTOS(icmp_ops, eth_lay3);
	INSERT_HASH_PROTOS(icmpv6_ops, eth_lay3);
	INSERT_HASH_PROTOS(igmp_ops, eth_lay3);
	INSERT_HASH_PROTOS(ip_auth_hdr_ops, eth_lay3);
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

static void dissector_init_layer_4(int type)
{
	init_hash(&eth_lay4);
	for_each_hash_int(&eth_lay4, dissector_set_print_type, type);
}

static void dissector_init_oui(void)
{
	FILE *fp;
	char buff[512], *ptr;
	struct vendor_id *ven;
	void **pos;
	fp = fopen("/etc/netsniff-ng/oui.conf", "r");
	if (!fp)
		panic("No /etc/netsniff-ng/oui.conf found!\n");
	memset(buff, 0, sizeof(buff));
	while (fgets(buff, sizeof(buff), fp) != NULL) {
		buff[sizeof(buff) - 1] = 0;
		ven = xmalloc(sizeof(*ven));
		ptr = buff;
		ptr = skips(ptr);
		ptr = getuint(ptr, &ven->id);
		ptr = skips(ptr);
		ptr = skipchar(ptr, ',');
		ptr = skips(ptr);
		ptr = strtrim_right(ptr, '\n');
		ptr = strtrim_right(ptr, ' ');
		ven->vendor = xstrdup(ptr);
		ven->next = NULL;
		pos = insert_hash(ven->id, ven, &eth_oui);
		if (pos) {
			ven->next = *pos;
			*pos = ven;
		}
		memset(buff, 0, sizeof(buff));
	}
	fclose(fp);
}

static int dissector_cleanup_oui(void *ptr)
{
	struct vendor_id *tmp, *v = ptr;
	if (!ptr)
		return 0;
	while ((tmp = v->next)) {
		xfree(v->vendor);
		xfree(v);
		v = tmp;
	}
	xfree(v->vendor);
	xfree(v);
	return 0;
}

static void dissector_init_ports_udp(void)
{
	FILE *fp;
	char buff[512], *ptr;
	struct port_udp *pudp;
	void **pos;
	fp = fopen("/etc/netsniff-ng/udp.conf", "r");
	if (!fp)
		panic("No /etc/netsniff-ng/udp.conf found!\n");
	memset(buff, 0, sizeof(buff));
	while (fgets(buff, sizeof(buff), fp) != NULL) {
		buff[sizeof(buff) - 1] = 0;
		pudp = xmalloc(sizeof(*pudp));
		ptr = buff;
		ptr = skips(ptr);
		ptr = getuint(ptr, &pudp->id);
		ptr = skips(ptr);
		ptr = skipchar(ptr, ',');
		ptr = skips(ptr);
		ptr = strtrim_right(ptr, '\n');
		ptr = strtrim_right(ptr, ' ');
		pudp->port = xstrdup(ptr);
		pudp->next = NULL;
		pos = insert_hash(pudp->id, pudp, &eth_ports_udp);
		if (pos) {
			pudp->next = *pos;
			*pos = pudp;
		}
		memset(buff, 0, sizeof(buff));
	}
	fclose(fp);
}

static int dissector_cleanup_ports_udp(void *ptr)
{
	struct port_udp *tmp, *p = ptr;
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

static void dissector_init_ports_tcp(void)
{
	FILE *fp;
	char buff[512], *ptr;
	struct port_tcp *ptcp;
	void **pos;
	fp = fopen("/etc/netsniff-ng/tcp.conf", "r");
	if (!fp)
		panic("No /etc/netsniff-ng/tcp.conf found!\n");
	memset(buff, 0, sizeof(buff));
	while (fgets(buff, sizeof(buff), fp) != NULL) {
		buff[sizeof(buff) - 1] = 0;
		ptcp = xmalloc(sizeof(*ptcp));
		ptr = buff;
		ptr = skips(ptr);
		ptr = getuint(ptr, &ptcp->id);
		ptr = skips(ptr);
		ptr = skipchar(ptr, ',');
		ptr = skips(ptr);
		ptr = strtrim_right(ptr, '\n');
		ptr = strtrim_right(ptr, ' ');
		ptcp->port = xstrdup(ptr);
		ptcp->next = NULL;
		pos = insert_hash(ptcp->id, ptcp, &eth_ports_tcp);
		if (pos) {
			ptcp->next = *pos;
			*pos = ptcp;
		}
		memset(buff, 0, sizeof(buff));
	}
	fclose(fp);
}

static int dissector_cleanup_ports_tcp(void *ptr)
{
	struct port_tcp *tmp, *p = ptr;
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

static void dissector_init_ether_types(void)
{
	FILE *fp;
	char buff[512], *ptr;
	struct ether_type *et;
	void **pos;
	fp = fopen("/etc/netsniff-ng/ether.conf", "r");
	if (!fp)
		panic("No /etc/netsniff-ng/ether.conf found!\n");
	memset(buff, 0, sizeof(buff));
	while (fgets(buff, sizeof(buff), fp) != NULL) {
		buff[sizeof(buff) - 1] = 0;
		et = xmalloc(sizeof(*et));
		ptr = buff;
		ptr = skips(ptr);
		ptr = getuint(ptr, &et->id);
		ptr = skips(ptr);
		ptr = skipchar(ptr, ',');
		ptr = skips(ptr);
		ptr = strtrim_right(ptr, '\n');
		ptr = strtrim_right(ptr, ' ');
		et->type = xstrdup(ptr);
		et->next = NULL;
		pos = insert_hash(et->id, et, &eth_ether_types);
		if (pos) {
			et->next = *pos;
			*pos = et;
		}
		memset(buff, 0, sizeof(buff));
	}
	fclose(fp);
}

static int dissector_cleanup_ether_types(void *ptr)
{
	struct ether_type *tmp, *p = ptr;
	if (!ptr)
		return 0;
	while ((tmp = p->next)) {
		xfree(p->type);
		xfree(p);
		p = tmp;
	}
	xfree(p->type);
	xfree(p);
	return 0;
}

void dissector_init_ethernet(int fnttype)
{
	dissector_init_entry(fnttype);
	dissector_init_layer_2(fnttype);
	dissector_init_layer_3(fnttype);
	dissector_init_layer_4(fnttype);
	dissector_init_exit(fnttype);
	dissector_init_oui();
	dissector_init_ports_udp();
	dissector_init_ports_tcp();
	dissector_init_ether_types();
}

void dissector_cleanup_ethernet(void)
{
	free_hash(&eth_lay2);
	free_hash(&eth_lay3);
	free_hash(&eth_lay4);
	for_each_hash(&eth_ether_types, dissector_cleanup_ether_types);
	free_hash(&eth_ether_types);
	for_each_hash(&eth_ports_udp, dissector_cleanup_ports_udp);
	free_hash(&eth_ports_udp);
	for_each_hash(&eth_ports_tcp, dissector_cleanup_ports_tcp);
	free_hash(&eth_ports_tcp);
	for_each_hash(&eth_oui, dissector_cleanup_oui);
	free_hash(&eth_oui);
}

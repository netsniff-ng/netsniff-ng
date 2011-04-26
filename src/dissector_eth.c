/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

/* Needs a better rewrite! */

#include <stdint.h>

#include "hash.h"
#include "parser.h"
#include "protos.h"
#include "tlsf.h"
#include "dissector.h"
#include "dissector_eth.h"
#include "xmalloc.h"

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

char *lookup_vendor(unsigned int id)
{
	struct vendor_id *entry = lookup_hash(id, &eth_oui);
	while (entry && id != entry->id)
		entry = entry->next;
	return (entry && id == entry->id ? entry->vendor : "Unknown");
}

char *lookup_port_udp(unsigned int id)
{
	struct port_udp *entry = lookup_hash(id, &eth_ports_udp);
	while (entry && id != entry->id)
		entry = entry->next;
	return (entry && id == entry->id ? entry->port : "Unknown");
}

char *lookup_port_tcp(unsigned int id)
{
	struct port_tcp *entry = lookup_hash(id, &eth_ports_tcp);
	while (entry && id != entry->id)
		entry = entry->next;
	return (entry && id == entry->id ? entry->port : "Unknown");
}

char *lookup_ether_type(unsigned int id)
{
	struct ether_type *entry = lookup_hash(id, &eth_ether_types);
	while (entry && id != entry->id)
		entry = entry->next;
	return (entry && id == entry->id ? entry->type : "Unknown");
}

static inline void dissector_init_entry(int (*fnt)(void *ptr))
{
	fnt(&ethernet_ops);
}

static inline void dissector_init_exit(int (*fnt)(void *ptr))
{
	fnt(&hex_ops);
}

static void dissector_init_lay2(int (*fnt)(void *ptr))
{
	init_hash(&eth_lay2);
	INSERT_HASH_PROTOS(arp_ops, eth_lay2);
	INSERT_HASH_PROTOS(vlan_ops, eth_lay2);
	INSERT_HASH_PROTOS(ipv4_ops, eth_lay2);
	INSERT_HASH_PROTOS(ipv6_ops, eth_lay2);
	for_each_hash(&eth_lay2, fnt);
}

static void dissector_init_lay3(int (*fnt)(void *ptr))
{
	init_hash(&eth_lay3);
	INSERT_HASH_PROTOS(icmp_ops, eth_lay3);
	INSERT_HASH_PROTOS(udp_ops, eth_lay3);
	INSERT_HASH_PROTOS(tcp_ops, eth_lay3);
	for_each_hash(&eth_lay3, fnt);
}

static void dissector_init_lay4(int (*fnt)(void *ptr))
{
	init_hash(&eth_lay4);
	for_each_hash(&eth_lay4, fnt);
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
		ven = xtlsf_malloc(sizeof(*ven));
		ptr = buff;
		ptr = skips(ptr);
		ptr = getuint(ptr, &ven->id);
		ptr = skips(ptr);
		ptr = skipchar(ptr, ',');
		ptr = skips(ptr);
		ptr = strtrim_right(ptr, '\n');
		ptr = strtrim_right(ptr, ' ');
		ven->vendor = xtlsf_strdup(ptr);
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
		xtlsf_free(v->vendor);
		xtlsf_free(v);
		v = tmp;
	}

	xtlsf_free(v->vendor);
	xtlsf_free(v);
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
		pudp = xtlsf_malloc(sizeof(*pudp));
		ptr = buff;
		ptr = skips(ptr);
		ptr = getuint(ptr, &pudp->id);
		ptr = skips(ptr);
		ptr = skipchar(ptr, ',');
		ptr = skips(ptr);
		ptr = strtrim_right(ptr, '\n');
		ptr = strtrim_right(ptr, ' ');
		pudp->port = xtlsf_strdup(ptr);
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
		xtlsf_free(p->port);
		xtlsf_free(p);
		p = tmp;
	}

	xtlsf_free(p->port);
	xtlsf_free(p);
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
		ptcp = xtlsf_malloc(sizeof(*ptcp));
		ptr = buff;
		ptr = skips(ptr);
		ptr = getuint(ptr, &ptcp->id);
		ptr = skips(ptr);
		ptr = skipchar(ptr, ',');
		ptr = skips(ptr);
		ptr = strtrim_right(ptr, '\n');
		ptr = strtrim_right(ptr, ' ');
		ptcp->port = xtlsf_strdup(ptr);
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
		xtlsf_free(p->port);
		xtlsf_free(p);
		p = tmp;
	}

	xtlsf_free(p->port);
	xtlsf_free(p);
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
		et = xtlsf_malloc(sizeof(*et));
		ptr = buff;
		ptr = skips(ptr);
		ptr = getuint(ptr, &et->id);
		ptr = skips(ptr);
		ptr = skipchar(ptr, ',');
		ptr = skips(ptr);
		ptr = strtrim_right(ptr, '\n');
		ptr = strtrim_right(ptr, ' ');
		et->type = xtlsf_strdup(ptr);
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
		xtlsf_free(p->type);
		xtlsf_free(p);
		p = tmp;
	}

	xtlsf_free(p->type);
	xtlsf_free(p);
	return 0;
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
		fnt = dissector_set_print_payload_hex;
		break;
	case FNTTYPE_PRINT_HEX2:
		fnt = dissector_set_print_all_hex;
		break;
	case FNTTYPE_PRINT_CHR1:
		fnt = dissector_set_print_payload;
		break;
	case FNTTYPE_PRINT_NOPA:
		fnt = dissector_set_print_no_payload;
		break;
	case FNTTYPE_PRINT_PAAC:
		fnt = dissector_set_print_c_style;
		break;
	default:
	case FNTTYPE_PRINT_NONE:
		fnt = dissector_set_print_none;
		break;
	}

	dissector_init_entry(fnt);
	dissector_init_lay2(fnt);
	dissector_init_lay3(fnt);
	dissector_init_lay4(fnt);
	dissector_init_exit(fnt);

	info("OUI "); fflush(stdout);
	dissector_init_oui();
	info("UDP "); fflush(stdout);
	dissector_init_ports_udp();
	info("TCP "); fflush(stdout);
	dissector_init_ports_tcp();
	info("ETH "); fflush(stdout);
	dissector_init_ether_types();
	info("\n"); fflush(stdout);
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

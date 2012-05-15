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
#include "dissector_80211.h"
#include "xmalloc.h"
#include "xstring.h"

struct hash_table ieee80211_lay2;

static struct hash_table ieee80211_oui;

struct vendor_id {
	unsigned int id;
	char *vendor;
	struct vendor_id *next;
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
	return __do_lookup_inline(id, vendor_id, &ieee80211_oui, vendor);
}

static inline void dissector_init_entry(int type)
{
	dissector_set_print_type(&ieee80211_mac_ops, type);
}

static inline void dissector_init_exit(int type)
{
	dissector_set_print_type(&none_ops, type);
}

static void dissector_init_layer_2(int type)
{
	init_hash(&ieee80211_lay2);
//	INSERT_HASH_PROTOS(arp_ops, eth_lay2);
//	INSERT_HASH_PROTOS(vlan_ops, eth_lay2);
//	INSERT_HASH_PROTOS(ipv4_ops, eth_lay2);
//	INSERT_HASH_PROTOS(ipv6_ops, eth_lay2);
	for_each_hash_int(&ieee80211_lay2, dissector_set_print_type, type);
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
		pos = insert_hash(ven->id, ven, &ieee80211_oui);
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

void dissector_init_ieee80211(int fnttype)
{
	dissector_init_entry(fnttype);
	dissector_init_layer_2(fnttype);
	dissector_init_exit(fnttype);
	dissector_init_oui();
}

void dissector_cleanup_ieee80211(void)
{
	free_hash(&ieee80211_lay2);
	for_each_hash(&ieee80211_oui, dissector_cleanup_oui);
	free_hash(&ieee80211_oui);
}

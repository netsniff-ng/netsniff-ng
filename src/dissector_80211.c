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
#include "oui.h"

struct hash_table ieee80211_lay2;

static inline void dissector_init_entry(int type)
{
//	dissector_set_print_type(&ieee80211_mac_ops, type);
}

static inline void dissector_init_exit(int type)
{
//	dissector_set_print_type(&none_ops, type);
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
	dissector_cleanup_oui();
}

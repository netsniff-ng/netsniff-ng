/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdint.h>

#include "hash.h"
#include "proto.h"
#include "protos.h"
#include "dissector.h"
#include "dissector_eth.h"
#include "lookup.h"
#include "xmalloc.h"

struct hash_table eth_lay2;
struct hash_table eth_lay3;

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
	INSERT_HASH_PROTOS(dccp_ops, eth_lay3);
	for_each_hash_int(&eth_lay3, dissector_set_print_type, type);
}

void dissector_init_ethernet(int fnttype)
{
	dissector_init_entry(fnttype);
	dissector_init_layer_2(fnttype);
	dissector_init_layer_3(fnttype);
	dissector_init_exit(fnttype);

	lookup_init(LT_PORTS_UDP);
	lookup_init(LT_PORTS_TCP);
	lookup_init(LT_ETHERTYPES);
	lookup_init(LT_OUI);
}

void dissector_cleanup_ethernet(void)
{
	free_hash(&eth_lay2);
	free_hash(&eth_lay3);

	lookup_cleanup(LT_OUI);
	lookup_cleanup(LT_ETHERTYPES);
	lookup_cleanup(LT_PORTS_TCP);
	lookup_cleanup(LT_PORTS_UDP);
}

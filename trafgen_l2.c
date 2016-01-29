/*
 * netsniff-ng - the packet sniffing beast
 * Subject to the GPL, version 2.
 */

#include <net/if_arp.h>
#include <linux/if_ether.h>

#include "built_in.h"
#include "trafgen_l2.h"
#include "trafgen_proto.h"

struct proto_field eth_fields[] = {
	{ .id = ETH_DST_ADDR, .len = 6, },
	{ .id = ETH_SRC_ADDR, .len = 6, .offset = 6 },
	{ .id = ETH_TYPE,     .len = 2, .offset = 12 },
};

static void eth_header_init(struct proto_hdr *hdr)
{
	proto_header_fields_add(hdr, eth_fields, array_size(eth_fields));

	proto_field_set_default_dev_mac(hdr, ETH_SRC_ADDR);
}

static struct proto_hdr eth_hdr = {
	.id		= PROTO_ETH,
	.layer		= PROTO_L2,
	.header_init	= eth_header_init,
};

static struct proto_field arp_fields[] = {
	{ .id = ARP_HTYPE, .len = 2 },
	{ .id = ARP_PTYPE, .len = 2, .offset = 2 },
	{ .id = ARP_HLEN,  .len = 1, .offset = 4 },
	{ .id = ARP_PLEN,  .len = 1, .offset = 5 },
	{ .id = ARP_OPER,  .len = 2, .offset = 6 },
	{ .id = ARP_SHA,   .len = 6, .offset = 8 },
	{ .id = ARP_SPA,   .len = 4, .offset = 14 },
	{ .id = ARP_THA,   .len = 6, .offset = 18 },
	{ .id = ARP_TPA,   .len = 4, .offset = 24 },
};

static void arp_header_init(struct proto_hdr *hdr)
{
	struct proto_hdr *lower;

	proto_lower_default_add(PROTO_ETH);

	lower = proto_current_header();

	if (lower->id == PROTO_ETH) {
		uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

		proto_field_set_default_bytes(lower, ETH_DST_ADDR, bcast);
		proto_field_set_default_be16(lower, ETH_TYPE, ETH_P_ARP);
	}

	proto_header_fields_add(hdr, arp_fields, array_size(arp_fields));

	/* Generate Announce request by default */
	proto_field_set_default_be16(hdr, ARP_HTYPE, ARPHRD_ETHER);
	proto_field_set_default_be16(hdr, ARP_PTYPE, ETH_P_IP);
	proto_field_set_default_u8(hdr, ARP_HLEN, 6);
	proto_field_set_default_u8(hdr, ARP_PLEN, 4);
	proto_field_set_default_be16(hdr, ARP_OPER, ARPOP_REQUEST);
	proto_field_set_default_dev_mac(hdr, ARP_SHA);
	proto_field_set_default_dev_ipv4(hdr, ARP_SPA);
	proto_field_set_default_dev_ipv4(hdr, ARP_TPA);
}

static struct proto_hdr arp_hdr = {
	.id		= PROTO_ARP,
	.layer		= PROTO_L2,
	.header_init	= arp_header_init,
};

void protos_l2_init(void)
{
	proto_header_register(&eth_hdr);
	proto_header_register(&arp_hdr);
}

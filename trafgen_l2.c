/*
 * netsniff-ng - the packet sniffing beast
 * Subject to the GPL, version 2.
 */

#include "built_in.h"
#include "trafgen_l2.h"
#include "trafgen_proto.h"

struct proto_field eth_fields[] = {
	{ .id = ETH_DST_ADDR, .len = 6, },
	{ .id = ETH_SRC_ADDR, .len = 6, .offset = 6 },
	{ .id = ETH_PROTO_ID, .len = 2, .offset = 12 },
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

void protos_l2_init(void)
{
	proto_header_register(&eth_hdr);
}

/*
 * netsniff-ng - the packet sniffing beast
 * Subject to the GPL, version 2.
 */

#include <net/if_arp.h>
#include <linux/if_ether.h>

#include "die.h"
#include "built_in.h"
#include "linktype.h"
#include "trafgen_l2.h"
#include "trafgen_dev.h"
#include "trafgen_proto.h"

static struct proto_field eth_fields[] = {
	{ .id = ETH_DST_ADDR, .len = 6, },
	{ .id = ETH_SRC_ADDR, .len = 6, .offset = 6 },
	{ .id = ETH_TYPE,     .len = 2, .offset = 12 },
};

static uint16_t pid_to_eth(enum proto_id pid)
{
	switch (pid) {
	case PROTO_ARP:
		return ETH_P_ARP;
	case PROTO_IP4:
		return ETH_P_IP;
	case PROTO_IP6:
		return ETH_P_IPV6;
	case PROTO_MPLS:
		return ETH_P_MPLS_UC;
	case PROTO_VLAN:
		return ETH_P_8021Q;
	case PROTO_PAUSE:
	case PROTO_PFC:
		return ETH_P_PAUSE;
	default:
		bug();
	}
}

static uint16_t eth_to_pid(uint16_t etype)
{
	switch (etype) {
	case ETH_P_ARP:
		return PROTO_ARP;
	case ETH_P_IP:
		return PROTO_IP4;
	case ETH_P_IPV6:
		return PROTO_IP6;
	case ETH_P_MPLS_UC:
		return PROTO_MPLS;
	case ETH_P_8021Q:
	case ETH_P_8021AD:
		return PROTO_VLAN;
	case ETH_P_PAUSE:
		return PROTO_PAUSE;
	default:
		return __PROTO_MAX;
	}
}

static void eth_set_next_proto(struct proto_hdr *hdr, enum proto_id pid)
{
	proto_hdr_field_set_default_be16(hdr, ETH_TYPE, pid_to_eth(pid));
}

static enum proto_id eth_get_next_proto(struct proto_hdr *hdr)
{
	return eth_to_pid(proto_hdr_field_get_u16(hdr, ETH_TYPE));
}

static void eth_header_init(struct proto_hdr *hdr)
{
	proto_header_fields_add(hdr, eth_fields, array_size(eth_fields));

	proto_hdr_field_set_default_dev_mac(hdr, ETH_SRC_ADDR);

	dev_io_link_type_set(proto_dev_get(), LINKTYPE_EN10MB);
}

static const struct proto_ops eth_proto_ops = {
	.id		= PROTO_ETH,
	.layer		= PROTO_L2,
	.header_init	= eth_header_init,
	.set_next_proto = eth_set_next_proto,
	.get_next_proto = eth_get_next_proto,
};

static struct proto_field pause_fields[] = {
	{ .id = PAUSE_OPCODE,   .len = 2, .offset = 0 },
	{ .id = PAUSE_TIME,     .len = 2, .offset = 2 },
};

static void pause_header_init(struct proto_hdr *hdr)
{
	uint8_t eth_dst[6] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x01 };

	struct proto_hdr *lower;

	lower = proto_lower_default_add(hdr, PROTO_ETH);
	proto_hdr_field_set_default_bytes(lower, ETH_DST_ADDR, eth_dst, 6);

	proto_header_fields_add(hdr, pause_fields, array_size(pause_fields));
	proto_hdr_field_set_default_be16(hdr, PAUSE_OPCODE, 0x1);
}

static struct proto_ops pause_proto_ops = {
	.id		= PROTO_PAUSE,
	.layer		= PROTO_L2,
	.header_init	= pause_header_init,
};

static struct proto_field pfc_fields[] = {
	{ .id = PFC_OPCODE,  .len = 2, .offset = 0 },
	{ .id = PFC_PRIO,    .len = 2, .offset = 2 },
	{ .id = PFC_PRIO_0,  .len = 2, .offset = 2, .mask = 0x0001 },
	{ .id = PFC_PRIO_1,  .len = 2, .offset = 2, .mask = 0x0002, .shift = 1 },
	{ .id = PFC_PRIO_2,  .len = 2, .offset = 2, .mask = 0x0004, .shift = 2 },
	{ .id = PFC_PRIO_3,  .len = 2, .offset = 2, .mask = 0x0008, .shift = 3 },
	{ .id = PFC_PRIO_4,  .len = 2, .offset = 2, .mask = 0x0010, .shift = 4 },
	{ .id = PFC_PRIO_5,  .len = 2, .offset = 2, .mask = 0x0020, .shift = 5 },
	{ .id = PFC_PRIO_6,  .len = 2, .offset = 2, .mask = 0x0040, .shift = 6 },
	{ .id = PFC_PRIO_7,  .len = 2, .offset = 2, .mask = 0x0080, .shift = 7 },
	{ .id = PFC_TIME_0,  .len = 2, .offset = 4,  },
	{ .id = PFC_TIME_1,  .len = 2, .offset = 6,  },
	{ .id = PFC_TIME_2,  .len = 2, .offset = 8,  },
	{ .id = PFC_TIME_3,  .len = 2, .offset = 10, },
	{ .id = PFC_TIME_4,  .len = 2, .offset = 12, },
	{ .id = PFC_TIME_5,  .len = 2, .offset = 14, },
	{ .id = PFC_TIME_6,  .len = 2, .offset = 16, },
	{ .id = PFC_TIME_7,  .len = 2, .offset = 18, },
};

static void pfc_header_init(struct proto_hdr *hdr)
{
	uint8_t eth_dst[6] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x01 };

	struct proto_hdr *lower;

	lower = proto_lower_default_add(hdr, PROTO_ETH);
	proto_hdr_field_set_default_bytes(lower, ETH_DST_ADDR, eth_dst, 6);

	proto_header_fields_add(hdr, pfc_fields, array_size(pfc_fields));
	proto_hdr_field_set_default_be16(hdr, PFC_OPCODE, 0x0101);
}

static struct proto_ops pfc_proto_ops = {
	.id		= PROTO_PFC,
	.layer		= PROTO_L2,
	.header_init	= pfc_header_init,
};

static struct proto_field vlan_fields[] = {
	/* TPID overlaps with Ethernet header and points to ether type */
	{ .id = VLAN_TPID, .len = 2, .offset = -2 },
	{ .id = VLAN_TCI,  .len = 2, .offset = 0 },
	{ .id = VLAN_PCP,  .len = 2, .offset = 0, .shift = 13, .mask = 0xe000 },
	{ .id = VLAN_DEI,  .len = 2, .offset = 0, .shift = 12, .mask = 0x1000 },
	{ .id = VLAN_VID,  .len = 2, .offset = 0, .shift = 0,  .mask = 0xfff },
	/* Original ether type is stored after VLAN header */
	{ .id = VLAN_ETYPE, .len = 2, .offset = 2 },
};

static void vlan_header_init(struct proto_hdr *hdr)
{
	struct proto_hdr *lower = proto_lower_default_add(hdr, PROTO_ETH);
	uint16_t lower_etype = 0;

	proto_header_fields_add(hdr, vlan_fields, array_size(vlan_fields));

	if (lower->ops->id == PROTO_ETH)
		lower_etype = proto_hdr_field_get_u16(lower, ETH_TYPE);
	else if (lower->ops->id == PROTO_VLAN)
		lower_etype = proto_hdr_field_get_u16(lower, VLAN_ETYPE);

	proto_hdr_field_set_be16(hdr, VLAN_ETYPE, lower_etype);
	proto_hdr_field_set_default_be16(hdr, VLAN_TPID, pid_to_eth(hdr->ops->id));
}

static void vlan_set_next_proto(struct proto_hdr *hdr, enum proto_id pid)
{
	if (pid != PROTO_VLAN)
		proto_hdr_field_set_be16(hdr, VLAN_ETYPE, pid_to_eth(pid));
}

static enum proto_id vlan_get_next_proto(struct proto_hdr *hdr)
{
	return eth_to_pid(proto_hdr_field_get_u16(hdr, VLAN_ETYPE));
}

static const struct proto_ops vlan_proto_ops = {
	.id		= PROTO_VLAN,
	.layer		= PROTO_L2,
	.header_init	= vlan_header_init,
	.set_next_proto = vlan_set_next_proto,
	.get_next_proto = vlan_get_next_proto,
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
	struct proto_hdr *lower = proto_lower_default_add(hdr, PROTO_ETH);

	if (lower->ops->id == PROTO_ETH) {
		const uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

		proto_hdr_field_set_default_bytes(lower, ETH_DST_ADDR, bcast, 6);
	}

	proto_header_fields_add(hdr, arp_fields, array_size(arp_fields));

	/* Generate Announce request by default */
	proto_hdr_field_set_default_be16(hdr, ARP_HTYPE, ARPHRD_ETHER);
	proto_hdr_field_set_default_be16(hdr, ARP_PTYPE, ETH_P_IP);
	proto_hdr_field_set_default_u8(hdr, ARP_HLEN, 6);
	proto_hdr_field_set_default_u8(hdr, ARP_PLEN, 4);
	proto_hdr_field_set_default_be16(hdr, ARP_OPER, ARPOP_REQUEST);
	proto_hdr_field_set_default_dev_mac(hdr, ARP_SHA);
	proto_hdr_field_set_default_dev_ipv4(hdr, ARP_SPA);
	proto_hdr_field_set_default_dev_ipv4(hdr, ARP_TPA);
}

static const struct proto_ops arp_proto_ops = {
	.id		= PROTO_ARP,
	.layer		= PROTO_L2,
	.header_init	= arp_header_init,
};

static struct proto_field mpls_fields[] = {
	{ .id = MPLS_LABEL, .len = 4, .shift = 12, .mask = 0xfffff000 },
	{ .id = MPLS_TC,    .len = 4, .shift = 9,  .mask = 0xe00 },
	{ .id = MPLS_LAST,  .len = 4, .shift = 8,  .mask = 0x100 },
	{ .id = MPLS_TTL,   .len = 4, .shift = 0,  .mask = 0xff },
};

static void mpls_header_init(struct proto_hdr *hdr)
{
	proto_lower_default_add(hdr, PROTO_ETH);

	proto_header_fields_add(hdr, mpls_fields, array_size(mpls_fields));

	proto_hdr_field_set_default_be32(hdr, MPLS_LAST, 1);
}

static void mpls_set_next_proto(struct proto_hdr *hdr, enum proto_id pid)
{
	if (pid == PROTO_MPLS)
		proto_hdr_field_set_default_be32(hdr, MPLS_LAST, 0);
}

static const struct proto_ops mpls_proto_ops = {
	.id		= PROTO_MPLS,
	.layer		= PROTO_L2,
	.header_init	= mpls_header_init,
	.set_next_proto = mpls_set_next_proto,
};

void protos_l2_init(void)
{
	proto_ops_register(&eth_proto_ops);
	proto_ops_register(&pause_proto_ops);
	proto_ops_register(&pfc_proto_ops);
	proto_ops_register(&vlan_proto_ops);
	proto_ops_register(&arp_proto_ops);
	proto_ops_register(&mpls_proto_ops);
}

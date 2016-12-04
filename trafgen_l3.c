/*
 * netsniff-ng - the packet sniffing beast
 * Subject to the GPL, version 2.
 */

#include <linux/if_ether.h>

#include "die.h"
#include "csum.h"
#include "built_in.h"
#include "trafgen_l2.h"
#include "trafgen_l3.h"
#include "trafgen_proto.h"
#include "trafgen_conf.h"

static struct proto_field ipv4_fields[] = {
	{ .id = IP4_VER,       .len = 1, .offset = 0, .shift = 4, .mask = 0xf0 },
	{ .id = IP4_IHL,       .len = 1, .offset = 0, .shift = 0, .mask = 0x0f },
	{ .id = IP4_DSCP,      .len = 1, .offset = 1, .shift = 2, .mask = 0xfc },
	{ .id = IP4_ECN,       .len = 1, .offset = 1, .shift = 0, .mask = 0x03 },
	{ .id = IP4_TOS,       .len = 1, .offset = 1 },
	{ .id = IP4_LEN,       .len = 2, .offset = 2 },
	{ .id = IP4_ID,        .len = 2, .offset = 4 },
	{ .id = IP4_FLAGS,     .len = 2, .offset = 6, .shift = 13, .mask = 0xe000 },
	{ .id = IP4_MF,        .len = 2, .offset = 6, .shift = 13, .mask = 0x2000 },
	{ .id = IP4_DF,        .len = 2, .offset = 6, .shift = 14, .mask = 0x4000 },
	{ .id = IP4_FRAG_OFFS, .len = 2, .offset = 6, .shift = 0,  .mask = 0x1fff },
	{ .id = IP4_TTL,       .len = 1, .offset = 8 },
	{ .id = IP4_PROTO,     .len = 1, .offset = 9 },
	{ .id = IP4_CSUM,      .len = 2, .offset = 10 },
	{ .id = IP4_SADDR,     .len = 4, .offset = 12 },
	{ .id = IP4_DADDR,     .len = 4, .offset = 16 },
};

static void ipv4_header_init(struct proto_hdr *hdr)
{
	proto_lower_default_add(hdr, PROTO_ETH);

	proto_header_fields_add(hdr, ipv4_fields, array_size(ipv4_fields));

	proto_field_set_default_u8(hdr, IP4_VER, 4);
	proto_field_set_default_u8(hdr, IP4_IHL, 5);
}

static void ipv4_field_changed(struct proto_field *field)
{
	field->hdr->is_csum_valid = false;

	if (field->id == IP4_SADDR || field->id == IP4_DADDR) {
		struct proto_hdr *upper = proto_upper_header(field->hdr);

		if (upper && (upper->ops->id == PROTO_UDP || upper->ops->id == PROTO_TCP))
			upper->is_csum_valid = false;
	}
}

static void ipv4_csum_update(struct proto_hdr *hdr)
{
	struct packet *pkt;
	uint16_t csum;

	if (hdr->is_csum_valid)
		return;
	if (proto_field_is_set(hdr, IP4_CSUM))
		return;

	pkt = packet_get(hdr->pkt_id);

	proto_field_set_default_u16(hdr, IP4_CSUM, 0);
	csum = htons(calc_csum(&pkt->payload[hdr->pkt_offset], hdr->len));
	proto_field_set_default_u16(hdr, IP4_CSUM, bswap_16(csum));

	hdr->is_csum_valid = true;
}

static void ipv4_packet_finish(struct proto_hdr *hdr)
{
	struct packet *pkt = current_packet();
	uint16_t total_len;

	total_len = pkt->len - hdr->pkt_offset;
	proto_field_set_default_be16(hdr, IP4_LEN, total_len);
	proto_field_set_default_dev_ipv4(hdr, IP4_SADDR);

	ipv4_csum_update(hdr);
}

static void ipv4_set_next_proto(struct proto_hdr *hdr, enum proto_id pid)
{
	uint8_t ip_proto;

	switch (pid) {
	case PROTO_IP4:
		ip_proto = IPPROTO_IPIP;
		break;
	case PROTO_IP6:
		ip_proto = IPPROTO_IPV6;
		break;
	case PROTO_ICMP4:
		ip_proto = IPPROTO_ICMP;
		break;
	case PROTO_UDP:
		ip_proto = IPPROTO_UDP;
		break;
	case PROTO_TCP:
		ip_proto = IPPROTO_TCP;
		break;
	default:
		bug();
	}

	proto_field_set_default_u8(hdr, IP4_PROTO, ip_proto);
}

static const struct proto_ops ipv4_proto_ops = {
	.id		= PROTO_IP4,
	.layer		= PROTO_L3,
	.header_init	= ipv4_header_init,
	.packet_update  = ipv4_csum_update,
	.field_changed  = ipv4_field_changed,
	.packet_finish  = ipv4_packet_finish,
	.set_next_proto = ipv4_set_next_proto,
};

static struct proto_field ipv6_fields[] = {
	{ .id = IP6_VER,       .len = 4,  .offset = 0, .shift = 28, .mask = 0xf0000000 },
	{ .id = IP6_CLASS,     .len = 4,  .offset = 0, .shift = 20, .mask = 0x0ff00000 },
	{ .id = IP6_FLOW_LBL,  .len = 4,  .offset = 0, .shift = 0,  .mask = 0x000fffff },
	{ .id = IP6_LEN,       .len = 2,  .offset = 4 },
	{ .id = IP6_NEXT_HDR,  .len = 1,  .offset = 6 },
	{ .id = IP6_HOP_LIMIT, .len = 1,  .offset = 7 },
	{ .id = IP6_SADDR,     .len = 16, .offset = 8 },
	{ .id = IP6_DADDR,     .len = 16, .offset = 24 },
};

static void ipv6_header_init(struct proto_hdr *hdr)
{
	proto_lower_default_add(hdr, PROTO_ETH);

	proto_header_fields_add(hdr, ipv6_fields, array_size(ipv6_fields));

	proto_field_set_default_be32(hdr, IP6_VER, 6);
}

static void ipv6_field_changed(struct proto_field *field)
{
	if (field->id == IP6_SADDR || field->id == IP6_DADDR) {
		struct proto_hdr *upper = proto_upper_header(field->hdr);

		if (upper && (upper->ops->id == PROTO_UDP || upper->ops->id == PROTO_TCP))
			upper->is_csum_valid = false;
	}
}

#define IPV6_HDR_LEN 40

static void ipv6_packet_finish(struct proto_hdr *hdr)
{
	struct packet *pkt = current_packet();
	uint16_t total_len = pkt->len - hdr->pkt_offset - IPV6_HDR_LEN;

	proto_field_set_default_be16(hdr, IP6_LEN, total_len);
	proto_field_set_default_dev_ipv6(hdr, IP6_SADDR);
}

static void ipv6_set_next_proto(struct proto_hdr *hdr, enum proto_id pid)
{
	uint8_t ip_proto;

	switch (pid) {
	case PROTO_ICMP6:
		ip_proto = IPPROTO_ICMPV6;
		break;
	case PROTO_UDP:
		ip_proto = IPPROTO_UDP;
		break;
	case PROTO_TCP:
		ip_proto = IPPROTO_TCP;
		break;
	default:
		bug();
	}

	proto_field_set_default_u8(hdr, IP6_NEXT_HDR, ip_proto);
}

static const struct proto_ops ipv6_proto_ops = {
	.id             = PROTO_IP6,
	.layer          = PROTO_L3,
	.header_init    = ipv6_header_init,
	.field_changed  = ipv6_field_changed,
	.packet_finish  = ipv6_packet_finish,
	.set_next_proto = ipv6_set_next_proto,
};

void protos_l3_init(void)
{
	proto_ops_register(&ipv4_proto_ops);
	proto_ops_register(&ipv6_proto_ops);
}

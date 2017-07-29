/*
 * netsniff-ng - the packet sniffing beast
 * Subject to the GPL, version 2.
 */

#include <stdbool.h>
#include <netinet/in.h>

#include "die.h"
#include "csum.h"
#include "built_in.h"
#include "trafgen_l3.h"
#include "trafgen_l4.h"
#include "trafgen_conf.h"
#include "trafgen_proto.h"

static struct proto_field udp_fields[] = {
	{ .id = UDP_SPORT, .len = 2, .offset = 0 },
	{ .id = UDP_DPORT, .len = 2, .offset = 2 },
	{ .id = UDP_LEN,   .len = 2, .offset = 4 },
	{ .id = UDP_CSUM,  .len = 2, .offset = 6 },
};

static void udp_header_init(struct proto_hdr *hdr)
{
	proto_lower_default_add(hdr, PROTO_IP4);

	proto_header_fields_add(hdr, udp_fields, array_size(udp_fields));
}

static void udp_field_changed(struct proto_field *field)
{
	field->hdr->is_csum_valid = false;
}

static void udp_csum_update(struct proto_hdr *hdr)
{
	struct proto_hdr *lower;
	uint16_t total_len;
	uint16_t csum;

	if (hdr->is_csum_valid)
		return;
	if (proto_hdr_field_is_set(hdr, UDP_CSUM))
		return;
	lower = proto_lower_header(hdr);
	if (!lower)
		return;

	total_len = packet_get(hdr->pkt_id)->len - hdr->pkt_offset;

	proto_hdr_field_set_default_be16(hdr, UDP_CSUM, 0);

	switch (lower->ops->id) {
	case PROTO_IP4:
		csum = p4_csum((void *) proto_header_ptr(lower), proto_header_ptr(hdr),
				total_len, IPPROTO_UDP);
		break;
	case PROTO_IP6:
		csum = p6_csum((void *) proto_header_ptr(lower), proto_header_ptr(hdr),
				total_len, IPPROTO_UDP);
		break;
	default:
		csum = 0;
		break;
	}

	proto_hdr_field_set_default_be16(hdr, UDP_CSUM, bswap_16(csum));
	hdr->is_csum_valid = true;
}

static void udp_packet_finish(struct proto_hdr *hdr)
{
	struct packet *pkt = proto_hdr_packet(hdr);
	uint16_t total_len;

	total_len = pkt->len - hdr->pkt_offset;
	proto_hdr_field_set_default_be16(hdr, UDP_LEN, total_len);

	udp_csum_update(hdr);
}

static void udp_set_next_proto(struct proto_hdr *hdr, enum proto_id pid)
{
	uint16_t dport;

	switch (pid) {
	case PROTO_DNS:
		dport = 53;
		break;
	default:
		bug();
	}

	proto_hdr_field_set_default_be16(hdr, UDP_DPORT, dport);
}

static const struct proto_ops udp_proto_ops = {
	.id		= PROTO_UDP,
	.layer		= PROTO_L4,
	.header_init	= udp_header_init,
	.packet_update  = udp_csum_update,
	.packet_finish  = udp_packet_finish,
	.field_changed  = udp_field_changed,
	.set_next_proto = udp_set_next_proto,
};

static struct proto_field tcp_fields[] = {
	{ .id = TCP_SPORT,   .len = 2, .offset = 0 },
	{ .id = TCP_DPORT,   .len = 2, .offset = 2 },
	{ .id = TCP_SEQ,     .len = 4, .offset = 4 },
	{ .id = TCP_ACK_SEQ, .len = 4, .offset = 8 },
	{ .id = TCP_DOFF,    .len = 2, .offset = 12, .shift = 12, .mask = 0xf000 },
	/* reserved (4 bits) */
	{ .id = TCP_CWR,     .len = 2, .offset = 12, .shift = 7, .mask = 0x0080 },
	{ .id = TCP_ECE,     .len = 2, .offset = 12, .shift = 6, .mask = 0x0040 },
	{ .id = TCP_URG,     .len = 2, .offset = 12, .shift = 5, .mask = 0x0020 },
	{ .id = TCP_ACK,     .len = 2, .offset = 12, .shift = 4, .mask = 0x0010 },
	{ .id = TCP_PSH,     .len = 2, .offset = 12, .shift = 3, .mask = 0x0008 },
	{ .id = TCP_RST,     .len = 2, .offset = 12, .shift = 2, .mask = 0x0004 },
	{ .id = TCP_SYN,     .len = 2, .offset = 12, .shift = 1, .mask = 0x0002 },
	{ .id = TCP_FIN,     .len = 2, .offset = 12, .shift = 0, .mask = 0x0001 },
	{ .id = TCP_WINDOW,  .len = 2, .offset = 14 },
	{ .id = TCP_CSUM,    .len = 2, .offset = 16 },
	{ .id = TCP_URG_PTR, .len = 2, .offset = 18 },
};

static void tcp_header_init(struct proto_hdr *hdr)
{
	proto_lower_default_add(hdr, PROTO_IP4);

	proto_header_fields_add(hdr, tcp_fields, array_size(tcp_fields));

	proto_hdr_field_set_default_be16(hdr, TCP_DOFF, 5);
}

static void tcp_field_changed(struct proto_field *field)
{
	field->hdr->is_csum_valid = false;
}

static void tcp_csum_update(struct proto_hdr *hdr)
{
	struct proto_hdr *lower = proto_lower_header(hdr);
	struct packet *pkt = proto_hdr_packet(hdr);
	uint16_t total_len;
	uint16_t csum;

	if (hdr->is_csum_valid)
		return;
	if (proto_hdr_field_is_set(hdr, TCP_CSUM))
		return;

	if (!lower)
		return;

	total_len = pkt->len - hdr->pkt_offset;

	proto_hdr_field_set_default_be16(hdr, TCP_CSUM, 0);

	switch (lower->ops->id) {
	case PROTO_IP4:
		csum = p4_csum((void *) proto_header_ptr(lower), proto_header_ptr(hdr),
				total_len, IPPROTO_TCP);
		break;
	case PROTO_IP6:
		csum = p6_csum((void *) proto_header_ptr(lower), proto_header_ptr(hdr),
				total_len, IPPROTO_TCP);
		break;
	default:
		csum = 0;
		break;
	}

	proto_hdr_field_set_default_be16(hdr, TCP_CSUM, bswap_16(csum));
	hdr->is_csum_valid = true;
}

static void tcp_set_next_proto(struct proto_hdr *hdr, enum proto_id pid)
{
	uint16_t dport;

	switch (pid) {
	case PROTO_DNS:
		dport = 53;
		break;
	default:
		bug();
	}

	proto_hdr_field_set_default_be16(hdr, TCP_DPORT, dport);
}

static const struct proto_ops tcp_proto_ops = {
	.id		= PROTO_TCP,
	.layer		= PROTO_L4,
	.header_init	= tcp_header_init,
	.packet_update  = tcp_csum_update,
	.packet_finish  = tcp_csum_update,
	.field_changed  = tcp_field_changed,
	.set_next_proto = tcp_set_next_proto,
};

static struct proto_field icmpv4_fields[] = {
	{ .id = ICMPV4_TYPE,       .len = 1, .offset = 0 },
	{ .id = ICMPV4_CODE,       .len = 1, .offset = 1 },
	{ .id = ICMPV4_CSUM,       .len = 2, .offset = 2 },
	/* Echo/Ping fields */
	{ .id = ICMPV4_ID,         .len = 2, .offset = 4 },
	{ .id = ICMPV4_SEQ,        .len = 2, .offset = 6 },
	/* Redirect field */
	{ .id = ICMPV4_REDIR_ADDR, .len = 4, .offset = 4 },
	/* Next-hop MTU */
	{ .id = ICMPV4_MTU,        .len = 2, .offset = 6 },
};

static void icmpv4_header_init(struct proto_hdr *hdr)
{
	proto_lower_default_add(hdr, PROTO_IP4);

	proto_header_fields_add(hdr, icmpv4_fields, array_size(icmpv4_fields));
}

static void icmpv4_csum_update(struct proto_hdr *hdr)
{
	struct packet *pkt;
	uint16_t csum;

	if (hdr->is_csum_valid)
		return;
	if (proto_hdr_field_is_set(hdr, ICMPV4_CSUM))
		return;

	pkt = packet_get(hdr->pkt_id);

	proto_hdr_field_set_default_u16(hdr, ICMPV4_CSUM, 0);
	csum = htons(calc_csum(proto_header_ptr(hdr), pkt->len - hdr->pkt_offset));
	proto_hdr_field_set_default_u16(hdr, ICMPV4_CSUM, bswap_16(csum));

	hdr->is_csum_valid = true;
}

static void icmpv4_field_changed(struct proto_field *field)
{
	field->hdr->is_csum_valid = false;
}

static const struct proto_ops icmpv4_proto_ops = {
	.id		= PROTO_ICMP4,
	.layer		= PROTO_L4,
	.header_init	= icmpv4_header_init,
	.packet_update  = icmpv4_csum_update,
	.packet_finish  = icmpv4_csum_update,
	.field_changed  = icmpv4_field_changed,
};

static struct proto_field icmpv6_fields[] = {
	{ .id = ICMPV6_TYPE, .len = 1, .offset = 0 },
	{ .id = ICMPV6_CODE, .len = 1, .offset = 1 },
	{ .id = ICMPV6_CSUM, .len = 2, .offset = 2 }
};

static void icmpv6_header_init(struct proto_hdr *hdr)
{
	proto_lower_default_add(hdr, PROTO_IP6);

	proto_header_fields_add(hdr, icmpv6_fields, array_size(icmpv6_fields));
}

static void icmpv6_csum_update(struct proto_hdr *hdr)
{
	struct proto_hdr *lower = proto_lower_header(hdr);
	struct packet *pkt = packet_get(hdr->pkt_id);
	uint16_t total_len;
	uint16_t csum;

	if (unlikely(!lower))
		return;
	if (hdr->is_csum_valid)
		return;
	if (proto_hdr_field_is_set(hdr, ICMPV6_CSUM))
		return;

	total_len = pkt->len - hdr->pkt_offset;

	proto_hdr_field_set_be16(hdr, ICMPV6_CSUM, 0);

	if (likely(lower->ops->id == PROTO_IP6)) {
		csum = p6_csum((void *) proto_header_ptr(lower), proto_header_ptr(hdr),
				total_len, IPPROTO_ICMPV6);

		proto_hdr_field_set_be16(hdr, ICMPV6_CSUM, bswap_16(csum));
		hdr->is_csum_valid = true;
	}
}

static void icmpv6_field_changed(struct proto_field *field)
{
	field->hdr->is_csum_valid = false;
}

static struct proto_ops icmpv6_proto_ops = {
	.id		= PROTO_ICMP6,
	.layer		= PROTO_L4,
	.header_init	= icmpv6_header_init,
	.packet_finish  = icmpv6_csum_update,
	.packet_update  = icmpv6_csum_update,
	.field_changed  = icmpv6_field_changed,
};

void protos_l4_init(void)
{
	proto_ops_register(&udp_proto_ops);
	proto_ops_register(&tcp_proto_ops);
	proto_ops_register(&icmpv4_proto_ops);
	proto_ops_register(&icmpv6_proto_ops);
}

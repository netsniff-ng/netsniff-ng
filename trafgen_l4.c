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
	{ .id = UDP_SPORT,	.len = 2,	.offset = 0 },
	{ .id = UDP_DPORT,	.len = 2,	.offset = 2 },
	{ .id = UDP_LEN,	.len = 2,	.offset = 4 },
	{ .id = UDP_CSUM,	.len = 2,	.offset = 6 },
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

static void udp_header_init(struct proto_hdr *hdr)
{
	proto_lower_default_add(hdr, PROTO_IP4);

	proto_header_fields_add(hdr, udp_fields, array_size(udp_fields));
}

static void udp_packet_finish(struct proto_hdr *hdr)
{
	struct proto_hdr *lower = proto_lower_header(hdr);
	struct packet *pkt = current_packet();
	uint16_t total_len;
	uint16_t csum;

	total_len = pkt->len - hdr->pkt_offset;
	proto_field_set_default_be16(hdr, UDP_LEN, total_len);

	if (proto_field_is_set(hdr, UDP_CSUM))
		return;

	if (!lower || lower->id != PROTO_IP4)
		return;

	total_len = proto_field_get_u16(hdr, UDP_LEN);
	csum = p4_csum((void *) proto_header_ptr(lower), proto_header_ptr(hdr),
			total_len, IPPROTO_UDP);

	proto_field_set_be16(hdr, UDP_CSUM, bswap_16(csum));
}

static struct proto_hdr udp_hdr = {
	.id		= PROTO_UDP,
	.layer		= PROTO_L4,
	.header_init	= udp_header_init,
	.packet_finish  = udp_packet_finish,
};

static void tcp_header_init(struct proto_hdr *hdr)
{
	proto_lower_default_add(hdr, PROTO_IP4);

	proto_header_fields_add(hdr, tcp_fields, array_size(tcp_fields));

	proto_field_set_default_be16(hdr, TCP_DOFF, 5);
}

static void tcp_packet_finish(struct proto_hdr *hdr)
{
	struct proto_hdr *lower = proto_lower_header(hdr);
	struct packet *pkt = current_packet();
	uint16_t total_len;
	uint16_t csum;

	if (proto_field_is_set(hdr, TCP_CSUM))
		return;

	if (!lower || lower->id != PROTO_IP4)
		return;

	total_len = pkt->len - hdr->pkt_offset;
	csum = p4_csum((void *) proto_header_ptr(lower), proto_header_ptr(hdr),
			total_len, IPPROTO_TCP);

	proto_field_set_be16(hdr, TCP_CSUM, bswap_16(csum));
}

static struct proto_hdr tcp_hdr = {
	.id		= PROTO_TCP,
	.layer		= PROTO_L4,
	.header_init	= tcp_header_init,
	.packet_finish  = tcp_packet_finish,
};

void protos_l4_init(void)
{
	proto_header_register(&udp_hdr);
	proto_header_register(&tcp_hdr);
}

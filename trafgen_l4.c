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

static void udp_header_init(struct proto_hdr *hdr)
{
	struct proto_hdr *lower;

	proto_lower_default_add(PROTO_IP4);

	lower = proto_current_header();

	if (lower->id == PROTO_IP4)
		proto_field_set_default_u8(lower, IP4_PROTO, IPPROTO_UDP);

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

void protos_l4_init(void)
{
	proto_header_register(&udp_hdr);
}

/*
 * netsniff-ng - the packet sniffing beast
 * Subject to the GPL, version 2.
 */

#include <string.h>

#include "str.h"
#include "xmalloc.h"
#include "built_in.h"
#include "trafgen_l7.h"
#include "trafgen_proto.h"

static struct proto_field dns_fields[] = {
	{ .id = DNS_ID,       .len = 2, .offset = 0 },
	{ .id = DNS_QR,       .len = 2, .offset = 2, .shift = 15, .mask = 0x8000 },
	{ .id = DNS_OPCODE,   .len = 2, .offset = 2, .shift = 11, .mask = 0x7800 },
	{ .id = DNS_AA,       .len = 2, .offset = 2, .shift = 10, .mask = 0x0400 },
	{ .id = DNS_TC,       .len = 2, .offset = 2, .shift = 9,  .mask = 0x0200 },
	{ .id = DNS_RD,       .len = 2, .offset = 2, .shift = 8,  .mask = 0x0100 },
	{ .id = DNS_RA,       .len = 2, .offset = 2, .shift = 7,  .mask = 0x80 },
	{ .id = DNS_ZERO,     .len = 2, .offset = 2, .shift = 4,  .mask = 0x30 },
	{ .id = DNS_RCODE,    .len = 2, .offset = 2, .shift = 0,  .mask = 0xf },
	{ .id = DNS_QD_COUNT, .len = 2, .offset = 4, },
	{ .id = DNS_AN_COUNT, .len = 2, .offset = 6, },
	{ .id = DNS_NS_COUNT, .len = 2, .offset = 8, },
	{ .id = DNS_AR_COUNT, .len = 2, .offset = 10, },
};

static struct proto_field dns_query_fields[] = {
	{ .id = DNS_QUERY_NAME,  .len = 0, .offset = 0 },
	{ .id = DNS_QUERY_TYPE,  .len = 2, .offset = 0 },
	{ .id = DNS_QUERY_CLASS, .len = 2, .offset = 2 },
};

static void dns_query_header_init(struct proto_hdr *hdr)
{
	proto_header_fields_add(hdr, dns_query_fields, array_size(dns_query_fields));
}

static void dns_query_header_finish(struct proto_hdr *hdr)
{
	proto_hdr_field_set_default_string(hdr, DNS_QUERY_NAME, "www.netsniff-ng.com");
	proto_hdr_field_set_default_be16(hdr, DNS_QUERY_CLASS, 1);
	proto_hdr_field_set_default_be16(hdr, DNS_QUERY_TYPE, 1);
}

static const struct proto_ops dns_proto_query_ops = {
	.header_init	= dns_query_header_init,
	.header_finish	= dns_query_header_finish,
};

static struct proto_field dns_rrecord_fields[] = {
	{ .id = DNS_RRECORD_NAME,  .len = 0, .offset = 0 },
	{ .id = DNS_RRECORD_TYPE,  .len = 2, .offset = 0 },
	{ .id = DNS_RRECORD_CLASS, .len = 2, .offset = 2 },
	{ .id = DNS_RRECORD_TTL,   .len = 4, .offset = 4 },
	{ .id = DNS_RRECORD_LEN,   .len = 2, .offset = 8 },
	{ .id = DNS_RRECORD_DATA,  .len = 0, .offset = 10 },
};

static void dns_rrecord_header_init(struct proto_hdr *hdr)
{
	proto_header_fields_add(hdr, dns_rrecord_fields, array_size(dns_rrecord_fields));
}

static void dns_rrecord_header_finish(struct proto_hdr *hdr)
{
	struct proto_field *data = proto_hdr_field_by_id(hdr, DNS_RRECORD_DATA);

	proto_hdr_field_set_default_be32(hdr, DNS_RRECORD_TTL, 1);
	proto_hdr_field_set_default_be16(hdr, DNS_RRECORD_CLASS, 1);
	proto_hdr_field_set_default_be16(hdr, DNS_RRECORD_LEN, data->len);
}

static const struct proto_ops dns_proto_rrecord_ops = {
	.header_init	= dns_rrecord_header_init,
	.header_finish  = dns_rrecord_header_finish,
};

static void dns_header_init(struct proto_hdr *hdr)
{
	proto_lower_default_add(hdr, PROTO_UDP);

	proto_header_fields_add(hdr, dns_fields, array_size(dns_fields));
}

static void dns_sort_headers(struct proto_hdr *hdr, uint32_t id, int index)
{
	int i;

	for (i = index; i < hdr->sub_headers_count; i++) {
		struct proto_hdr *sub_hdr = hdr->sub_headers[i];

		if (sub_hdr->id == id && sub_hdr->index != index) {
			proto_hdr_move_sub_header(hdr, sub_hdr, hdr->sub_headers[index]);
			index++;
		}
	}
}

static void dns_header_finish(struct proto_hdr *hdr)
{
	size_t ar_count = 0;
	size_t ns_count = 0;
	size_t qd_count = 0;
	size_t an_count = 0;
	int i;

	for (i = 0; i < hdr->sub_headers_count; i++) {
		struct proto_hdr *sub_hdr = hdr->sub_headers[i];

		switch (sub_hdr->id) {
		case DNS_QUERY_HDR:
			qd_count++;
			break;
		case DNS_ANSWER_HDR:
			an_count++;
			break;
		case DNS_AUTH_HDR:
			ns_count++;
			break;
		case DNS_ADD_HDR:
			ar_count++;
			break;
		}
	}

	dns_sort_headers(hdr, DNS_QUERY_HDR, 0);
	dns_sort_headers(hdr, DNS_ANSWER_HDR, qd_count);
	dns_sort_headers(hdr, DNS_AUTH_HDR, qd_count + an_count);
	dns_sort_headers(hdr, DNS_ADD_HDR, qd_count + an_count + ns_count);

	proto_hdr_field_set_default_be16(hdr, DNS_QD_COUNT, qd_count);
	proto_hdr_field_set_default_be16(hdr, DNS_AN_COUNT, an_count);
	proto_hdr_field_set_default_be16(hdr, DNS_NS_COUNT, ns_count);
	proto_hdr_field_set_default_be16(hdr, DNS_AR_COUNT, ar_count);

	if (an_count)
		proto_hdr_field_set_default_be16(hdr, DNS_QR, 1);
}

static void dns_push_sub_header(struct proto_hdr *hdr, struct proto_hdr *sub_hdr)
{
	switch (sub_hdr->id) {
	case DNS_QUERY_HDR:
		sub_hdr->ops = &dns_proto_query_ops;
		break;
	case DNS_ANSWER_HDR:
	case DNS_AUTH_HDR:
	case DNS_ADD_HDR:
		sub_hdr->ops = &dns_proto_rrecord_ops;
		break;
	default:
		bug();
	}
}

static const struct proto_ops dns_proto_ops = {
	.id		 = PROTO_DNS,
	.layer		 = PROTO_L7,
	.header_init	 = dns_header_init,
	.header_finish   = dns_header_finish,
	.push_sub_header = dns_push_sub_header,
};

void protos_l7_init(void)
{
	proto_ops_register(&dns_proto_ops);
}

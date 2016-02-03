/*
 * netsniff-ng - the packet sniffing beast
 * Subject to the GPL, version 2.
 */

#include <stddef.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/if_ether.h>

#include "dev.h"
#include "xmalloc.h"
#include "trafgen_conf.h"
#include "trafgen_l2.h"
#include "trafgen_l3.h"
#include "trafgen_l4.h"
#include "trafgen_proto.h"

#define field_shift_and_mask(f, v) (((v) << (f)->shift) & \
		((f)->mask ? (f)->mask : (0xffffffff)))

#define field_unmask_and_unshift(f, v) (((v) & \
		((f)->mask ? (f)->mask : (0xffffffff))) >> (f)->shift)

static struct proto_ctx ctx;

#define PROTO_MAX_LAYERS	16

static struct proto_hdr *headers[PROTO_MAX_LAYERS];
static size_t headers_count;

static struct proto_hdr *registered;

static inline struct proto_hdr *proto_current_header(void)
{
	if (headers_count > 0)
		return headers[headers_count - 1];

	panic("No header was added\n");
}

struct proto_hdr *proto_lower_header(struct proto_hdr *hdr)
{
	struct proto_hdr *lower = NULL;
	size_t i;

	if (headers_count == 0)
		return NULL;

	for (i = 1, lower = headers[0]; i < headers_count; i++) {
		if (headers[i] == hdr)
			return headers[i - 1];
	}

	return lower;
}

uint8_t *proto_header_ptr(struct proto_hdr *hdr)
{
	return &current_packet()->payload[hdr->pkt_offset];
}

static struct proto_hdr *proto_header_by_id(enum proto_id id)
{
	struct proto_hdr *p = registered;

	for (; p; p = p->next)
		if (p->id == id)
			return p;

	panic("Can't lookup proto by id %u\n", id);
}

void proto_header_register(struct proto_hdr *hdr)
{
	hdr->next = registered;
	registered = hdr;

	hdr->fields = NULL;
	hdr->fields_count = 0;
}

static void proto_fields_realloc(struct proto_hdr *hdr, size_t count)
{
	hdr->fields = xrealloc(hdr->fields, count * sizeof(*hdr->fields));
	hdr->fields_count = count;
}

void proto_header_fields_add(struct proto_hdr *hdr,
			     const struct proto_field *fields, size_t count)
{
	struct packet *pkt = current_packet();
	struct proto_field *f;
	int i;

	if (!hdr->fields)
		hdr->pkt_offset = pkt->len;

	proto_fields_realloc(hdr, hdr->fields_count + count);

	for (i = 0; count >= 1; count--, i++) {
		f = &hdr->fields[hdr->fields_count - count];

		f->id = fields[i].id;
		f->len = fields[i].len;
		f->is_set = false;
		f->shift = fields[i].shift;
		f->mask = fields[i].mask;
		f->pkt_offset = hdr->pkt_offset + fields[i].offset;

		if (f->pkt_offset + f->len > pkt->len)
			set_fill(0, (f->pkt_offset + f->len) - pkt->len);
	}
}

static struct proto_field *proto_field_by_id(struct proto_hdr *hdr, uint32_t fid)
{
	int i;

	for (i = 0; i < hdr->fields_count; i++)
		if (hdr->fields[i].id == fid)
			return &hdr->fields[i];

	panic("Failed lookup field id %u for proto id %u\n", fid, hdr->id);
}

bool proto_field_is_set(struct proto_hdr *hdr, uint32_t fid)
{
	struct proto_field *field = proto_field_by_id(hdr, fid);

	return field ? field->is_set : false;
}

struct proto_hdr *proto_header_init(enum proto_id pid)
{
	struct proto_hdr *hdr = proto_header_by_id(pid);
	struct proto_hdr *new_hdr;

	if (headers_count >= PROTO_MAX_LAYERS)
		panic("Too many proto headers\n");

	new_hdr = xmalloc(sizeof(*new_hdr));
	memcpy(new_hdr, hdr, sizeof(*new_hdr));

	if (new_hdr->header_init)
		new_hdr->header_init(new_hdr);

	headers[headers_count++] = new_hdr;
	return new_hdr;
}

void proto_header_finish(struct proto_hdr *hdr)
{
	if (hdr && hdr->header_finish)
		hdr->header_finish(hdr);
}

struct proto_hdr *proto_lower_default_add(struct proto_hdr *hdr,
					  enum proto_id pid)
{
	struct proto_hdr *current;

	if (headers_count > 0) {
		current = proto_current_header();

		if (current->layer >= proto_header_by_id(pid)->layer)
			goto set_proto;
		if (current->id == pid)
			goto set_proto;
	}

	current = proto_header_init(pid);

set_proto:
	if (current->set_next_proto)
		current->set_next_proto(current, hdr->id);

	return current;
}

static void __proto_field_set_bytes(struct proto_hdr *hdr, uint32_t fid,
				    uint8_t *bytes, bool is_default, bool is_be)
{
	struct proto_field *field;
	uint8_t *payload;
	uint32_t v32;
	uint16_t v16;
	uint8_t v8;

	field = proto_field_by_id(hdr, fid);

	if (is_default && field->is_set)
		return;

	payload = &current_packet()->payload[field->pkt_offset];

	if (field->len == 1) {
		v8 = field_shift_and_mask(field, *bytes);
		v8 = field->mask ? (v8 | *payload) : v8;
		bytes = &v8;
	} else if (field->len == 2) {
		v16 = field_shift_and_mask(field, *(uint16_t *)bytes);
		v16 = is_be ? cpu_to_be16(v16) : v16;
		v16 = field->mask ? (v16 | *(uint16_t *)payload) : v16;
		bytes = (uint8_t *)&v16;
	} else if (field->len == 4) {
		v32 = field_shift_and_mask(field, *(uint32_t *)bytes);
		v32 = is_be ? cpu_to_be32(v32) : v32;
		v32 = field->mask ? (v32 | *(uint32_t *)payload) : v32;
		bytes = (uint8_t *)&v32;
	}

	memcpy(payload, bytes, field->len);

	if (!is_default)
		field->is_set = true;
}

void proto_field_set_bytes(struct proto_hdr *hdr, uint32_t fid, uint8_t *bytes)
{
	__proto_field_set_bytes(hdr, fid, bytes, false, false);
}

static uint8_t *__proto_field_get_bytes(struct proto_field *field)
{
	struct packet *pkt = current_packet();

	return &pkt->payload[field->pkt_offset];
}

void proto_field_set_u8(struct proto_hdr *hdr, uint32_t fid, uint8_t val)
{
	proto_field_set_bytes(hdr, fid, (uint8_t *)&val);
}

uint8_t proto_field_get_u8(struct proto_hdr *hdr, uint32_t fid)
{
	struct proto_field *field = proto_field_by_id(hdr, fid);
	uint8_t val = *__proto_field_get_bytes(field);

	return field_unmask_and_unshift(field, val);
}

void proto_field_set_u16(struct proto_hdr *hdr, uint32_t fid, uint16_t val)
{
	proto_field_set_bytes(hdr, fid, (uint8_t *)&val);
}

uint16_t proto_field_get_u16(struct proto_hdr *hdr, uint32_t fid)
{
	struct proto_field *field = proto_field_by_id(hdr, fid);
	uint16_t val = *(uint16_t *)__proto_field_get_bytes(field);

	return field_unmask_and_unshift(field, be16_to_cpu(val));
}

void proto_field_set_u32(struct proto_hdr *hdr, uint32_t fid, uint32_t val)
{
	proto_field_set_bytes(hdr, fid, (uint8_t *)&val);
}

uint32_t proto_field_get_u32(struct proto_hdr *hdr, uint32_t fid)
{
	struct proto_field *field = proto_field_by_id(hdr, fid);
	uint32_t val = *(uint32_t *)__proto_field_get_bytes(field);

	return field_unmask_and_unshift(field, be32_to_cpu(val));
}

void proto_field_set_default_bytes(struct proto_hdr *hdr, uint32_t fid, uint8_t *bytes)
{
	__proto_field_set_bytes(hdr, fid, bytes, true, false);
}

void proto_field_set_default_u8(struct proto_hdr *hdr, uint32_t fid, uint8_t val)
{
	__proto_field_set_bytes(hdr, fid, (uint8_t *)&val, true, false);
}

void proto_field_set_default_u16(struct proto_hdr *hdr, uint32_t fid, uint16_t val)
{
	__proto_field_set_bytes(hdr, fid, (uint8_t *)&val, true, false);
}

void proto_field_set_default_u32(struct proto_hdr *hdr, uint32_t fid, uint32_t val)
{
	__proto_field_set_bytes(hdr, fid, (uint8_t *)&val, true, false);
}

void proto_field_set_be16(struct proto_hdr *hdr, uint32_t fid, uint16_t val)
{
	__proto_field_set_bytes(hdr, fid, (uint8_t *)&val, false, true);
}

void proto_field_set_be32(struct proto_hdr *hdr, uint32_t fid, uint32_t val)
{
	__proto_field_set_bytes(hdr, fid, (uint8_t *)&val, false, true);
}

void proto_field_set_default_be16(struct proto_hdr *hdr, uint32_t fid, uint16_t val)
{
	__proto_field_set_bytes(hdr, fid, (uint8_t *)&val, true, true);
}

void proto_field_set_default_be32(struct proto_hdr *hdr, uint32_t fid, uint32_t val)
{
	__proto_field_set_bytes(hdr, fid, (uint8_t *)&val, true, true);
}

static void __proto_field_set_dev_mac(struct proto_hdr *hdr, uint32_t fid,
				      bool is_default)
{
	uint8_t mac[ETH_ALEN];
	int ret;

	if (proto_field_is_set(hdr, fid))
		return;

	if (!hdr->ctx->dev)
		panic("Device is not specified\n");

	ret = device_hw_address(hdr->ctx->dev, mac, sizeof(mac));
	if (ret < 0)
		panic("Could not get device hw address\n");

	__proto_field_set_bytes(hdr, fid, mac, is_default, false);
}

void proto_field_set_dev_mac(struct proto_hdr *hdr, uint32_t fid)
{
	__proto_field_set_dev_mac(hdr, fid, false);
}

void proto_field_set_default_dev_mac(struct proto_hdr *hdr, uint32_t fid)
{
	__proto_field_set_dev_mac(hdr, fid, true);
}

static void __proto_field_set_dev_ipv4(struct proto_hdr *hdr, uint32_t fid,
				       bool is_default)
{
	struct sockaddr_storage ss = { };
	struct sockaddr_in *ss4;
	uint32_t ip_addr;
	int ret;

	if (proto_field_is_set(hdr, fid))
		return;

	ret = device_address(hdr->ctx->dev, AF_INET, &ss);
	if (ret < 0)
		panic("Could not get device IPv4 address\n");

	ss4 = (struct sockaddr_in *) &ss;
	ip_addr = ss4->sin_addr.s_addr;

	__proto_field_set_bytes(hdr, fid, (uint8_t *)&ip_addr, is_default, false);
}

void proto_field_set_dev_ipv4(struct proto_hdr *hdr, uint32_t fid)
{
	__proto_field_set_dev_ipv4(hdr, fid, false);
}

void proto_field_set_default_dev_ipv4(struct proto_hdr *hdr, uint32_t fid)
{
	__proto_field_set_dev_ipv4(hdr, fid, true);
}

void protos_init(const char *dev)
{
	struct proto_hdr *p;

	ctx.dev = dev;

	protos_l2_init();
	protos_l3_init();
	protos_l4_init();

	for (p = registered; p; p = p->next)
		p->ctx = &ctx;
}

void proto_packet_finish(void)
{
	ssize_t i;

	/* Go down from upper layers to do last calculations (checksum) */
	for (i = headers_count - 1; i >= 0; i--) {
		struct proto_hdr *p = headers[i];

		if (p->packet_finish)
			p->packet_finish(p);
	}

	for (i = 0; i < headers_count; i++) {
		struct proto_hdr *p = headers[i];

		if (p->fields) {
			xfree(p->fields);
			p->fields_count = 0;
		}

		xfree(headers[i]);
	}

	headers_count = 0;
}

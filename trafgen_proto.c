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

struct ctx {
	const char *dev;
};
static struct ctx ctx;

static const struct proto_ops *registered_ops[__PROTO_MAX];

struct proto_hdr *proto_lower_header(struct proto_hdr *hdr)
{
	struct packet *pkt = packet_get(hdr->pkt_id);
	struct proto_hdr **headers = &pkt->headers[0];

	if (hdr->index == 0)
		return NULL;

	return headers[hdr->index - 1];
}

struct proto_hdr *proto_upper_header(struct proto_hdr *hdr)
{
	struct packet *pkt = packet_get(hdr->pkt_id);
	struct proto_hdr **headers = &pkt->headers[0];
	size_t headers_count = pkt->headers_count;

	if (hdr->index == headers_count - 1)
		return NULL;

	return headers[hdr->index + 1];
}

uint8_t *proto_header_ptr(struct proto_hdr *hdr)
{
	return &packet_get(hdr->pkt_id)->payload[hdr->pkt_offset];
}

static const struct proto_ops *proto_ops_by_id(enum proto_id id)
{
	const struct proto_ops *ops = registered_ops[id];

	bug_on(ops->id != id);
	return ops;
}

void proto_ops_register(const struct proto_ops *ops)
{
	bug_on(ops->id >= __PROTO_MAX);
	registered_ops[ops->id] = ops;
}

static void proto_fields_realloc(struct proto_hdr *hdr, size_t count)
{
	hdr->fields = xrealloc(hdr->fields, count * sizeof(*hdr->fields));
	hdr->fields_count = count;
}

void proto_header_fields_add(struct proto_hdr *hdr,
			     const struct proto_field *fields, size_t count)
{
	struct packet *pkt = packet_get(hdr->pkt_id);
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
		f->hdr = hdr;

		if (f->pkt_offset + f->len > pkt->len) {
			hdr->len += f->len;
			set_fill(0, (f->pkt_offset + f->len) - pkt->len);
		}
	}
}

struct proto_field *proto_field_by_id(struct proto_hdr *hdr, uint32_t fid)
{
	/* Assume the fields are stored in the same order as the respective
	 * enum, so the index can be used for faster lookup here.
	 */
	bug_on(hdr->fields[fid].id != fid);

	return &hdr->fields[fid];
}

bool proto_field_is_set(struct proto_hdr *hdr, uint32_t fid)
{
	struct proto_field *field = proto_field_by_id(hdr, fid);

	return field ? field->is_set : false;
}

struct proto_hdr *proto_header_push(enum proto_id pid)
{
	struct packet *pkt = current_packet();
	struct proto_hdr **headers = &pkt->headers[0];
	const struct proto_ops *ops = proto_ops_by_id(pid);
	struct proto_hdr *hdr;

	bug_on(pkt->headers_count >= PROTO_MAX_LAYERS);

	hdr = xzmalloc(sizeof(*hdr));
	hdr->ops = ops;
	hdr->pkt_id = current_packet_id();

	if (ops && ops->header_init)
		ops->header_init(hdr);

	/* This is very important to have it after header_init as
	 * pkt->headers_count might be changed by adding default lower headers */
	hdr->index = pkt->headers_count;

	headers[pkt->headers_count++] = hdr;
	return hdr;
}

void proto_header_finish(struct proto_hdr *hdr)
{
	if (hdr && hdr->ops && hdr->ops->header_finish)
		hdr->ops->header_finish(hdr);
}

struct proto_hdr *proto_lower_default_add(struct proto_hdr *upper,
					  enum proto_id pid)
{
	struct proto_hdr *current;
	size_t headers_count = current_packet()->headers_count;
	const struct proto_ops *ops;

	if (headers_count > 0) {
		current = current_packet()->headers[headers_count - 1];
		ops = current->ops;

		if (ops->layer >= proto_ops_by_id(pid)->layer)
			goto set_proto;
		if (ops->id == pid)
			goto set_proto;
	}

	current = proto_header_push(pid);
	ops = current->ops;

set_proto:
	if (ops && ops->set_next_proto)
		ops->set_next_proto(current, upper->ops->id);

	return current;
}

static void __proto_field_set_bytes(struct proto_hdr *hdr, uint32_t fid,
				    const uint8_t *bytes, bool is_default,
				    bool is_be)
{
	struct proto_field *field;
	uint8_t *payload, *p8;
	uint16_t *p16;
	uint32_t *p32;
	uint32_t v32;
	uint16_t v16;
	uint8_t v8;

	field = proto_field_by_id(hdr, fid);

	if (is_default && field->is_set)
		return;

	payload = &packet_get(hdr->pkt_id)->payload[field->pkt_offset];

	if (field->len == 1) {
		p8 = payload;
		*p8 = field->mask ? *p8 & ~field->mask : *p8;

		v8 = field_shift_and_mask(field, *bytes);
		v8 = field->mask ? (v8 | *p8) : v8;

		bytes = &v8;
	} else if (field->len == 2) {
		p16 = (uint16_t *)payload;
		*p16 = be16_to_cpu(*p16);
		*p16 = cpu_to_be16(field->mask ? *p16 & ~field->mask : *p16);

		v16 = field_shift_and_mask(field, *(const uint16_t *)bytes);
		v16 = is_be ? cpu_to_be16(v16) : v16;
		v16 = field->mask ? (v16 | *p16) : v16;

		bytes = (uint8_t *)&v16;
	} else if (field->len == 4) {
		p32 = (uint32_t *)payload;
		*p32 = be32_to_cpu(*p32);
		*p32 = cpu_to_be32(field->mask ? *p32 & ~field->mask : *p32);

		v32 = field_shift_and_mask(field, *(const uint32_t *)bytes);
		v32 = is_be ? cpu_to_be32(v32) : v32;
		v32 = field->mask ? (v32 | *p32) : v32;

		bytes = (uint8_t *)&v32;
	}

	memcpy(payload, bytes, field->len);

	if (!is_default)
		field->is_set = true;
}

void proto_field_set_bytes(struct proto_hdr *hdr, uint32_t fid,
			   const uint8_t *bytes)
{
	__proto_field_set_bytes(hdr, fid, bytes, false, false);
}

static uint8_t *__proto_field_get_bytes(struct proto_field *field)
{
	return &packet_get(field->hdr->pkt_id)->payload[field->pkt_offset];
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

void proto_field_set_default_bytes(struct proto_hdr *hdr, uint32_t fid,
				   const uint8_t *bytes)
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

	ret = device_hw_address(ctx.dev, mac, sizeof(mac));
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
	int ret;

	if (proto_field_is_set(hdr, fid))
		return;

	ret = device_address(ctx.dev, AF_INET, &ss);
	if (ret < 0) {
		fprintf(stderr, "Warning: Could not get device IPv4 address for %s\n", ctx.dev);
		return;
	}

	ss4 = (struct sockaddr_in *) &ss;
	__proto_field_set_bytes(hdr, fid, (uint8_t *)&ss4->sin_addr.s_addr, is_default, false);
}

void proto_field_set_dev_ipv4(struct proto_hdr *hdr, uint32_t fid)
{
	__proto_field_set_dev_ipv4(hdr, fid, false);
}

void proto_field_set_default_dev_ipv4(struct proto_hdr *hdr, uint32_t fid)
{
	__proto_field_set_dev_ipv4(hdr, fid, true);
}

static void __proto_field_set_dev_ipv6(struct proto_hdr *hdr, uint32_t fid,
				       bool is_default)
{
	struct sockaddr_storage ss = { };
	struct sockaddr_in6 *ss6;
	int ret;

	if (proto_field_is_set(hdr, fid))
		return;

	ret = device_address(ctx.dev, AF_INET6, &ss);
	if (ret < 0) {
		fprintf(stderr, "Warning: Could not get device IPv6 address for %s\n", ctx.dev);
		return;
	}

	ss6 = (struct sockaddr_in6 *) &ss;
	__proto_field_set_bytes(hdr, fid, (uint8_t *)&ss6->sin6_addr.s6_addr, is_default, false);
}

void proto_field_set_dev_ipv6(struct proto_hdr *hdr, uint32_t fid)
{
	__proto_field_set_dev_ipv6(hdr, fid, false);
}

void proto_field_set_default_dev_ipv6(struct proto_hdr *hdr, uint32_t fid)
{
	__proto_field_set_dev_ipv6(hdr, fid, true);
}

void protos_init(const char *dev)
{
	ctx.dev = dev;

	protos_l2_init();
	protos_l3_init();
	protos_l4_init();
}

void proto_packet_update(uint32_t idx)
{
	struct packet *pkt = packet_get(idx);
	ssize_t i;

	for (i = pkt->headers_count - 1; i >= 0; i--) {
		struct proto_hdr *hdr = pkt->headers[i];

		if (hdr->ops->packet_update)
			hdr->ops->packet_update(hdr);
	}
}

void proto_packet_finish(void)
{
	struct proto_hdr **headers = current_packet()->headers;
	size_t headers_count = current_packet()->headers_count;
	ssize_t i;

	/* Go down from upper layers to do last calculations (checksum) */
	for (i = headers_count - 1; i >= 0; i--) {
		struct proto_hdr *hdr = headers[i];
		const struct proto_ops *ops = hdr->ops;

		if (ops && ops->packet_finish)
			ops->packet_finish(hdr);
	}
}

static inline uint32_t field_inc(struct proto_field *field)
{
	uint32_t min = field->func.min;
	uint32_t max = field->func.max;
	uint32_t val = field->func.val;
	uint32_t inc = field->func.inc;
	uint32_t next;

	next = (val + inc) % (max + 1);
	field->func.val = max(next, min);

	return val;
}

static void field_inc_func(struct proto_field *field)
{
	if (field->len == 1) {
		proto_field_set_u8(field->hdr, field->id, field_inc(field));
	} else if (field->len == 2) {
		proto_field_set_be16(field->hdr, field->id, field_inc(field));
	} else if (field->len == 4) {
		proto_field_set_be32(field->hdr, field->id, field_inc(field));
	} else if (field->len > 4) {
		uint8_t *bytes = __proto_field_get_bytes(field);

		bytes += field->len - 4;

		*(uint32_t *)bytes = bswap_32(field_inc(field));
	}
}

static inline uint32_t field_rand(struct proto_field *field)
{
	return field->func.min + (rand() % ((field->func.max - field->func.min) + 1));
}

static void field_rnd_func(struct proto_field *field)
{
	if (field->len == 1) {
		proto_field_set_u8(field->hdr, field->id,
				    (uint8_t) field_rand(field));
	} else if (field->len == 2) {
		proto_field_set_be16(field->hdr, field->id,
				    (uint16_t) field_rand(field));
	} else if (field->len == 4) {
		proto_field_set_be32(field->hdr, field->id,
				    (uint32_t) field_rand(field));
	} else if (field->len > 4) {
		uint8_t *bytes = __proto_field_get_bytes(field);
		uint32_t i;

		for (i = 0; i < field->len; i++)
			bytes[i] = (uint8_t) field_rand(field);
	}
}

void proto_field_func_add(struct proto_hdr *hdr, uint32_t fid,
			  struct proto_field_func *func)
{
	struct proto_field *field = proto_field_by_id(hdr, fid);

	bug_on(!func);

	field->func.update_field = func->update_field;
	field->func.type = func->type;
	field->func.max = func->max ?: UINT32_MAX - 1;
	field->func.min = func->min;
	field->func.inc = func->inc;

	if (func->type & PROTO_FIELD_FUNC_INC) {
		if (func->type & PROTO_FIELD_FUNC_MIN)
			field->func.val = func->min;
		else if (field->len == 1)
			field->func.val = proto_field_get_u8(hdr, fid);
		else if (field->len == 2)
			field->func.val = proto_field_get_u16(hdr, fid);
		else if (field->len == 4)
			field->func.val = proto_field_get_u32(hdr, fid);
		else if (field->len > 4) {
			uint8_t *bytes = __proto_field_get_bytes(field);

			bytes += field->len - 4;
			field->func.val = bswap_32(*(uint32_t *)bytes);
		}

		field->func.update_field = field_inc_func;
	} else if (func->type & PROTO_FIELD_FUNC_RND) {
		field->func.update_field = field_rnd_func;
	}
}

void proto_field_dyn_apply(struct proto_field *field)
{
	if (field->func.update_field)
		field->func.update_field(field);

	if (field->hdr->ops->field_changed)
		field->hdr->ops->field_changed(field);
}

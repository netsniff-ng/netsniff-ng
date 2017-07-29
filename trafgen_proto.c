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
#include "trafgen_l7.h"
#include "trafgen_proto.h"

#define field_shift_and_mask(f, v) (((v) << (f)->shift) & \
		((f)->mask ? (f)->mask : (0xffffffff)))

#define field_unmask_and_unshift(f, v) (((v) & \
		((f)->mask ? (f)->mask : (0xffffffff))) >> (f)->shift)

struct ctx {
	struct dev_io *dev;
};
static struct ctx ctx;

static const struct proto_ops *registered_ops[__PROTO_MAX];

struct packet *proto_hdr_packet(struct proto_hdr *hdr)
{
	return packet_get(hdr->pkt_id);
}

struct proto_hdr *packet_last_header(struct packet *pkt)
{
	struct proto_hdr **headers = &pkt->headers[0];

	if (pkt->headers_count == 0)
		return NULL;

	return headers[pkt->headers_count - 1];
}

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

	if (pkt->headers_count > 0) {
		struct proto_hdr *last = packet_last_header(pkt);
		bug_on(!last);

		hdr->pkt_offset = last->pkt_offset + last->len;
	}

	proto_fields_realloc(hdr, hdr->fields_count + count);

	for (i = 0; count >= 1; count--, i++) {
		int fill_len;

		f = &hdr->fields[hdr->fields_count - count];

		f->id = fields[i].id;
		f->len = fields[i].len;
		f->is_set = false;
		f->shift = fields[i].shift;
		f->mask = fields[i].mask;
		f->pkt_offset = hdr->pkt_offset + fields[i].offset;
		f->hdr = hdr;

		if (!f->len)
			continue;

		fill_len = (f->pkt_offset + f->len) - (hdr->pkt_offset + hdr->len);
		if (fill_len > 0) {
			if (!pkt->is_created)
				set_fill(0, (f->pkt_offset + f->len) - pkt->len);

			hdr->len += f->len;
		}
	}
}

struct proto_field *proto_hdr_field_by_id(struct proto_hdr *hdr, uint32_t fid)
{
	/* Assume the fields are stored in the same order as the respective
	 * enum, so the index can be used for faster lookup here.
	 */
	bug_on(hdr->fields[fid].id != fid);

	return &hdr->fields[fid];
}

bool proto_hdr_field_is_set(struct proto_hdr *hdr, uint32_t fid)
{
	struct proto_field *field = proto_hdr_field_by_id(hdr, fid);

	return field ? field->is_set : false;
}

struct proto_hdr *proto_packet_apply(enum proto_id pid, struct packet *pkt)
{
	struct proto_hdr **headers = &pkt->headers[0];
	const struct proto_ops *ops = proto_ops_by_id(pid);
	struct proto_hdr *hdr;

	bug_on(pkt->headers_count >= PROTO_MAX_LAYERS);

	hdr = xzmalloc(sizeof(*hdr));
	hdr->ops = ops;
	hdr->pkt_id = pkt->id;

	if (ops && ops->header_init)
		ops->header_init(hdr);

	/* This is very important to have it after header_init as
	 * pkt->headers_count might be changed by adding default lower headers */
	hdr->index = pkt->headers_count;

	headers[pkt->headers_count++] = hdr;
	return hdr;
}

struct proto_hdr *proto_header_push(enum proto_id pid)
{
	return proto_packet_apply(pid, current_packet());
}

void proto_header_finish(struct proto_hdr *hdr)
{
	if (hdr && hdr->ops && hdr->ops->header_finish)
		hdr->ops->header_finish(hdr);
}

enum proto_id proto_hdr_get_next_proto(struct proto_hdr *hdr)
{
	if (hdr->ops && hdr->ops->get_next_proto)
		return hdr->ops->get_next_proto(hdr);

	return __PROTO_MAX;
}

struct proto_hdr *proto_hdr_push_sub_header(struct proto_hdr *hdr, int id)
{
	struct proto_hdr *sub_hdr;

	sub_hdr = xzmalloc(sizeof(struct proto_hdr));
	sub_hdr->index = hdr->sub_headers_count;
	sub_hdr->parent = hdr;
	sub_hdr->id = id;

	hdr->sub_headers_count++;
	hdr->sub_headers = xrealloc(hdr->sub_headers,
				    hdr->sub_headers_count * sizeof(struct proto_hdr *));

	hdr->sub_headers[hdr->sub_headers_count - 1] = sub_hdr;

	if (hdr->ops->push_sub_header)
		hdr->ops->push_sub_header(hdr, sub_hdr);

	if (sub_hdr->ops->header_init)
		sub_hdr->ops->header_init(sub_hdr);

	return sub_hdr;
}

static void __proto_hdr_set_offset(struct proto_hdr *hdr, uint16_t pkt_offset)
{
	size_t i;

	hdr->pkt_offset = pkt_offset;

	for (i = 0; i < hdr->fields_count; i++) {
		struct proto_field *f = &hdr->fields[i];

		f->pkt_offset = pkt_offset + f->offset;
	}
}

void proto_hdr_move_sub_header(struct proto_hdr *hdr, struct proto_hdr *from,
			       struct proto_hdr *to)
{
	struct proto_hdr *src_hdr, *dst_hdr, *tmp;
	uint8_t *src_ptr, *dst_ptr;
	uint16_t to_pkt_offset;
	uint16_t to_index;
	uint16_t pkt_offset;
	int idx_shift;
	size_t len = 0;
	uint8_t *buf;
	int i;

	if (hdr->sub_headers_count < 2)
		return;
	if (from->index == to->index)
		return;

	buf = xmemdupz(proto_header_ptr(from), from->len);

	to_pkt_offset = to->pkt_offset;
	to_index = to->index;

	if (from->index < to->index) {
		src_hdr = hdr->sub_headers[from->index + 1];
		dst_hdr = to;

		src_ptr = proto_header_ptr(src_hdr);
		dst_ptr = proto_header_ptr(from);
		len = (to->pkt_offset + to->len) - src_hdr->pkt_offset;

		pkt_offset = from->pkt_offset;
		idx_shift = 1;
	} else {
		src_hdr = to;
		dst_hdr = hdr->sub_headers[from->index - 1];

		src_ptr = proto_header_ptr(src_hdr);
		dst_ptr = src_ptr + from->len;
		len = from->pkt_offset - to->pkt_offset;

		pkt_offset = to->pkt_offset + from->len;
		idx_shift = -1;
	}

	hdr->sub_headers[from->index] = to;
	hdr->sub_headers[to->index] = from;

	for (i = src_hdr->index; i <= dst_hdr->index; i++) {
		tmp = hdr->sub_headers[i];

		__proto_hdr_set_offset(tmp, pkt_offset);
		pkt_offset += tmp->len;
	}

	for (i = src_hdr->index; i <= dst_hdr->index; i++)
		hdr->sub_headers[i]->index = i + idx_shift;

	memmove(dst_ptr, src_ptr, len);

	from->pkt_offset = to_pkt_offset;
	from->index = to_index;

	memcpy(proto_header_ptr(from), buf, from->len);

	xfree(buf);
}

struct proto_hdr *proto_lower_default_add(struct proto_hdr *upper,
					  enum proto_id pid)
{
	struct packet *pkt = proto_hdr_packet(upper);
	size_t headers_count = pkt->headers_count;
	struct proto_hdr *current;
	const struct proto_ops *ops;

	if (headers_count > 0) {
		current = pkt->headers[headers_count - 1];
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

static void __proto_field_relocate(struct proto_field *field)
{
	struct proto_hdr *hdr = field->hdr;
	struct packet *pkt = packet_get(hdr->pkt_id);
	uint8_t *from, *to;
	int i;

	/* If this is a last field then just calculate 'pkt_offset' */
	if (field->id == hdr->fields_count - 1) {
		field->pkt_offset = hdr->pkt_offset + hdr->len - field->len;
		return;
	}

	/* Use 'pkt_offset' from the 1st real (len > 0) field after the
	 * 'target' one */
	for (i = field->id + 1; i < hdr->fields_count; i++) {
		if (hdr->fields[i].len == 0)
			continue;

		field->pkt_offset = hdr->fields[i].pkt_offset;
		break;
	}

	/* Move payload of overlapped fields (each after the 'target' field) */
	from = &pkt->payload[field->pkt_offset];
	to = &pkt->payload[field->pkt_offset + field->len];
	memcpy(to, from, hdr->len - field->len);

	/* Recalculate 'pkt_offset' of the rest fields */
	for (; i < hdr->fields_count; i++) {
		struct proto_field *tmp = &hdr->fields[i];

		if (tmp->len == 0)
			continue;

		tmp->pkt_offset += field->len;
	}
}

static void __proto_field_set_bytes(struct proto_field *field,
				    const uint8_t *bytes, size_t len,
				    bool is_default, bool is_be)
{
	uint8_t *payload, *p8;
	uint16_t *p16;
	uint32_t *p32;
	uint32_t v32;
	uint16_t v16;
	uint8_t v8;

	if (is_default && field->is_set)
		return;

	if (field->len == 0) {
		field->hdr->len += len;
		field->len = len;
		set_fill(0, len);

		__proto_field_relocate(field);
	}

	payload = &packet_get(field->hdr->pkt_id)->payload[field->pkt_offset];

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

void proto_hdr_field_set_bytes(struct proto_hdr *hdr, uint32_t fid,
			       const uint8_t *bytes, size_t len)
{
	struct proto_field *field = proto_hdr_field_by_id(hdr, fid);

	__proto_field_set_bytes(field, bytes, len, false, false);
}

static uint8_t *__proto_field_get_bytes(struct proto_field *field)
{
	return &packet_get(field->hdr->pkt_id)->payload[field->pkt_offset];
}

uint8_t *proto_hdr_field_get_bytes(struct proto_hdr *hdr, uint32_t fid)
{
	struct proto_field *field = proto_hdr_field_by_id(hdr, fid);

	return __proto_field_get_bytes(field);
}

void proto_hdr_field_set_u8(struct proto_hdr *hdr, uint32_t fid, uint8_t val)
{
	proto_hdr_field_set_bytes(hdr, fid, (uint8_t *)&val, 1);
}

uint8_t proto_hdr_field_get_u8(struct proto_hdr *hdr, uint32_t fid)
{
	struct proto_field *field = proto_hdr_field_by_id(hdr, fid);
	uint8_t val = *__proto_field_get_bytes(field);

	return field_unmask_and_unshift(field, val);
}

void proto_hdr_field_set_u16(struct proto_hdr *hdr, uint32_t fid, uint16_t val)
{
	proto_hdr_field_set_bytes(hdr, fid, (uint8_t *)&val, 2);
}

uint16_t proto_hdr_field_get_u16(struct proto_hdr *hdr, uint32_t fid)
{
	struct proto_field *field = proto_hdr_field_by_id(hdr, fid);
	uint16_t val = *(uint16_t *)__proto_field_get_bytes(field);

	return field_unmask_and_unshift(field, be16_to_cpu(val));
}

void proto_hdr_field_set_u32(struct proto_hdr *hdr, uint32_t fid, uint32_t val)
{
	proto_hdr_field_set_bytes(hdr, fid, (uint8_t *)&val, 4);
}

uint32_t proto_hdr_field_get_u32(struct proto_hdr *hdr, uint32_t fid)
{
	struct proto_field *field = proto_hdr_field_by_id(hdr, fid);
	uint32_t val = *(uint32_t *)__proto_field_get_bytes(field);

	return field_unmask_and_unshift(field, be32_to_cpu(val));
}

uint32_t proto_hdr_field_get_be32(struct proto_hdr *hdr, uint32_t fid)
{
	struct proto_field *field = proto_hdr_field_by_id(hdr, fid);
	uint32_t val = *(uint32_t *)__proto_field_get_bytes(field);

	return field_unmask_and_unshift(field, val);
}

void proto_hdr_field_set_default_bytes(struct proto_hdr *hdr, uint32_t fid,
				       const uint8_t *bytes, size_t len)
{
	struct proto_field *field = proto_hdr_field_by_id(hdr, fid);

	__proto_field_set_bytes(field, bytes, len, true, false);
}

void proto_hdr_field_set_default_u8(struct proto_hdr *hdr, uint32_t fid, uint8_t val)
{
	struct proto_field *field = proto_hdr_field_by_id(hdr, fid);

	__proto_field_set_bytes(field, (uint8_t *)&val, 1, true, false);
}

void proto_hdr_field_set_default_u16(struct proto_hdr *hdr, uint32_t fid, uint16_t val)
{
	struct proto_field *field = proto_hdr_field_by_id(hdr, fid);

	__proto_field_set_bytes(field, (uint8_t *)&val, 2, true, false);
}

void proto_hdr_field_set_default_u32(struct proto_hdr *hdr, uint32_t fid, uint32_t val)
{
	struct proto_field *field = proto_hdr_field_by_id(hdr, fid);

	__proto_field_set_bytes(field, (uint8_t *)&val, 4, true, false);
}

void proto_hdr_field_set_be16(struct proto_hdr *hdr, uint32_t fid, uint16_t val)
{
	struct proto_field *field = proto_hdr_field_by_id(hdr, fid);

	__proto_field_set_bytes(field, (uint8_t *)&val, 2, false, true);
}

void proto_hdr_field_set_be32(struct proto_hdr *hdr, uint32_t fid, uint32_t val)
{
	struct proto_field *field = proto_hdr_field_by_id(hdr, fid);

	__proto_field_set_bytes(field, (uint8_t *)&val, 4, false, true);
}

void proto_hdr_field_set_default_be16(struct proto_hdr *hdr, uint32_t fid, uint16_t val)
{
	struct proto_field *field = proto_hdr_field_by_id(hdr, fid);

	__proto_field_set_bytes(field, (uint8_t *)&val, 2, true, true);
}

void proto_hdr_field_set_default_be32(struct proto_hdr *hdr, uint32_t fid, uint32_t val)
{
	struct proto_field *field = proto_hdr_field_by_id(hdr, fid);

	__proto_field_set_bytes(field, (uint8_t *)&val, 4, true, true);
}

static void __proto_hdr_field_set_dev_mac(struct proto_hdr *hdr, uint32_t fid,
					  bool is_default)
{
	struct proto_field *field = proto_hdr_field_by_id(hdr, fid);
	uint8_t mac[ETH_ALEN];
	int ret;

	if (proto_hdr_field_is_set(hdr, fid))
		return;

	if (dev_io_is_netdev(ctx.dev)) {
		ret = device_hw_address(dev_io_name_get(ctx.dev), mac, sizeof(mac));
		if (ret < 0)
			panic("Could not get device hw address\n");

		__proto_field_set_bytes(field, mac, 6, is_default, false);
	}
}

void proto_hdr_field_set_dev_mac(struct proto_hdr *hdr, uint32_t fid)
{
	__proto_hdr_field_set_dev_mac(hdr, fid, false);
}

void proto_hdr_field_set_default_dev_mac(struct proto_hdr *hdr, uint32_t fid)
{
	__proto_hdr_field_set_dev_mac(hdr, fid, true);
}

static void __proto_hdr_field_set_dev_ipv4(struct proto_hdr *hdr, uint32_t fid,
					   bool is_default)
{
	struct proto_field *field = proto_hdr_field_by_id(hdr, fid);
	struct sockaddr_storage ss = { };
	struct sockaddr_in *ss4;
	int ret;

	if (proto_hdr_field_is_set(hdr, fid))
		return;

	if (dev_io_is_netdev(ctx.dev)) {
		ret = device_address(dev_io_name_get(ctx.dev), AF_INET, &ss);
		if (ret < 0) {
			fprintf(stderr, "Warning: Could not get device IPv4 address for %s\n",
				dev_io_name_get(ctx.dev));
			return;
		}

		ss4 = (struct sockaddr_in *) &ss;
		__proto_field_set_bytes(field, (uint8_t *)&ss4->sin_addr.s_addr, 4, is_default, false);
	}
}

void proto_hdr_field_set_dev_ipv4(struct proto_hdr *hdr, uint32_t fid)
{
	__proto_hdr_field_set_dev_ipv4(hdr, fid, false);
}

void proto_hdr_field_set_default_dev_ipv4(struct proto_hdr *hdr, uint32_t fid)
{
	__proto_hdr_field_set_dev_ipv4(hdr, fid, true);
}

static void __proto_hdr_field_set_dev_ipv6(struct proto_hdr *hdr, uint32_t fid,
					   bool is_default)
{
	struct proto_field *field = proto_hdr_field_by_id(hdr, fid);
	struct sockaddr_storage ss = { };
	struct sockaddr_in6 *ss6;
	int ret;

	if (proto_hdr_field_is_set(hdr, fid))
		return;

	if (dev_io_is_netdev(ctx.dev)) {
		ret = device_address(dev_io_name_get(ctx.dev), AF_INET6, &ss);
		if (ret < 0) {
			fprintf(stderr, "Warning: Could not get device IPv6 address for %s\n",
				dev_io_name_get(ctx.dev));
			return;
		}

		ss6 = (struct sockaddr_in6 *) &ss;
		__proto_field_set_bytes(field, (uint8_t *)&ss6->sin6_addr.s6_addr, 16, is_default, false);
	}
}

void proto_hdr_field_set_dev_ipv6(struct proto_hdr *hdr, uint32_t fid)
{
	__proto_hdr_field_set_dev_ipv6(hdr, fid, false);
}

void proto_hdr_field_set_default_dev_ipv6(struct proto_hdr *hdr, uint32_t fid)
{
	__proto_hdr_field_set_dev_ipv6(hdr, fid, true);
}

void proto_hdr_field_set_string(struct proto_hdr *hdr, uint32_t fid, const char *str)
{
	proto_hdr_field_set_bytes(hdr, fid, (uint8_t *)str, strlen(str) + 1);
}

void proto_hdr_field_set_default_string(struct proto_hdr *hdr, uint32_t fid, const char *str)
{
	proto_hdr_field_set_default_bytes(hdr, fid, (uint8_t *)str, strlen(str) + 1);
}

void proto_field_set_u8(struct proto_field *field, uint8_t val)
{
	__proto_field_set_bytes(field, &val, 1, false, false);
}

uint8_t proto_field_get_u8(struct proto_field *field)
{
	uint8_t val = *__proto_field_get_bytes(field);

	return field_unmask_and_unshift(field, val);
}

void proto_field_set_u16(struct proto_field *field, uint16_t val)
{
	__proto_field_set_bytes(field, (uint8_t *)&val, 2, false, false);
}

uint16_t proto_field_get_u16(struct proto_field *field)
{
	uint16_t val = *(uint16_t *)__proto_field_get_bytes(field);

	return field_unmask_and_unshift(field, be16_to_cpu(val));
}

void proto_field_set_u32(struct proto_field *field, uint32_t val)
{
	__proto_field_set_bytes(field, (uint8_t *)&val, 4, false, false);
}

uint32_t proto_field_get_u32(struct proto_field *field)
{
	uint32_t val = *(uint32_t *)__proto_field_get_bytes(field);

	return field_unmask_and_unshift(field, be32_to_cpu(val));
}

uint32_t proto_field_get_be32(struct proto_field *field)
{
	uint32_t val = *(uint32_t *)__proto_field_get_bytes(field);

	return field_unmask_and_unshift(field, val);
}

void proto_field_set_be16(struct proto_field *field, uint16_t val)
{
	__proto_field_set_bytes(field, (uint8_t *)&val, 2, false, true);
}

void proto_field_set_be32(struct proto_field *field, uint32_t val)
{
	__proto_field_set_bytes(field, (uint8_t *)&val, 4, false, true);
}

void proto_field_set_bytes(struct proto_field *field, const uint8_t *bytes, size_t len)
{
	__proto_field_set_bytes(field, bytes, len, false, false);
}

void proto_field_set_string(struct proto_field *field, const char *str)
{
	proto_field_set_bytes(field, (uint8_t *)str, strlen(str) + 1);
}

void proto_field_set_default_string(struct proto_field *field, const char *str)
{
	__proto_field_set_bytes(field, (uint8_t *)str, strlen(str) + 1, true, false);
}

void protos_init(struct dev_io *dev)
{
	ctx.dev = dev;

	protos_l2_init();
	protos_l3_init();
	protos_l4_init();
	protos_l7_init();
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

	current_packet()->is_created = true;
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
		proto_field_set_u8(field, field_inc(field));
	} else if (field->len == 2) {
		proto_field_set_be16(field, field_inc(field));
	} else if (field->len == 4) {
		proto_field_set_be32(field, field_inc(field));
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
		proto_field_set_u8(field, (uint8_t) field_rand(field));
	} else if (field->len == 2) {
		proto_field_set_be16(field, (uint16_t) field_rand(field));
	} else if (field->len == 4) {
		proto_field_set_be32(field, (uint32_t) field_rand(field));
	} else if (field->len > 4) {
		uint8_t *bytes = __proto_field_get_bytes(field);
		uint32_t i;

		for (i = 0; i < field->len; i++)
			bytes[i] = (uint8_t) field_rand(field);
	}
}

void proto_field_func_add(struct proto_field *field,
			  struct proto_field_func *func)
{
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
			field->func.val = proto_field_get_u8(field);
		else if (field->len == 2)
			field->func.val = proto_field_get_u16(field);
		else if (field->len == 4)
			field->func.val = proto_field_get_u32(field);
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

struct dev_io *proto_dev_get(void)
{
	return ctx.dev;
}

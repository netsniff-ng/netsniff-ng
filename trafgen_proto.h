#ifndef TRAFGEN_PROTO_H
#define TRAFGEN_PROTO_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

struct proto_ctx {
	const char *dev;
};

enum proto_id {
	PROTO_NONE,
	PROTO_ETH,
	PROTO_VLAN,
	PROTO_ARP,
	PROTO_IP4,
	PROTO_IP6,
	PROTO_UDP,
	PROTO_TCP,
};

enum proto_layer {
	PROTO_L0, /* invalid layer */
	PROTO_L2,
	PROTO_L3,
	PROTO_L4,
};

struct proto_field {
	uint32_t id;
	size_t len;
	uint32_t shift;
	uint32_t mask;
	/* might be negative (e.g. VLAN TPID field) */
	int16_t offset;

	bool is_set;
	uint16_t pkt_offset;
};

struct proto_hdr {
	enum proto_id id;
	enum proto_layer layer;

	struct proto_hdr *next;
	struct proto_ctx *ctx;
	uint16_t pkt_offset;
	struct proto_field *fields;
	size_t fields_count;

	void (*header_init)(struct proto_hdr *hdr);
	void (*header_finish)(struct proto_hdr *hdr);
	void (*packet_finish)(struct proto_hdr *hdr);
	void (*set_next_proto)(struct proto_hdr *hdr, enum proto_id pid);
};

extern void protos_init(const char *dev);
extern void proto_header_register(struct proto_hdr *hdr);

extern struct proto_hdr *proto_header_init(enum proto_id pid);
extern void proto_header_finish(struct proto_hdr *hdr);
extern void proto_packet_finish(void);
extern struct proto_hdr *proto_lower_default_add(struct proto_hdr *hdr,
						 enum proto_id pid);

extern struct proto_hdr *proto_lower_header(struct proto_hdr *hdr);
extern uint8_t *proto_header_ptr(struct proto_hdr *hdr);

extern void proto_header_fields_add(struct proto_hdr *hdr,
				    const struct proto_field *fields,
				    size_t count);

extern bool proto_field_is_set(struct proto_hdr *hdr, uint32_t fid);
extern void proto_field_set_bytes(struct proto_hdr *hdr, uint32_t fid,
				  uint8_t *bytes);
extern void proto_field_set_u8(struct proto_hdr *hdr, uint32_t fid, uint8_t val);
extern uint8_t proto_field_get_u8(struct proto_hdr *hdr, uint32_t fid);
extern void proto_field_set_u16(struct proto_hdr *hdr, uint32_t fid, uint16_t val);
extern uint16_t proto_field_get_u16(struct proto_hdr *hdr, uint32_t fid);
extern void proto_field_set_u32(struct proto_hdr *hdr, uint32_t fid, uint32_t val);
extern uint32_t proto_field_get_u32(struct proto_hdr *hdr, uint32_t fid);

extern void proto_field_set_default_bytes(struct proto_hdr *hdr, uint32_t fid,
					  uint8_t *bytes);
extern void proto_field_set_default_u8(struct proto_hdr *hdr, uint32_t fid,
				       uint8_t val);
extern void proto_field_set_default_u16(struct proto_hdr *hdr, uint32_t fid,
				        uint16_t val);
extern void proto_field_set_default_u32(struct proto_hdr *hdr, uint32_t fid,
				        uint32_t val);

extern void proto_field_set_be16(struct proto_hdr *hdr, uint32_t fid, uint16_t val);
extern void proto_field_set_be32(struct proto_hdr *hdr, uint32_t fid, uint32_t val);

extern void proto_field_set_default_be16(struct proto_hdr *hdr, uint32_t fid,
					 uint16_t val);
extern void proto_field_set_default_be32(struct proto_hdr *hdr, uint32_t fid,
					 uint32_t val);

extern void proto_field_set_dev_mac(struct proto_hdr *hdr, uint32_t fid);
extern void proto_field_set_default_dev_mac(struct proto_hdr *hdr, uint32_t fid);

extern void proto_field_set_dev_ipv4(struct proto_hdr *hdr, uint32_t fid);
extern void proto_field_set_default_dev_ipv4(struct proto_hdr *hdr, uint32_t fid);

#endif /* TRAFGEN_PROTO_H */

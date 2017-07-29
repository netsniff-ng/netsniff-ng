#ifndef TRAFGEN_PROTO_H
#define TRAFGEN_PROTO_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "trafgen_dev.h"

struct packet;

enum proto_id {
	PROTO_NONE = 0,
	PROTO_ETH,
	PROTO_PAUSE,
	PROTO_PFC,
	PROTO_VLAN,
	PROTO_ARP,
	PROTO_MPLS,
	PROTO_IP4,
	PROTO_ICMP4,
	PROTO_IP6,
	PROTO_ICMP6,
	PROTO_UDP,
	PROTO_TCP,
	PROTO_DNS,
	__PROTO_MAX,
};

enum proto_layer {
	PROTO_L0, /* invalid layer */
	PROTO_L2,
	PROTO_L3,
	PROTO_L4,
	PROTO_L7,
};

struct proto_field;
struct proto_hdr;

struct proto_ops {
	enum proto_id id;
	enum proto_layer layer;

	void (*header_init)(struct proto_hdr *hdr);
	void (*header_finish)(struct proto_hdr *hdr);
	void (*push_sub_header)(struct proto_hdr *hdr, struct proto_hdr *sub_hdr);
	void (*field_changed)(struct proto_field *field);
	void (*packet_finish)(struct proto_hdr *hdr);
	void (*packet_update)(struct proto_hdr *hdr);
	void (*set_next_proto)(struct proto_hdr *hdr, enum proto_id pid);
	enum proto_id (*get_next_proto)(struct proto_hdr *hdr);
};

struct proto_hdr {
	const struct proto_ops *ops;
	struct proto_hdr *parent;
	struct proto_hdr **sub_headers;
	uint32_t sub_headers_count;
	uint16_t pkt_offset;
	uint32_t pkt_id;
	uint32_t index;
	struct proto_field *fields;
	size_t fields_count;
	bool is_csum_valid;
	uint32_t id;
	size_t len;
};

enum proto_field_func_t {
	PROTO_FIELD_FUNC_INC = 1 << 0,
	PROTO_FIELD_FUNC_MIN = 1 << 1,
	PROTO_FIELD_FUNC_RND = 1 << 2,
};

struct proto_field_func {
	enum proto_field_func_t type;
	uint32_t min;
	uint32_t max;
	int32_t inc;
	uint16_t offset;
	uint32_t val;
	size_t len;

	void (*update_field)(struct proto_field *field);
};

struct proto_field {
	uint32_t id;
	size_t len;
	uint32_t shift;
	uint32_t mask;
	/* might be negative (e.g. VLAN TPID field) */
	int16_t offset;

	struct proto_field_func func;
	bool is_set;
	uint16_t pkt_offset;
	struct proto_hdr *hdr;
};

extern void protos_init(struct dev_io *dev);
extern void proto_ops_register(const struct proto_ops *ops);

struct proto_hdr *proto_packet_apply(enum proto_id pid, struct packet *pkt);
extern struct proto_hdr *proto_header_push(enum proto_id pid);
extern void proto_header_finish(struct proto_hdr *hdr);
extern void proto_packet_finish(void);
extern void proto_packet_update(uint32_t idx);

extern enum proto_id proto_hdr_get_next_proto(struct proto_hdr *hdr);
extern struct packet *proto_hdr_packet(struct proto_hdr *hdr);
extern struct proto_hdr *proto_hdr_push_sub_header(struct proto_hdr *hdr, int id);
extern void proto_hdr_move_sub_header(struct proto_hdr *hdr, struct proto_hdr *from,
				      struct proto_hdr *to);

extern struct proto_hdr *proto_lower_default_add(struct proto_hdr *hdr,
						 enum proto_id pid);

extern struct proto_hdr *packet_last_header(struct packet *pkt);
extern struct proto_hdr *proto_lower_header(struct proto_hdr *hdr);
extern struct proto_hdr *proto_upper_header(struct proto_hdr *hdr);
extern uint8_t *proto_header_ptr(struct proto_hdr *hdr);

extern void proto_header_fields_add(struct proto_hdr *hdr,
				    const struct proto_field *fields,
				    size_t count);

extern bool proto_hdr_field_is_set(struct proto_hdr *hdr, uint32_t fid);
extern uint8_t *proto_hdr_field_get_bytes(struct proto_hdr *hdr, uint32_t fid);
extern void proto_hdr_field_set_bytes(struct proto_hdr *hdr, uint32_t fid,
				  const uint8_t *bytes, size_t len);
extern void proto_hdr_field_set_u8(struct proto_hdr *hdr, uint32_t fid, uint8_t val);
extern uint8_t proto_hdr_field_get_u8(struct proto_hdr *hdr, uint32_t fid);
extern void proto_hdr_field_set_u16(struct proto_hdr *hdr, uint32_t fid, uint16_t val);
extern uint16_t proto_hdr_field_get_u16(struct proto_hdr *hdr, uint32_t fid);
extern void proto_hdr_field_set_u32(struct proto_hdr *hdr, uint32_t fid, uint32_t val);
extern uint32_t proto_hdr_field_get_u32(struct proto_hdr *hdr, uint32_t fid);
extern uint32_t proto_hdr_field_get_be32(struct proto_hdr *hdr, uint32_t fid);

extern void proto_hdr_field_set_default_bytes(struct proto_hdr *hdr, uint32_t fid,
					  const uint8_t *bytes, size_t len);
extern void proto_hdr_field_set_default_u8(struct proto_hdr *hdr, uint32_t fid,
				       uint8_t val);
extern void proto_hdr_field_set_default_u16(struct proto_hdr *hdr, uint32_t fid,
				        uint16_t val);
extern void proto_hdr_field_set_default_u32(struct proto_hdr *hdr, uint32_t fid,
				        uint32_t val);

extern void proto_hdr_field_set_be16(struct proto_hdr *hdr, uint32_t fid, uint16_t val);
extern void proto_hdr_field_set_be32(struct proto_hdr *hdr, uint32_t fid, uint32_t val);

extern void proto_hdr_field_set_default_be16(struct proto_hdr *hdr, uint32_t fid,
					 uint16_t val);
extern void proto_hdr_field_set_default_be32(struct proto_hdr *hdr, uint32_t fid,
					 uint32_t val);

extern void proto_hdr_field_set_dev_mac(struct proto_hdr *hdr, uint32_t fid);
extern void proto_hdr_field_set_default_dev_mac(struct proto_hdr *hdr, uint32_t fid);

extern void proto_hdr_field_set_dev_ipv4(struct proto_hdr *hdr, uint32_t fid);
extern void proto_hdr_field_set_default_dev_ipv4(struct proto_hdr *hdr, uint32_t fid);

extern void proto_hdr_field_set_dev_ipv6(struct proto_hdr *hdr, uint32_t fid);
extern void proto_hdr_field_set_default_dev_ipv6(struct proto_hdr *hdr, uint32_t fid);

extern void proto_hdr_field_set_string(struct proto_hdr *hdr, uint32_t fid, const char *str);
extern void proto_hdr_field_set_default_string(struct proto_hdr *hdr, uint32_t fid, const char *str);

extern void proto_field_dyn_apply(struct proto_field *field);

extern struct proto_field *proto_hdr_field_by_id(struct proto_hdr *hdr, uint32_t fid);


extern void proto_field_set_u8(struct proto_field *field, uint8_t val);
extern uint8_t proto_field_get_u8(struct proto_field *field);
extern void proto_field_set_u16(struct proto_field *field, uint16_t val);
extern uint16_t proto_field_get_u16(struct proto_field *field);
extern void proto_field_set_u32(struct proto_field *field, uint32_t val);
extern uint32_t proto_field_get_u32(struct proto_field *field);
extern uint32_t proto_field_get_be32(struct proto_field *field);
extern void proto_field_set_be16(struct proto_field *field, uint16_t val);
extern void proto_field_set_be32(struct proto_field *field, uint32_t val);
extern void proto_field_set_bytes(struct proto_field *field, const uint8_t *bytes, size_t len);
extern void proto_field_set_string(struct proto_field *field, const char *str);
extern void proto_field_set_default_string(struct proto_field *field, const char *str);

extern void proto_field_func_add(struct proto_field *field,
				 struct proto_field_func *func);

extern struct dev_io *proto_dev_get(void);

#endif /* TRAFGEN_PROTO_H */

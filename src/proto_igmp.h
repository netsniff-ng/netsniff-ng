/*
 * This file is part of netsniff-ng - the packet sniffing beast.
 * Copyright (C) 2012 Christoph Jaeger <christophjaeger@linux.com>
 * Subject to the GPL, version 2.
 */

#ifndef _PROTO_IGMP_H_
#define _PROTO_IGMP_H_

#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>

#include "dissector_eth.h"
#include "proto_struct.h"

/* IGMPv0 (RFC-988) */
struct igmp_v0_msg {
	uint8_t  type;
	uint8_t  code;
	uint16_t checksum;
	uint32_t identifier;
	uint32_t group_address;
	uint64_t access_key;
} __attribute__((packed));

/* igmp_v0_msg.type */
#define IGMP_V0_CREATE_GROUP_REQUEST  0x01
#define IGMP_V0_CREATE_GROUP_REPLY    0x02
#define IGMP_V0_JOIN_GROUP_REQUEST    0x03
#define IGMP_V0_JOIN_GROUP_REPLY      0x04
#define IGMP_V0_LEAVE_GROUP_REQUEST   0x05
#define IGMP_V0_LEAVE_GROUP_REPLY     0x06
#define IGMP_V0_CONFIRM_GROUP_REQUEST 0x07
#define IGMP_V0_CONFIRM_GROUP_REPLY   0x08

/* IGMPv1 (RFC-1054/RFC-1112, obsoletes RFC-988) */
struct igmp_v1_msg {
	union {
#if defined(__LITTLE_ENDIAN_BITFIELD)
		uint8_t type:4,
			version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
		uint8_t version:4,
			type:4;
#else
# error "Please fix <asm/byteorder.h>"
#endif
		uint8_t version__type;
	};
	uint8_t  unused; /* always zero */
	uint16_t checksum;
	uint32_t group_address;
} __attribute__((packed));

/* igmp_v1_msg.version__type (!) */
/* IGMP_V1_MEMBERSHIP_QUERY 0x11 */
#define IGMP_V1_MEMBERSHIP_REPORT 0x12

/* IGMPv2 (RFC-2236) */
struct igmp_v2_msg {
	uint8_t  type;
	uint8_t  max_resp_time;
	uint16_t checksum;
	uint32_t group_address;
} __attribute__((packed));

/* igmp_v2_msg.type */
/* IGMP_V2_MEMBERSHIP_QUERY 0x11 */
#define IGMP_V2_MEMBERSHIP_REPORT 0x16
#define IGMP_V2_LEAVE_GROUP       0x17

/* IGMPv3 (RFC-3376) */
struct igmp_v3_group_record {
	uint8_t  record_type;
	uint8_t  aux_data_len; /* always zero */
	uint16_t number_of_sources;
	uint32_t multicast_address;
	uint32_t source_addresses[0];
	/* auxiliary data (IGMPv3 does not define any) */
} __attribute__((packed));

/* igmp_v3_group_record.record_type */
#define IGMP_V3_MODE_IS_INCLUDE        1
#define IGMP_V3_MODE_IS_EXCLUDE        2
#define IGMP_V3_CHANGE_TO_INCLUDE_MODE 3
#define IGMP_V3_CHANGE_TO_EXCLUDE_MODE 4
#define IGMP_V3_ALLOW_NEW_SOURCES      5
#define IGMP_V3_BLOCK_OLD_SOURCES      6

struct igmp_v3_membership_report {
	uint8_t  type;
	uint8_t  reserved1;
	uint16_t checksum;
	uint16_t reserved2;
	uint16_t number_of_group_records;
	struct igmp_v3_group_record group_records[0];
} __attribute__((packed));

struct igmp_v3_membership_query {
	uint8_t  type;
	uint8_t  max_resp_code;
	uint16_t checksum;
	uint32_t group_address;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint8_t  qrv:3,
		 s_flag:1,
		 reserved:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	uint8_t  reserved:4,
		 s_flag:1,
		 qrv:3;
#else
# error "Please fix <asm/byteorder.h>"
#endif
	uint8_t  qqic;
	uint16_t number_of_sources;
	uint32_t source_addresses[0];
} __attribute__((packed));

#define IGMP_MEMBERSHIP_QUERY     0x11 /* v1/v2/v3 */
#define IGMP_V3_MEMBERSHIP_REPORT 0x22

#define EXP(x) (((x) & 0x70) >> 4)
#define MANT(x) ((x) & 0x0F)

#define DECODE_MAX_RESP_CODE(x) ((x) < 128 ? (x) : (MANT(x) | 0x10) << (EXP(x) + 3))
#define DECODE_QQIC(x)          ((x) < 128 ? (x) : (MANT(x) | 0x10) << (EXP(x) + 3))

static char *friendly_msg_type_name(uint8_t msg_type)
{
	switch (msg_type) {
	case IGMP_V0_CREATE_GROUP_REQUEST:
		return "Create Group Request";
	case IGMP_V0_CREATE_GROUP_REPLY:
		return "Create Group Reply";
	case IGMP_V0_JOIN_GROUP_REQUEST:
		return "Join Group Request";
	case IGMP_V0_JOIN_GROUP_REPLY:
		return "Join Group Reply";
	case IGMP_V0_LEAVE_GROUP_REQUEST:
		return "Leave Group Request";
	case IGMP_V0_LEAVE_GROUP_REPLY:
		return "Leave Group Reply";
	case IGMP_V0_CONFIRM_GROUP_REQUEST:
		return "Confirm Group Request";
	case IGMP_V0_CONFIRM_GROUP_REPLY:
		return "Confirm Group Reply";
	case IGMP_MEMBERSHIP_QUERY:
		return "Membership Query";
	case IGMP_V1_MEMBERSHIP_REPORT:
	case IGMP_V2_MEMBERSHIP_REPORT:
	case IGMP_V3_MEMBERSHIP_REPORT:
		return "Membership Report";
	case IGMP_V2_LEAVE_GROUP:
		return "Leave Group";
	default:
		return NULL;
	}
}

#define PRINT_FRIENDLY_NAMED_MSG_TYPE(type)			\
	do {							\
		if (friendly_msg_type_name(type))		\
			tprintf("  Type (0x%.2x, %s)", type,	\
				friendly_msg_type_name(type));	\
		else						\
			tprintf("  Type (0x%.2x)", type);	\
	} while (0)

static char *friendly_group_rec_type_name(uint8_t rec_type)
{
	switch (rec_type) {
	case IGMP_V3_MODE_IS_INCLUDE:
		return "Mode Is Include";
	case IGMP_V3_MODE_IS_EXCLUDE:
		return "Mode Is Exclude";
	case IGMP_V3_CHANGE_TO_INCLUDE_MODE:
		return "Change To Include Mode";
	case IGMP_V3_CHANGE_TO_EXCLUDE_MODE:
		return "Change To Exclude Mode";
	case IGMP_V3_ALLOW_NEW_SOURCES:
		return "Allow New Sources";
	case IGMP_V3_BLOCK_OLD_SOURCES:
		return "Block Old Sources";
	default:
		return NULL;
	}
}

static inline void dissect_igmp_v0(struct igmp_v0_msg *msg, size_t len)
{
	char     addr[INET_ADDRSTRLEN];
	uint16_t csum;

	static const char *reply_codes[] = {
		"Request Granted",
		"Request Denied, No Resources",
		"Request Denied, Invalid Code",
		"Request Denied, Invalid Group Address",
		"Request Denied, Invalid Access Key"
	};

	tprintf(" [ IGMPv0");
	PRINT_FRIENDLY_NAMED_MSG_TYPE(msg->type);

	switch (msg->type) {
	case IGMP_V0_CREATE_GROUP_REQUEST:
		switch (msg->code) {
		case 0:
			tprintf(", Code (%u, %s)", msg->code, "Public");
			break;
		case 1:
			tprintf(", Code (%u, %s)", msg->code, "Private");
			break;
		default:
			tprintf(", Code (%u)", msg->code);
		}
		break;
	case IGMP_V0_CREATE_GROUP_REPLY:
	case IGMP_V0_JOIN_GROUP_REPLY:
	case IGMP_V0_LEAVE_GROUP_REPLY:
	case IGMP_V0_CONFIRM_GROUP_REPLY:
		if (msg->code < 5)
			tprintf(", Code (%u, %s)", msg->code, reply_codes[msg->code]);
		else
			tprintf(", Code (%u, Request Pending, Retry In %u Seconds)",
				msg->code, msg->code);
		break;
	default:
		tprintf(", Code (%u)", msg->code);
	}

	/* TODO: use len instead of sizeof */
	csum = calc_csum(msg, sizeof(struct igmp_v0_msg), 0);
	tprintf(", CSum (0x%.4x) is %s", ntohs(msg->checksum), csum ?
		colorize_start_full(black, red) "bogus (!)" colorize_end() : "ok");
	if (csum)
		tprintf(" - %s should be %x%s", colorize_start_full(black, red),
			csum_expected(msg->checksum, csum), colorize_end());
	tprintf(", Id (%u)", ntohs(msg->identifier));
	inet_ntop(AF_INET, &msg->group_address, addr, sizeof(addr));
	tprintf(", Group Addr (%s)", addr);
	tprintf(", Access Key (0x%.16x)", msg->access_key);
	tprintf(" ]\n\n");
}

static inline void dissect_igmp_v1(struct igmp_v1_msg *msg, size_t len)
{
	char     addr[INET_ADDRSTRLEN];
	uint16_t csum;

	tprintf(" [ IGMPv1");
	PRINT_FRIENDLY_NAMED_MSG_TYPE(msg->version__type);
	/* TODO: use len instead of sizeof */
	csum = calc_csum(msg, sizeof(struct igmp_v1_msg), 0);
	tprintf(", CSum (0x%.4x) is %s", ntohs(msg->checksum), csum ?
		colorize_start_full(black, red) "bogus (!)" colorize_end() : "ok");
	if (csum)
		tprintf(" - %s should be %x%s", colorize_start_full(black, red),
			csum_expected(msg->checksum, csum), colorize_end());
	inet_ntop(AF_INET, &msg->group_address, addr, sizeof(addr));
	tprintf(", Group Addr (%s)", addr);
	tprintf(" ]\n\n");
}

static inline void dissect_igmp_v2(struct igmp_v2_msg *msg, size_t len)
{
	char     addr[INET_ADDRSTRLEN];
	uint16_t csum;

	tprintf(" [ IGMPv2");
	PRINT_FRIENDLY_NAMED_MSG_TYPE(msg->type);
	tprintf(", Max Resp Time (%u)", msg->max_resp_time);
	/* TODO: use len instead of sizeof */
	csum = calc_csum(msg, sizeof(struct igmp_v1_msg), 0);
	tprintf(", CSum (0x%.4x) is %s", ntohs(msg->checksum), csum ?
		colorize_start_full(black, red) "bogus (!)" colorize_end() : "ok");
	if (csum)
		tprintf(" - %s should be %x%s", colorize_start_full(black, red),
			csum_expected(msg->checksum, csum), colorize_end());
	inet_ntop(AF_INET, &msg->group_address, addr, sizeof(addr));
	tprintf(", Group Addr (%s)", addr);
	tprintf(" ]\n\n");
}

static inline void dissect_igmp_v3_membership_query(
	struct igmp_v3_membership_query *msg, size_t len)
{
	char   addr[INET_ADDRSTRLEN];
	size_t i, n = ntohs(msg->number_of_sources);

	tprintf(" [ IGMPv3");
	PRINT_FRIENDLY_NAMED_MSG_TYPE(msg->type);
	tprintf(", Max Resp Code (0x%.2x => %u)", msg->max_resp_code,
		DECODE_MAX_RESP_CODE(msg->max_resp_code));
	/* TODO: compute and verify checksum */
	tprintf(", CSum (0x%.4x)", ntohs(msg->checksum));
	inet_ntop(AF_INET, &msg->group_address, addr, sizeof(addr));
	/* S Flag (Suppress Router-Side Processing) */
	tprintf(", Suppress (%u)", msg->s_flag ? 1 : 0);
	/* QRV (Querier's Robustness Variable) */
	tprintf(", QRV (%u)", msg->qrv);
	/* QQIC (Querier's Query Interval Code) */
	tprintf(", QQIC (0x%.2x => %u)", msg->qqic, DECODE_QQIC(msg->qqic));
	tprintf(", Group Addr (%s)", addr);
	tprintf(", Num Src (%u)", n);

	if (n) {
		inet_ntop(AF_INET, &msg->source_addresses[0], addr, sizeof(addr));
		tprintf(", Src Addr (%s", addr);
		for (i = 1; i < n; i++) {
			inet_ntop(AF_INET, &msg->source_addresses[i], addr, sizeof(addr));
			tprintf(", %s", addr);
		}
		tprintf(")");
	}

	tprintf(" ]\n\n");
}

static inline void dissect_igmp_v3_membership_report(
	struct igmp_v3_membership_report *msg, size_t len)
{
	size_t   m      = ntohs(msg->number_of_group_records);
	uint8_t *offset = (uint8_t *) &msg->group_records;

	tprintf(" [ IGMPv3");
	PRINT_FRIENDLY_NAMED_MSG_TYPE(msg->type);
	/* TODO: calculate and verify checksum */
	tprintf(", CSum (0x%.4x)", ntohs(msg->checksum));
	tprintf(", Num Group Rec (%u)", m);
	tprintf(" ]\n");

	while (m--) {
		char addr[INET_ADDRSTRLEN];
		struct igmp_v3_group_record *rec = msg->group_records;
		size_t n = ntohs(rec->number_of_sources);

		tprintf("   [ Group Record");
		if (friendly_group_rec_type_name(rec->record_type))
			tprintf("  Type (%u, %s)", rec->record_type,
				friendly_group_rec_type_name(rec->record_type));
		else
			tprintf("  Type (%u)", rec->record_type);
		tprintf(", Num Src (%u)", n);
		inet_ntop(AF_INET, &rec->multicast_address, addr, sizeof(addr));
		tprintf(", Multicast Addr (%s)", addr);
		offset += sizeof(struct igmp_v3_group_record);

		if (n--) {
			inet_ntop(AF_INET, offset, addr, sizeof(addr));
			tprintf(", Src Addr (%s", addr);
			offset += sizeof(uint32_t);
			while (n--) {
				inet_ntop(AF_INET, offset, addr, sizeof(addr));
				tprintf(", %s", addr);
				offset += sizeof(uint32_t);
			}
			tprintf(")");
		}

		tprintf(" ]\n\n");
	}
}

static inline void igmp_type_unknown(uint8_t *packet, size_t len)
{
	assert(0);
}

static inline void igmp(uint8_t *packet, size_t len)
{
	switch (*packet) {
	case IGMP_V0_CREATE_GROUP_REQUEST:
	case IGMP_V0_CREATE_GROUP_REPLY:
	case IGMP_V0_JOIN_GROUP_REQUEST:
	case IGMP_V0_JOIN_GROUP_REPLY:
	case IGMP_V0_LEAVE_GROUP_REQUEST:
	case IGMP_V0_LEAVE_GROUP_REPLY:
	case IGMP_V0_CONFIRM_GROUP_REQUEST:
	case IGMP_V0_CONFIRM_GROUP_REPLY:
		assert(len == sizeof(struct igmp_v0_msg));
		dissect_igmp_v0((struct igmp_v0_msg *) packet, len);
		break;
	case IGMP_MEMBERSHIP_QUERY: /* v1/v2/v3 */
		if (len >= sizeof(struct igmp_v3_membership_query)) {
			dissect_igmp_v3_membership_query(
				(struct igmp_v3_membership_query *) packet, len);
		} else if (*(packet + 1)) {
			/* v1 and v2 differs in second byte of message */
			assert(len == sizeof(struct igmp_v2_msg));
			dissect_igmp_v2((struct igmp_v2_msg *) packet, len);
		} else {
			assert(len == sizeof(struct igmp_v1_msg));
			dissect_igmp_v1((struct igmp_v1_msg *) packet, len);
		}
		break;
	case IGMP_V1_MEMBERSHIP_REPORT:
		assert(len == sizeof(struct igmp_v1_msg));
		dissect_igmp_v1((struct igmp_v1_msg *) packet, len);
		break;
	case IGMP_V2_MEMBERSHIP_REPORT:
	case IGMP_V2_LEAVE_GROUP:
		assert(len == sizeof(struct igmp_v2_msg));
		dissect_igmp_v2((struct igmp_v2_msg *) packet, len);
		break;
	case IGMP_V3_MEMBERSHIP_REPORT:
		assert(len >= sizeof(struct igmp_v3_membership_report));
		dissect_igmp_v3_membership_report(
			(struct igmp_v3_membership_report *) packet, len);
		break;
	default:
		igmp_type_unknown(packet, len);
		break;
	}
}

static inline void igmp_less(uint8_t *packet, size_t len)
{
	int version = -1;

	switch (*packet) {
	case IGMP_V0_CREATE_GROUP_REQUEST:
	case IGMP_V0_CREATE_GROUP_REPLY:
	case IGMP_V0_JOIN_GROUP_REQUEST:
	case IGMP_V0_JOIN_GROUP_REPLY:
	case IGMP_V0_LEAVE_GROUP_REQUEST:
	case IGMP_V0_LEAVE_GROUP_REPLY:
	case IGMP_V0_CONFIRM_GROUP_REQUEST:
	case IGMP_V0_CONFIRM_GROUP_REPLY:
		assert(len == sizeof(struct igmp_v0_msg));
		version = 0;
		break;
	case IGMP_MEMBERSHIP_QUERY: /* v1/v2/v3 */
		if (len >= sizeof(struct igmp_v3_membership_query)) {
			version = 3;
		} else if (*(packet + 1)) {
			/* v1 and v2 differs in second byte of message */
			assert(len == sizeof(struct igmp_v2_msg));
			version = 2;
		} else {
			assert(len == sizeof(struct igmp_v1_msg));
			version = 1;
		}
		break;
	case IGMP_V1_MEMBERSHIP_REPORT:
		assert(len == sizeof(struct igmp_v1_msg));
		version = 1;
		break;
	case IGMP_V2_MEMBERSHIP_REPORT:
	case IGMP_V2_LEAVE_GROUP:
		assert(len == sizeof(struct igmp_v2_msg));
		version = 2;
		break;
	case IGMP_V3_MEMBERSHIP_REPORT:
		assert(len >= sizeof(struct igmp_v3_membership_report));
		version = 3;
		break;
	default:
		igmp_type_unknown(packet, len);
		break;
	}

	assert(version >= 0);
	tprintf(" IGMPv%u", version);
	PRINT_FRIENDLY_NAMED_MSG_TYPE(*packet);
}

struct protocol igmp_ops = {
	.key = 0x02,
	.offset = 0,
	.print_full = igmp,
	.print_less = igmp_less,
	.print_pay_ascii = empty,
	.print_pay_hex = empty,
	.print_pay_none = igmp,
	.print_all_hex = hex,
	.proto_next = NULL,
};

#endif /* _PROTO_IGMP_H_ */

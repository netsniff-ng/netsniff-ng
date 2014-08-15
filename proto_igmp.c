/*
 * netsniff-ng - the packet sniffing beast
 * Copyright (C) 2012 Christoph Jaeger <christoph@netsniff-ng.org>
 * Subject to the GPL, version 2.
 */

#include <inttypes.h>
#include <arpa/inet.h>
#include <asm/byteorder.h>
#include <netinet/in.h>

#include "proto.h"
#include "protos.h"
#include "csum.h"
#include "built_in.h"
#include "pkt_buff.h"

/* IGMPv0 (RFC-988) */
struct igmp_v0_msg {
	uint8_t  type;
	uint8_t  code;
	uint16_t checksum;
	uint32_t identifier;
	uint32_t group_address;
	uint64_t access_key;
} __packed;

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
		uint8_t version__type;
		struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
			uint8_t type    :4,
				version :4;
#elif defined(__BIG_ENDIAN_BITFIELD)
			uint8_t version :4,
				type    :4;
#else
# error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint8_t  unused; /* always zero */
	uint16_t checksum;
	uint32_t group_address;
} __packed;

/* igmp_v1_msg.version__type (!) */
/* IGMP_V1_MEMBERSHIP_QUERY 0x11 */
#define IGMP_V1_MEMBERSHIP_REPORT 0x12

/* IGMPv2 (RFC-2236) */
struct igmp_v2_msg {
	uint8_t  type;
	uint8_t  max_resp_time;
	uint16_t checksum;
	uint32_t group_address;
} __packed;

/* igmp_v2_msg.type */
/* IGMP_V2_MEMBERSHIP_QUERY 0x11 */
#define IGMP_V2_MEMBERSHIP_REPORT 0x16
#define IGMP_V2_LEAVE_GROUP       0x17

/*
 * RGMP (RFC-3488)
 * The RGMP message format resembles the IGMPv2 message format. All RGMP
 * messages are sent with TTL 1, to destination address 224.0.0.25.
 */
#define RGMP_LEAVE_GROUP 0xFC
#define RGMP_JOIN_GROUP  0xFD
#define RGMP_BYE         0xFE
#define RGMP_HELLO       0xFF

/* IGMPv3 (RFC-3376) */
struct igmp_v3_group_record {
	uint8_t  record_type;
	uint8_t  aux_data_len; /* always zero */
	uint16_t number_of_sources;
	uint32_t multicast_address;
	uint32_t source_addresses[0];
	/* auxiliary data (IGMPv3 does not define any) */
} __packed;

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
} __packed;

struct igmp_v3_membership_query {
	uint8_t  type;
	uint8_t  max_resp_code;
	uint16_t checksum;
	uint32_t group_address;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint8_t qrv    :3,
		s_flag :1,
		       :4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	uint8_t        :4,
		s_flag :1,
		qrv    :3;
#else
# error "Please fix <asm/byteorder.h>"
#endif
	uint8_t  qqic;
	uint16_t number_of_sources;
	uint32_t source_addresses[0];
} __packed;

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
	case RGMP_HELLO:
		return "Hello";
	case RGMP_BYE:
		return "Bye";
	case RGMP_JOIN_GROUP:
		return "Join Group";
	case RGMP_LEAVE_GROUP:
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

static void dissect_igmp_v0(struct pkt_buff *pkt)
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

	struct igmp_v0_msg *msg =
		(struct igmp_v0_msg *) pkt_pull(pkt, sizeof(*msg));

	if (msg == NULL)
		return;

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

	csum = calc_csum(msg, sizeof(*msg) + pkt_len(pkt), 0);
	tprintf(", CSum (0x%.4x) is %s", ntohs(msg->checksum), csum ?
		colorize_start_full(black, red) "bogus (!)" colorize_end() : "ok");
	if (csum)
		tprintf(" - %s should be %x%s", colorize_start_full(black, red),
			csum_expected(msg->checksum, csum), colorize_end());
	tprintf(", Id (%u)", ntohs(msg->identifier));
	inet_ntop(AF_INET, &msg->group_address, addr, sizeof(addr));
	tprintf(", Group Addr (%s)", addr);
	tprintf(", Access Key (0x%.16"PRIx64")", msg->access_key);
	tprintf(" ]\n");
}

static void dissect_igmp_v1(struct pkt_buff *pkt)
{
	char     addr[INET_ADDRSTRLEN];
	uint16_t csum;

	struct igmp_v1_msg *msg =
		(struct igmp_v1_msg *) pkt_pull(pkt, sizeof(*msg));

	if (msg == NULL)
		return;

	tprintf(" [ IGMPv1");
	PRINT_FRIENDLY_NAMED_MSG_TYPE(msg->version__type);
	csum = calc_csum(msg, sizeof(*msg) + pkt_len(pkt), 0);
	tprintf(", CSum (0x%.4x) is %s", ntohs(msg->checksum), csum ?
		colorize_start_full(black, red) "bogus (!)" colorize_end() : "ok");
	if (csum)
		tprintf(" - %s should be %x%s", colorize_start_full(black, red),
			csum_expected(msg->checksum, csum), colorize_end());
	inet_ntop(AF_INET, &msg->group_address, addr, sizeof(addr));
	tprintf(", Group Addr (%s)", addr);
	tprintf(" ]\n");
}

static void dissect_igmp_v2(struct pkt_buff *pkt)
{
	char     addr[INET_ADDRSTRLEN];
	uint16_t csum;

	struct igmp_v2_msg *msg =
		(struct igmp_v2_msg *) pkt_pull(pkt, sizeof(*msg));

	if (msg == NULL)
		return;

	switch (msg->type) {
	case RGMP_HELLO:
	case RGMP_BYE:
	case RGMP_JOIN_GROUP:
	case RGMP_LEAVE_GROUP:
		tprintf(" [ IGMPv2 (RGMP)");
		break;
	default:
		tprintf(" [ IGMPv2");
		break;
	}

	PRINT_FRIENDLY_NAMED_MSG_TYPE(msg->type);
	tprintf(", Max Resp Time (%u)", msg->max_resp_time);
	csum = calc_csum(msg, sizeof(*msg) + pkt_len(pkt), 0);
	tprintf(", CSum (0x%.4x) is %s", ntohs(msg->checksum), csum ?
		colorize_start_full(black, red) "bogus (!)" colorize_end() : "ok");
	if (csum)
		tprintf(" - %s should be %x%s", colorize_start_full(black, red),
			csum_expected(msg->checksum, csum), colorize_end());
	inet_ntop(AF_INET, &msg->group_address, addr, sizeof(addr));
	tprintf(", Group Addr (%s)", addr);
	tprintf(" ]\n");
}

static void dissect_igmp_v3_membership_query(struct pkt_buff *pkt)
{
	char      addr[INET_ADDRSTRLEN];
	size_t    n;
	uint16_t  csum;
	uint32_t *src_addr;

	struct igmp_v3_membership_query *msg =
		(struct igmp_v3_membership_query *) pkt_pull(pkt, sizeof(*msg));

	if (msg == NULL)
		return;

	tprintf(" [ IGMPv3");
	PRINT_FRIENDLY_NAMED_MSG_TYPE(msg->type);
	tprintf(", Max Resp Code (0x%.2x => %u)", msg->max_resp_code,
		DECODE_MAX_RESP_CODE(msg->max_resp_code));
	csum = calc_csum(msg, sizeof(*msg) + pkt_len(pkt), 0);
	tprintf(", CSum (0x%.4x) is %s", ntohs(msg->checksum), csum ?
		colorize_start_full(black, red) "bogus (!)" colorize_end() : "ok");
	if (csum)
		tprintf(" - %s should be %x%s", colorize_start_full(black, red),
			csum_expected(msg->checksum, csum), colorize_end());
	inet_ntop(AF_INET, &msg->group_address, addr, sizeof(addr));
	/* S Flag (Suppress Router-Side Processing) */
	tprintf(", Suppress (%u)", msg->s_flag ? 1 : 0);
	/* QRV (Querier's Robustness Variable) */
	tprintf(", QRV (%u)", msg->qrv);
	/* QQIC (Querier's Query Interval Code) */
	tprintf(", QQIC (0x%.2x => %u)", msg->qqic, DECODE_QQIC(msg->qqic));
	tprintf(", Group Addr (%s)", addr);
	n = ntohs(msg->number_of_sources);
	tprintf(", Num Src (%zu)", n);

	if (n--) {
		src_addr = (uint32_t *) pkt_pull(pkt, sizeof(*src_addr));
		if (src_addr != NULL) {
			inet_ntop(AF_INET, src_addr, addr, sizeof(addr));
			tprintf(", Src Addr (%s", addr);
			while (n--) {
				src_addr = (uint32_t *)
					pkt_pull(pkt, sizeof(*src_addr));
				if (src_addr == NULL)
					break;
				inet_ntop(AF_INET, src_addr, addr, sizeof(addr));
				tprintf(", %s", addr);
			}
			tprintf(")");
		}
	}
	tprintf(" ]\n");
}

static void dissect_igmp_v3_membership_report(struct pkt_buff *pkt)
{
	char      addr[INET_ADDRSTRLEN];
	size_t    m, n;
	uint16_t  csum;
	uint32_t *src_addr;

	struct igmp_v3_group_record      *rec;
	struct igmp_v3_membership_report *msg =
		(struct igmp_v3_membership_report *) pkt_pull(pkt, sizeof(*msg));

	if (msg == NULL)
		return;

	tprintf(" [ IGMPv3");
	PRINT_FRIENDLY_NAMED_MSG_TYPE(msg->type);
	csum = calc_csum(msg, sizeof(*msg) + pkt_len(pkt), 0);
	tprintf(", CSum (0x%.4x) is %s", ntohs(msg->checksum), csum ?
		colorize_start_full(black, red) "bogus (!)" colorize_end() : "ok");
	if (csum)
		tprintf(" - %s should be %x%s", colorize_start_full(black, red),
			csum_expected(msg->checksum, csum), colorize_end());
	m = ntohs(msg->number_of_group_records);
	tprintf(", Num Group Rec (%zu)", m);
	tprintf(" ]\n");

	while (m--) {
		rec = (struct igmp_v3_group_record *) pkt_pull(pkt, sizeof(*rec));

		if (rec == NULL)
			break;

		tprintf("   [ Group Record");
		if (friendly_group_rec_type_name(rec->record_type))
			tprintf("  Type (%u, %s)", rec->record_type,
				friendly_group_rec_type_name(rec->record_type));
		else
			tprintf("  Type (%u)", rec->record_type);
		n = ntohs(rec->number_of_sources);
		tprintf(", Num Src (%zu)", n);
		inet_ntop(AF_INET, &rec->multicast_address, addr, sizeof(addr));
		tprintf(", Multicast Addr (%s)", addr);

		if (n--) {
			src_addr = (uint32_t *) pkt_pull(pkt, sizeof(*src_addr));
			if (src_addr != NULL) {
				inet_ntop(AF_INET, src_addr, addr, sizeof(addr));
				tprintf(", Src Addr (%s", addr);
				while (n--) {
					src_addr = (uint32_t *)
						pkt_pull(pkt, sizeof(*src_addr));
					if (src_addr == NULL)
						break;
					inet_ntop(AF_INET, src_addr, addr, sizeof(addr));
					tprintf(", %s", addr);
				}
				tprintf(")");
			}
		}

		tprintf(" ]\n");
	}
	tprintf("\n");
}

static void igmp(struct pkt_buff *pkt)
{
	switch (*pkt_peek(pkt)) {
	case IGMP_V0_CREATE_GROUP_REQUEST:
	case IGMP_V0_CREATE_GROUP_REPLY:
	case IGMP_V0_JOIN_GROUP_REQUEST:
	case IGMP_V0_JOIN_GROUP_REPLY:
	case IGMP_V0_LEAVE_GROUP_REQUEST:
	case IGMP_V0_LEAVE_GROUP_REPLY:
	case IGMP_V0_CONFIRM_GROUP_REQUEST:
	case IGMP_V0_CONFIRM_GROUP_REPLY:
		if (pkt_len(pkt) == sizeof(struct igmp_v0_msg))
			dissect_igmp_v0(pkt);
		break;
	case IGMP_MEMBERSHIP_QUERY: /* v1/v2/v3 */
		if (pkt_len(pkt) >= sizeof(struct igmp_v3_membership_query))
			dissect_igmp_v3_membership_query(pkt);
		else if (pkt_len(pkt) == sizeof(struct igmp_v2_msg)
			&& *(pkt_peek(pkt) + 1))
			dissect_igmp_v2(pkt);
		else if (pkt_len(pkt) == sizeof(struct igmp_v1_msg))
			dissect_igmp_v1(pkt);
		break;
	case IGMP_V1_MEMBERSHIP_REPORT:
		if (pkt_len(pkt) == sizeof(struct igmp_v1_msg))
			dissect_igmp_v1(pkt);
		break;
	case RGMP_HELLO:
	case RGMP_BYE:
	case RGMP_JOIN_GROUP:
	case RGMP_LEAVE_GROUP:
	case IGMP_V2_MEMBERSHIP_REPORT:
	case IGMP_V2_LEAVE_GROUP:
		if (pkt_len(pkt) == sizeof(struct igmp_v2_msg))
			dissect_igmp_v2(pkt);
		break;
	case IGMP_V3_MEMBERSHIP_REPORT:
		if (pkt_len(pkt) >= sizeof(struct igmp_v3_membership_report))
			dissect_igmp_v3_membership_report(pkt);
		break;
	}
}

static void igmp_less(struct pkt_buff *pkt)
{
	int version = -1;

	switch (*pkt_peek(pkt)) {
	case IGMP_V0_CREATE_GROUP_REQUEST:
	case IGMP_V0_CREATE_GROUP_REPLY:
	case IGMP_V0_JOIN_GROUP_REQUEST:
	case IGMP_V0_JOIN_GROUP_REPLY:
	case IGMP_V0_LEAVE_GROUP_REQUEST:
	case IGMP_V0_LEAVE_GROUP_REPLY:
	case IGMP_V0_CONFIRM_GROUP_REQUEST:
	case IGMP_V0_CONFIRM_GROUP_REPLY:
		if (pkt_len(pkt) == sizeof(struct igmp_v0_msg))
			version = 0;
		break;
	case IGMP_MEMBERSHIP_QUERY: /* v1/v2/v3 */
		if (pkt_len(pkt) >= sizeof(struct igmp_v3_membership_query))
			version = 3;
		else if (pkt_len(pkt) == sizeof(struct igmp_v2_msg)
			&& *(pkt_peek(pkt) + 1))
			version = 2;
		else if (pkt_len(pkt) == sizeof(struct igmp_v1_msg))
			version = 1;
		break;
	case IGMP_V1_MEMBERSHIP_REPORT:
		if (pkt_len(pkt) == sizeof(struct igmp_v1_msg))
			version = 1;
		break;
	case RGMP_HELLO:
	case RGMP_BYE:
	case RGMP_JOIN_GROUP:
	case RGMP_LEAVE_GROUP:
	case IGMP_V2_MEMBERSHIP_REPORT:
	case IGMP_V2_LEAVE_GROUP:
		if (pkt_len(pkt) == sizeof(struct igmp_v2_msg))
			version = 2;
		break;
	case IGMP_V3_MEMBERSHIP_REPORT:
		if (pkt_len(pkt) >= sizeof(struct igmp_v3_membership_report))
			version = 3;
		break;
	}

	if (version < 0 || version > 3)
		return;

	switch (*pkt_peek(pkt)) {
	case RGMP_HELLO:
	case RGMP_BYE:
	case RGMP_JOIN_GROUP:
	case RGMP_LEAVE_GROUP:
		tprintf(" IGMPv2 (RGMP)");
		break;
	default:
		tprintf(" IGMPv%u", version);
		break;
	}
	PRINT_FRIENDLY_NAMED_MSG_TYPE(*pkt_peek(pkt));
}

struct protocol igmp_ops = {
	.key = 0x02,
	.print_full = igmp,
	.print_less = igmp_less,
};

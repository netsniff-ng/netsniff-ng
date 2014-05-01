/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend <markus@netsniff-ng.org>, Deutsche Flugsicherung GmbH
 * Subject to the GPL, version 2.
 *
 * IPv6 Mobility Header described in RFC6275
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */
#include <arpa/inet.h>

#include "proto.h"
#include "dissector_eth.h"
#include "built_in.h"
#include "pkt_buff.h"

#define BINDING_REFRESH_REQUEST_MESSAGE	0x00
#define HOME_TEST_INIT_MESSAGE		0x01
#define CARE_OF_TEST_INIT_MESSAGE	0x02
#define HOME_TEST_MESSAGE		0x03
#define CARE_OF_TEST_MESSAGE		0x04
#define BINDING_UPDATE_MESSAGE		0x05
#define BINDING_ACKNOWLEDGEMENT_MESSAGE	0x06
#define BINDING_ERROR_MESSAGE		0x07

struct mobilityhdr {
	uint8_t		payload_proto;
	uint8_t		hdr_len;
	uint8_t		MH_type;
	uint8_t		reserved;
	uint16_t	chksum;
	uint8_t		msgdata[0];
} __packed;

struct bin_refr_req_msg {
	uint16_t	reserved;
	uint8_t		mobility_opt[0];
} __packed;

/* for 0x01 and 0x02 */
struct tst_init_msg {
	uint16_t	reserved;
	uint64_t	init_cookie;
	uint8_t		mobility_opt[0];
} __packed;

/* for 0x03 and 0x04 */
struct tst_msg {
	uint16_t	nonce_index;
	uint64_t	init_cookie;
	uint64_t	keygen_token;
	uint8_t		mobility_opt[0];
} __packed;

struct bind_upd_msg {
	uint16_t	sequence;
	uint16_t	ahlk_res;
	uint16_t	lifetime;
	uint8_t		mobility_opt[0];
} __packed;

struct bind_ack_msg {
	uint8_t		status;
	uint8_t		k_res;
	uint16_t	sequence;
	uint16_t	lifetime;
	uint8_t		mobility_opt[0];
} __packed;

struct bind_err_msg {
	uint8_t		status;
	uint8_t		res;
	uint64_t	home_addr;
	uint8_t		mobility_opt[0];
} __packed;


static void dissect_mobility_options(struct pkt_buff *pkt __maybe_unused,
				     ssize_t *message_data_len)
{
	/* Have to been upgraded.
	 * http://tools.ietf.org/html/rfc6275#section-6.2.1
	 */
	if (*message_data_len)
		tprintf("MH Option(s) recognized ");

	/* If adding dissector reduce message_data_len for each using of
	 * pkt_pull to the same size.
	 */
}

static void dissect_mobilityhdr_type_0(struct pkt_buff *pkt,
				       ssize_t *message_data_len)
{
	struct bin_refr_req_msg *type_0;
	
	type_0 = (struct bin_refr_req_msg *) pkt_pull(pkt, sizeof(*type_0));
	*message_data_len -= sizeof(*type_0);
	if (type_0 == NULL || *message_data_len > pkt_len(pkt) ||
	    *message_data_len < 0)
		return;

	dissect_mobility_options(pkt, message_data_len);
}

static void dissect_mobilityhdr_type_1_2(struct pkt_buff *pkt,
					 ssize_t *message_data_len)
{
	struct tst_init_msg *type_1_2;

	type_1_2 = (struct tst_init_msg *) pkt_pull(pkt, sizeof(*type_1_2));
	*message_data_len -= sizeof(*type_1_2);
	if (type_1_2 == NULL || *message_data_len > pkt_len(pkt) ||
	    *message_data_len < 0)
		return;

	tprintf("Init Cookie (0x%"PRIx64")", ntohll(type_1_2->init_cookie));

	dissect_mobility_options(pkt, message_data_len);
}

static void dissect_mobilityhdr_type_3_4(struct pkt_buff *pkt,
					 ssize_t *message_data_len)
{
	struct tst_msg *type_3_4;

	type_3_4 = (struct tst_msg *) pkt_pull(pkt, sizeof(*type_3_4));
	*message_data_len -= sizeof(*type_3_4);
	if (type_3_4 == NULL || *message_data_len > pkt_len(pkt) ||
	    *message_data_len < 0)
		return;

	tprintf("HN Index (%u) ", ntohs(type_3_4->nonce_index));
	tprintf("Init Cookie (0x%"PRIx64") ", ntohll(type_3_4->init_cookie));
	tprintf("Keygen Token (0x%"PRIx64")", ntohll(type_3_4->keygen_token));

	dissect_mobility_options(pkt, message_data_len);
}

static void dissect_mobilityhdr_type_5(struct pkt_buff *pkt,
				       ssize_t *message_data_len)
{
	struct bind_upd_msg *type_5;

	type_5 = (struct bind_upd_msg *) pkt_pull(pkt, sizeof(*type_5));
	*message_data_len -= sizeof(*type_5);
	if (type_5 == NULL || *message_data_len > pkt_len(pkt) ||
	    *message_data_len < 0)
		return;

	tprintf("Sequence (0x%x) ", ntohs(type_5->sequence));
	tprintf("A|H|L|K (0x%x) ", ntohs(type_5->ahlk_res) >> 12);
	tprintf("Lifetime (%us)", ntohs(type_5->lifetime) * 4);

	dissect_mobility_options(pkt, message_data_len);
}

static void dissect_mobilityhdr_type_6(struct pkt_buff *pkt,
				       ssize_t *message_data_len)
{
	struct bind_ack_msg *type_6;

	type_6 = (struct bind_ack_msg *) pkt_pull(pkt, sizeof(*type_6));
	if (type_6 == NULL)
		return;

	*message_data_len -= sizeof(*type_6);
	if (*message_data_len > pkt_len(pkt) || *message_data_len < 0)
		return;

	tprintf("Status (0x%x) ", type_6->status);
	tprintf("K (%u) ", type_6->k_res >> 7);
	tprintf("Sequence (0x%x)", ntohs(type_6->sequence));
	tprintf("Lifetime (%us)", ntohs(type_6->lifetime) * 4);

	dissect_mobility_options(pkt, message_data_len);
}

static void dissect_mobilityhdr_type_7(struct pkt_buff *pkt,
				       ssize_t *message_data_len)
{
	char address[INET6_ADDRSTRLEN];
	uint64_t addr;
	struct bind_err_msg *type_7;

	type_7 = (struct bind_err_msg *) pkt_pull(pkt, sizeof(*type_7));
	if (type_7 == NULL)
		return;

	*message_data_len -= sizeof(*type_7);
	addr = ntohll(type_7->home_addr);
	if (*message_data_len > pkt_len(pkt) || *message_data_len < 0)
		return;

	tprintf("Status (0x%x) ", type_7->status);
	tprintf("Home Addr (%s)",
		inet_ntop(AF_INET6, &addr, address,
		sizeof(address)));

	dissect_mobility_options(pkt, message_data_len);
}

static void get_mh_type(struct pkt_buff *pkt, ssize_t *message_data_len,
			uint8_t *mh_type)
{
	switch (*mh_type) {
	case BINDING_REFRESH_REQUEST_MESSAGE:
		tprintf("Binding Refresh Request Message ");
		dissect_mobilityhdr_type_0(pkt, message_data_len);
		break;
	case HOME_TEST_INIT_MESSAGE:
		tprintf("Home Test Init Message ");
		dissect_mobilityhdr_type_1_2(pkt, message_data_len);
		break;
	case CARE_OF_TEST_INIT_MESSAGE:
		tprintf("Care-of Test Init Message ");
		dissect_mobilityhdr_type_1_2(pkt, message_data_len);
		break;
	case HOME_TEST_MESSAGE:
		tprintf("Binding Refresh Request Message ");
		dissect_mobilityhdr_type_3_4(pkt, message_data_len);
		break;
	case CARE_OF_TEST_MESSAGE:
		tprintf("Binding Refresh Request Message ");
		dissect_mobilityhdr_type_3_4(pkt, message_data_len);
		break;
	case BINDING_UPDATE_MESSAGE:
		tprintf("Binding Refresh Request Message ");
		dissect_mobilityhdr_type_5(pkt, message_data_len);
		break;
	case BINDING_ACKNOWLEDGEMENT_MESSAGE:
		tprintf("Binding Refresh Request Message ");
		dissect_mobilityhdr_type_6(pkt, message_data_len);
		break;
	case BINDING_ERROR_MESSAGE:
		tprintf("Binding Refresh Request Message ");
		dissect_mobilityhdr_type_7(pkt, message_data_len);
		break;
	default:
		tprintf("Type %u is unknown. Error", *mh_type);
	}
}

static void mobility(struct pkt_buff *pkt)
{
	uint16_t hdr_ext_len;
	ssize_t message_data_len;
	struct mobilityhdr *mobility;

	mobility = (struct mobilityhdr *) pkt_pull(pkt, sizeof(*mobility));
	if (mobility == NULL)
		return;

	/* Total Header Length in Bytes */
	hdr_ext_len = (mobility->hdr_len + 1) * 8;
	/* Total Message Data length in Bytes*/
	message_data_len = (hdr_ext_len - sizeof(*mobility));

	tprintf("\t [ Mobility ");
	tprintf("NextHdr (%u), ", mobility->payload_proto);
	if (message_data_len > pkt_len(pkt) || message_data_len < 0){
		tprintf("HdrExtLen (%u, %u Bytes %s), ", mobility->hdr_len,
				hdr_ext_len, colorize_start_full(black, red)
				"invalid" colorize_end());
		return;
	}
	tprintf("HdrExtLen (%u, %u Bytes), ", mobility->hdr_len,
		hdr_ext_len);
	tprintf("MH Type (%u), ", mobility->MH_type);
	tprintf("Res (0x%x), ", mobility->reserved);
	tprintf("Chks (0x%x), ", ntohs(mobility->chksum));
	tprintf("MH Data ");

	get_mh_type(pkt, &message_data_len, &mobility->MH_type);

	tprintf(" ]\n");

	if (message_data_len > pkt_len(pkt) || message_data_len < 0)
		return;

	pkt_pull(pkt, message_data_len);
	pkt_set_proto(pkt, &eth_lay3, mobility->payload_proto);
}

static void mobility_less(struct pkt_buff *pkt)
{
	uint16_t hdr_ext_len;
	ssize_t message_data_len;
	struct mobilityhdr *mobility;

	mobility = (struct mobilityhdr *) pkt_pull(pkt, sizeof(*mobility));
	if (mobility == NULL)
		return;

	/* Total Header Length in Bytes */
	hdr_ext_len = (mobility->hdr_len + 1) * 8;
	/* Total Message Data length in Bytes*/
	message_data_len = (hdr_ext_len - sizeof(*mobility));
	if (message_data_len > pkt_len(pkt) || message_data_len < 0)
		return;

	tprintf(" Mobility Type (%u), ", mobility->MH_type);

	pkt_pull(pkt, message_data_len);
	pkt_set_proto(pkt, &eth_lay3, mobility->payload_proto);
}

struct protocol ipv6_mobility_ops = {
	.key = 0x87,
	.print_full = mobility,
	.print_less = mobility_less,
};

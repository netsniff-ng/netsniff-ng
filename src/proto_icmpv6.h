/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend <markus@netsniff-ng.org>
 * Subject to the GPL, version 2.
 *
 * ICMPv6 described in RFC4443, RFC2710, RFC4861, RFC2894,
 * RFC4620, RFC3122, RFC3810, RFC3775, RFC3971, RFC4065
 * RFC4286
 */

#ifndef PROTO_ICMPV6_H
#define PROTO_ICMPV6_H

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "built_in.h"
#include "proto_struct.h"
#include "dissector_eth.h"
#include "pkt_buff.h"
#include "built_in.h"

struct icmpv6_general_hdr {
	uint8_t h_type;
	uint8_t h_code;
	uint16_t h_chksum;
} __packed;

/* for type 0x01 and 0x03 */
struct icmpv6_type_1_3 {
	uint32_t unused;
	uint8_t invoking_pkt[0];
} __packed;

struct icmpv6_type_2 {
	uint32_t MTU;
	uint8_t invoking_pkt[0];
} __packed;

struct icmpv6_type_4 {
	uint32_t pointer;
	uint8_t invoking_pkt[0];
} __packed;

struct icmpv6_type_128_129 {
	uint16_t id;
	uint16_t sn;
	uint8_t data[0];
} __packed;

/* MLD format */
struct icmpv6_type_130_131_132 {
	uint16_t maxrespdel;
	uint16_t res;
	struct in6_addr ipv6_addr;
} __packed;

static char *icmpv6_type_1_codes[] = {
	"No route to destination",
	"Communication with destination administratively prohibited",
	"Beyond scope of source address",
	"Address unreachable",
	"Port unreachable",
	"Source address failed ingress/egress policy",
	"Reject route to destination",
	"Error in Source Routing Header",
};

static inline void dissect_icmpv6_type1(struct pkt_buff *pkt)
{
	struct icmpv6_type_1_3 *icmp_1;
	
	icmp_1 = (struct icmpv6_type_1_3 *) pkt_pull(pkt,sizeof(*icmp_1));
	if (icmp_1 == NULL)
		return;

	tprintf(", Unused (0x%x)",ntohl(icmp_1->unused));
	tprintf(" Payload include as much of invoking packet");
}

static inline void dissect_icmpv6_type2(struct pkt_buff *pkt)
{
	struct icmpv6_type_2 *icmp_2;

	icmp_2 = (struct icmpv6_type_2 *) pkt_pull(pkt,sizeof(*icmp_2));
	if (icmp_2 == NULL)
		return;

	tprintf(", MTU (0x%x)",ntohl(icmp_2->MTU));
	tprintf(" Payload include as much of invoking packet");
}

static char *icmpv6_type_3_codes[] = {
	"Hop limit exceeded in transit",
	"Fragment reassembly time exceeded",
};

static inline void dissect_icmpv6_type3(struct pkt_buff *pkt)
{
	struct icmpv6_type_1_3 *icmp_3;

	icmp_3 = (struct icmpv6_type_1_3 *) pkt_pull(pkt,sizeof(*icmp_3));
	if (icmp_3 == NULL)
		return;

	tprintf(", Unused (0x%x)",ntohl(icmp_3->unused));
	tprintf(" Payload include as much of invoking packet");
}

static char *icmpv6_type_4_codes[] = {
	"Erroneous header field encountered",
	"Unrecognized Next Header type encountered",
	"Unrecognized IPv6 option encountered",
};

static inline void dissect_icmpv6_type4(struct pkt_buff *pkt)
{
	struct icmpv6_type_4 *icmp_4;

	icmp_4 = (struct icmpv6_type_4 *) pkt_pull(pkt,sizeof(*icmp_4));
	if (icmp_4 == NULL)
		return;

	tprintf(", Pointer (0x%x)",ntohl(icmp_4->pointer));
	tprintf(" Payload include as much of invoking packet");
}

static inline void dissect_icmpv6_type128(struct pkt_buff *pkt)
{
	struct icmpv6_type_128_129 *icmp_128;

	icmp_128 = (struct icmpv6_type_128_129 *)
		      pkt_pull(pkt,sizeof(*icmp_128));
	if (icmp_128 == NULL)
		return;

	tprintf(", ID (0x%x)",ntohs(icmp_128->id));
	tprintf(", Seq. Nr. (%u)",ntohs(icmp_128->sn));
	tprintf(" Payload include Data");
}

static inline void dissect_icmpv6_type129(struct pkt_buff *pkt)
{
	struct icmpv6_type_128_129 *icmp_129;

	icmp_129 = (struct icmpv6_type_128_129 *)
		      pkt_pull(pkt,sizeof(*icmp_129));
	if (icmp_129 == NULL)
		return;

	tprintf(", ID (0x%x)",ntohs(icmp_129->id));
	tprintf(", Seq. Nr. (%u)",ntohs(icmp_129->sn));
	tprintf(" Payload include Data");
}

static inline void dissect_icmpv6_type130(struct pkt_buff *pkt)
{
	char address[INET6_ADDRSTRLEN];
	struct icmpv6_type_130_131_132 *icmp_130;

	icmp_130 = (struct icmpv6_type_130_131_132 *)
		      pkt_pull(pkt,sizeof(*icmp_130));
	if (icmp_130 == NULL)
		return;

	tprintf(", Max Resp Delay (%ums)",ntohs(icmp_130->maxrespdel));
	tprintf(", Res (0x%x)",ntohs(icmp_130->res));
	tprintf(", Address: %s",
			inet_ntop(AF_INET6, &icmp_130->ipv6_addr,
				  address, sizeof(address)));
}

#define icmpv6_code_range_valid(code, sarr)	((code) < array_size((sarr)))

static inline void icmpv6_process(struct icmpv6_general_hdr *icmp, char **type,
				  char **code,
				  void (**optional)(struct pkt_buff *pkt))
{
	*type = "Unknown Type";
	*code = "Unknown Code";

	switch (icmp->h_type) {
	case 1:
		*type = "Destination Unreachable";
		if (icmpv6_code_range_valid(icmp->h_code, icmpv6_type_1_codes))
			*code = icmpv6_type_1_codes[icmp->h_code];
		*optional = dissect_icmpv6_type1;
		return;
	case 2:
		*type = "Packet Too Big";
		*optional = dissect_icmpv6_type2;
		return;
	case 3:
		*type = "Time Exceeded";
		if (icmpv6_code_range_valid(icmp->h_code, icmpv6_type_3_codes))
			*code = icmpv6_type_3_codes[icmp->h_code];
		*optional = dissect_icmpv6_type3;
		return;
	case 4:
		*type = "Parameter Problem";
		if (icmpv6_code_range_valid(icmp->h_code, icmpv6_type_4_codes))
			*code = icmpv6_type_4_codes[icmp->h_code];
		*optional = dissect_icmpv6_type4;
		return;
	case 100:
		*type = "Private experimation";
		return;
	case 101:
		*type = "Private experimation";
		return;
	case 127:
		*type = "Reserved for expansion of ICMPv6 error messages";
		return;
	case 128:
		*type = "Echo Request";
		*optional = dissect_icmpv6_type128;
		return;
	case 129:
		*type = "Echo Reply";
		*optional = dissect_icmpv6_type129;
		return;
	case 130:
		*type = "Multicast Listener Query";
		*optional = dissect_icmpv6_type130;
		return;
	case 131:
		*type = "Multicast Listener Report";
		return;
	case 132:
		*type = "Multicast Listener Done";
		return;
	case 133:
		*type = "Router Solicitation";
		return;
	case 134:
		*type = "Router Advertisement";
		return;
	case 135:
		*type = "Neighbor Solicitation";
		return;
	case 136:
		*type = "Neighbor Advertisement";
		return;
	case 137:
		*type = "Redirect Message";
		return;
	case 138:
		*type = "Router Renumbering";
		return;
	case 139:
		*type = "ICMP Node Information Query";
		return;
	case 140:
		*type = "ICMP Node Information Response";
		return;
	case 141:
		*type = "Inverse Neighbor Discovery Solicitation Message";
		return;
	case 142:
		*type = "Inverse Neighbor Discovery Advertisement Message";
		return;
	case 143:
		*type = "Multicast Listener Report v2";
		return;
	case 144:
		*type = "Home Agent Address Discovery Request Message";
		return;
	case 145:
		*type = "Home Agent Address Discovery Reply Message";
		return;
	case 146:
		*type = "Mobile Prefix Solicitation";
		return;
	case 147:
		*type = "Mobile Prefix Advertisement";
		return;
	case 148:
		*type = "Certification Path Solicitation";
		return;
	case 149:
		*type = "Certification Path Advertisement";
		return;
	case 150:
		*type = "ICMP messages utilized by experimental mobility "
			"protocols such as Seamoby";
		return;
	case 151:
		*type = "Multicast Router Advertisement";
		return;
	case 152:
		*type = "Multicast Router Solicitation";
		return;
	case 153:
		*type = "Multicast Router Termination";
		return;
	case 155:
		*type = "RPL Control Message";
		return;
	case 200:
		*type = "Private experimation";
		return;
	case 201:
		*type = "Private experimation";
		return;
	case 255:
		*type = "Reserved for expansion of ICMPv6 error messages";
		return;
	}
}

static inline void icmpv6(struct pkt_buff *pkt)
{
	char *type = NULL, *code = NULL;
	void (*optional)(struct pkt_buff *pkt) = NULL;
	struct icmpv6_general_hdr *icmp =
		(struct icmpv6_general_hdr *) pkt_pull(pkt, sizeof(*icmp));

	if (icmp == NULL)
		return;

	icmpv6_process(icmp, &type, &code, &optional);

	tprintf(" [ ICMPv6 ");
	tprintf("%s (%u), ", type, icmp->h_type);
	tprintf("%s (%u), ", code, icmp->h_code);
	tprintf("Chks (0x%x)", ntohs(icmp->h_chksum));
	if (optional)
		(*optional) (pkt);
	tprintf(" ]\n\n");
}

static inline void icmpv6_less(struct pkt_buff *pkt)
{
	struct icmpv6_general_hdr *icmp =
		(struct icmpv6_general_hdr *) pkt_pull(pkt, sizeof(*icmp));

	if (icmp == NULL)
		return;

	tprintf(" ICMPv6 Type (%u) Code (%u)", icmp->h_type, icmp->h_code);
}

struct protocol icmpv6_ops = {
	.key = 0x3A,
	.print_full = icmpv6,
	.print_less = icmpv6_less,
};

#endif /* PROTO_ICMPV6_H */

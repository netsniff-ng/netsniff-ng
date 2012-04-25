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

#define icmpv6_code_range_valid(code, sarr)	((code) < array_size((sarr)))

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

/* MLDv1 msg */
struct icmpv6_type_130_131_132 {
	uint16_t maxrespdel;
	uint16_t res;
	struct in6_addr ipv6_addr;
} __packed;
/* end MLDv1 msg */

struct icmpv6_type_130_mldv2 {
	uint8_t resv_S_QRV;
	uint8_t QQIC;
	uint16_t nr_src;
	struct in6_addr ipv6_addr[0];
} __packed;

/* Neighbor Discovery msg */
struct icmpv6_type_133 {
	uint32_t res;
	uint8_t ops[0];
} __packed;

struct icmpv6_type_134 {
	uint8_t cur_hop_limit;
	uint8_t m_o_res;
	uint16_t router_lifetime;
	uint32_t reachable_time;
	uint32_t retrans_timer;
	uint8_t ops[0];
} __packed;

struct icmpv6_type_135 {
	uint32_t res;
	struct in6_addr ipv6_addr;
	uint8_t ops[0];
} __packed;

struct icmpv6_type_136 {
	uint32_t r_s_o_res;
	struct in6_addr ipv6_addr;
	uint8_t ops[0];
} __packed;

struct icmpv6_type_137 {
	uint32_t res;
	struct in6_addr ipv6_targ_addr;
	struct in6_addr ipv6_dest_addr;
	uint8_t ops[0];
} __packed;

struct icmpv6_neighb_disc_ops_general {
	uint8_t type;
	uint8_t len;
	uint8_t ops[0];
} __packed;

struct icmpv6_neighb_disc_ops_type_1_2 {
	uint8_t link_lay_addr[0];
} __packed;

struct icmpv6_neighb_disc_ops_type_3 {
	uint8_t prefix_len;
	uint8_t l_a_res1;
	uint32_t valid_lifetime;
	uint32_t preferred_lifetime;
	uint32_t res2;
	struct in6_addr prefix;
} __packed;

struct icmpv6_neighb_disc_ops_type_4 {
	uint16_t res1;
	uint32_t res2;
	uint8_t ip_hdr_data[0];
} __packed;

struct icmpv6_neighb_disc_ops_type_5 {
	uint16_t res1;
	uint32_t MTU;
} __packed;
/* end Neighbor Discovery msg */

struct icmpv6_type_138 {
	uint32_t seq_nr;
	uint8_t seg_nr;
	uint8_t flags;
	uint16_t maxdelay;
	uint32_t res;
} __packed;

/* Node Information Queries */
struct icmpv6_type_139_140 {
	uint16_t qtype;
	uint16_t flags;
	uint64_t nonce;
	uint8_t data[0];
} __packed;
/* end Node Information Queries */

static inline void print_ipv6_addr_list(struct pkt_buff *pkt, uint8_t nr_addr)
{
	char address[INET6_ADDRSTRLEN];
	struct in6_addr *addr;
	
	while (nr_addr--) {
	    addr = (struct in6_addr *) pkt_pull(pkt, sizeof(*addr));
	    if (addr == NULL)
		    return;

	    tprintf("\n\t   Address: %s",
		    inet_ntop(AF_INET6, addr, address,
			      sizeof(address)));
	}
}

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
	uint16_t nr_src, maxrespdel;
	uint8_t switch_mldv2 = 0;
	struct icmpv6_type_130_131_132 *icmp_130;

	icmp_130 = (struct icmpv6_type_130_131_132 *)
		      pkt_pull(pkt,sizeof(*icmp_130));
	if (icmp_130 == NULL)
		return;
	maxrespdel = ntohs(icmp_130->maxrespdel);

	if(pkt_len(pkt) >= sizeof(struct icmpv6_type_130_mldv2))
		  switch_mldv2 = 1;

	if(switch_mldv2)
		tprintf(", Max Resp Delay (%ums)", maxrespdel >> 15 ?
			(((maxrespdel & 0xFFF) | 0x1000) <<
			(((maxrespdel >> 12) & 0x3) + 3)) : maxrespdel);
	else
		tprintf(", Max Resp Delay (%ums)",maxrespdel);
	tprintf(", Res (0x%x)",ntohs(icmp_130->res));
	tprintf(", Address: %s",
			inet_ntop(AF_INET6, &icmp_130->ipv6_addr,
				  address, sizeof(address)));

	if(switch_mldv2) {
		struct icmpv6_type_130_mldv2 *icmp_130_mldv2;
		
		icmp_130_mldv2 = (struct icmpv6_type_130_mldv2 *)
			      pkt_pull(pkt,sizeof(*icmp_130_mldv2));
		if (icmp_130_mldv2 == NULL)
			return;
		
		nr_src = ntohs(icmp_130_mldv2->nr_src);

		tprintf(", Resv (0x%x)",icmp_130_mldv2->resv_S_QRV >> 4);
		tprintf(", S (%u)",(icmp_130_mldv2->resv_S_QRV >> 3) & 0x1);
		tprintf(", QRV (0x%x)",icmp_130_mldv2->resv_S_QRV & 0x3);
		tprintf(", QQIC (%u)",icmp_130_mldv2->QQIC);
		tprintf(", Nr Src (0x%x)",nr_src);

		print_ipv6_addr_list(pkt, nr_src);
	}
}

static inline void dissect_icmpv6_type131(struct pkt_buff *pkt)
{
	char address[INET6_ADDRSTRLEN];
	struct icmpv6_type_130_131_132 *icmp_131;

	icmp_131 = (struct icmpv6_type_130_131_132 *)
		      pkt_pull(pkt,sizeof(*icmp_131));
	if (icmp_131 == NULL)
		return;

	tprintf(", Max Resp Delay (%ums)",ntohs(icmp_131->maxrespdel));
	tprintf(", Res (0x%x)",ntohs(icmp_131->res));
	tprintf(", Address: %s",
			inet_ntop(AF_INET6, &icmp_131->ipv6_addr,
				  address, sizeof(address)));
}

static inline void dissect_icmpv6_type132(struct pkt_buff *pkt)
{
	dissect_icmpv6_type131(pkt);
}

static inline void dissect_neighb_disc_ops_1(struct pkt_buff *pkt, size_t len)
{
	struct icmpv6_neighb_disc_ops_type_1_2 *icmp_neighb_disc_1;
	
	icmp_neighb_disc_1 = (struct icmpv6_neighb_disc_ops_type_1_2 *)
				pkt_pull(pkt,sizeof(*icmp_neighb_disc_1));
	if (icmp_neighb_disc_1 == NULL)
			return;

	tprintf("Address 0x");

	while(len--){
		    tprintf("%x", *pkt_pull(pkt,1));
	}
}

static inline void dissect_neighb_disc_ops_2(struct pkt_buff *pkt, size_t len)
{
	dissect_neighb_disc_ops_1(pkt, len);
}

static inline void dissect_neighb_disc_ops_3(struct pkt_buff *pkt, size_t len)
{
	char address[INET6_ADDRSTRLEN];
	struct icmpv6_neighb_disc_ops_type_3 *icmp_neighb_disc_3;

	icmp_neighb_disc_3 = (struct icmpv6_neighb_disc_ops_type_3 *)
				pkt_pull(pkt,sizeof(*icmp_neighb_disc_3));
	if (icmp_neighb_disc_3 == NULL)
			return;

	tprintf("Prefix Len (%u) ",icmp_neighb_disc_3->prefix_len);
	tprintf("L (%u) A (%u) Res1 (0x%x) ",icmp_neighb_disc_3->l_a_res1 >> 7,
				(icmp_neighb_disc_3->l_a_res1 >> 7) & 0x1,
				icmp_neighb_disc_3->l_a_res1 & 0x3F);
	tprintf("Valid Lifetime (%us) ",
				ntohl(icmp_neighb_disc_3->valid_lifetime));
	tprintf("Preferred Lifetime (%us) ",
				ntohl(icmp_neighb_disc_3->preferred_lifetime));
	tprintf("Reserved2 (0x%x) ",
				ntohl(icmp_neighb_disc_3->res2));
	tprintf(", Prefix: %s ",
				inet_ntop(AF_INET6,&icmp_neighb_disc_3->prefix,
				address, sizeof(address)));
}

static inline void dissect_neighb_disc_ops_4(struct pkt_buff *pkt, size_t len)
{
	struct icmpv6_neighb_disc_ops_type_4 *icmp_neighb_disc_4;

	icmp_neighb_disc_4 = (struct icmpv6_neighb_disc_ops_type_4 *)
				pkt_pull(pkt,sizeof(*icmp_neighb_disc_4));
	if (icmp_neighb_disc_4 == NULL)
			return;

	tprintf("Reserved 1 (0x%x) ", ntohs(icmp_neighb_disc_4->res1));
	tprintf("Reserved 2 (0x%x) ", ntohl(icmp_neighb_disc_4->res2));
	tprintf("IP header + data ");

	while(len--){
		    tprintf("%x", *pkt_pull(pkt,1));
	}
}

static inline void dissect_neighb_disc_ops_5(struct pkt_buff *pkt, size_t len)
{
	struct icmpv6_neighb_disc_ops_type_5 *icmp_neighb_disc_5;

	icmp_neighb_disc_5 = (struct icmpv6_neighb_disc_ops_type_5 *)
				pkt_pull(pkt,sizeof(*icmp_neighb_disc_5));
	if (icmp_neighb_disc_5 == NULL)
			return;

	tprintf("Reserved (0x%x) ", ntohs(icmp_neighb_disc_5->res1));
	tprintf("MTU (%u)", ntohl(icmp_neighb_disc_5->MTU));
}

static inline void dissect_neighb_disc_ops_9(struct pkt_buff *pkt, size_t len)
{
// 	struct icmpv6_neighb_disc_ops_type_5 *icmp_neighb_disc_5;
// 
// 	icmp_neighb_disc_5 = (struct icmpv6_neighb_disc_ops_type_5 *)
// 				pkt_pull(pkt,sizeof(*icmp_neighb_disc_5));
// 	if (icmp_neighb_disc_5 == NULL)
// 			return;
// 
// 	tprintf("Reserved (0x%x) ", ntohs(icmp_neighb_disc_5->res1));
// 	tprintf("MTU (%u)", ntohl(icmp_neighb_disc_5->MTU));
}

static inline void dissect_neighb_disc_ops_10(struct pkt_buff *pkt, size_t len)
{
// 	struct icmpv6_neighb_disc_ops_type_5 *icmp_neighb_disc_5;
//
// 	icmp_neighb_disc_5 = (struct icmpv6_neighb_disc_ops_type_5 *)
// 				pkt_pull(pkt,sizeof(*icmp_neighb_disc_5));
// 	if (icmp_neighb_disc_5 == NULL)
// 			return;
//
// 	tprintf("Reserved (0x%x) ", ntohs(icmp_neighb_disc_5->res1));
// 	tprintf("MTU (%u)", ntohl(icmp_neighb_disc_5->MTU));
}

static inline char *icmpv6_neighb_disc_ops(uint8_t code) {
	switch (code) {
	case 1:
		return "Source Link-Layer Address";
	case 2:
		return "Target Link-Layer Address";
	case 3:
		return "Prefix Information";
	case 4:
		return "Redirected Header";
	case 5:
		return "MTU";
	case 9:
		return "Source Address List";
	case 10:
		return "Target Address List";
	}

	return NULL;
};

static inline void dissect_neighb_disc_ops(struct pkt_buff *pkt)
{
	size_t ops_total_len, ops_payl_len;
	struct icmpv6_neighb_disc_ops_general *icmp_neighb_disc;
	
	while(pkt_len(pkt)) {
		icmp_neighb_disc = (struct icmpv6_neighb_disc_ops_general *)
				pkt_pull(pkt,sizeof(*icmp_neighb_disc));
		if (icmp_neighb_disc == NULL)
			return;

		ops_total_len = icmp_neighb_disc->len * 8;
		ops_payl_len = ops_total_len - sizeof(*icmp_neighb_disc);

		tprintf("\n\tOption %s (%u) ",
			  icmpv6_neighb_disc_ops(icmp_neighb_disc->type) ?
			  icmpv6_neighb_disc_ops(icmp_neighb_disc->type)
			  : "Type Unknown", icmp_neighb_disc->type);
		tprintf("Length (%u, %u bytes) ", icmp_neighb_disc->len,
			ops_total_len);
		
		switch (icmp_neighb_disc->type) {
		case 1:
			dissect_neighb_disc_ops_1(pkt, ops_payl_len);
			break;
		case 2:
			dissect_neighb_disc_ops_2(pkt, ops_payl_len);
			break;
		case 3:
			dissect_neighb_disc_ops_3(pkt, ops_payl_len);
			break;
		case 4:
			dissect_neighb_disc_ops_4(pkt, ops_payl_len);
			break;
		case 5:
			dissect_neighb_disc_ops_5(pkt, ops_payl_len);
			break;
		/* Type 9 and 10 defined in
		 * http://tools.ietf.org/html/rfc3122#section-3.1
		 */
		case 9:
			dissect_neighb_disc_ops_9(pkt, ops_payl_len);
			break;
		case 10:
			dissect_neighb_disc_ops_10(pkt, ops_payl_len);
			break;
		default:
			pkt_pull(pkt, ops_payl_len);
		}
	}
}

static inline void dissect_icmpv6_type133(struct pkt_buff *pkt)
{
	struct icmpv6_type_133 *icmp_133;

	icmp_133 = (struct icmpv6_type_133 *)
		      pkt_pull(pkt,sizeof(*icmp_133));
	if (icmp_133 == NULL)
		return;

	tprintf(", Reserved (0x%x)",ntohl(icmp_133->res));

	dissect_neighb_disc_ops(pkt);
}

static inline void dissect_icmpv6_type134(struct pkt_buff *pkt)
{
	struct icmpv6_type_134 *icmp_134;

	icmp_134 = (struct icmpv6_type_134 *)
		      pkt_pull(pkt,sizeof(*icmp_134));
	if (icmp_134 == NULL)
		return;

	tprintf(", Cur Hop Limit (%u)",icmp_134->cur_hop_limit);
	tprintf(", M (%u) O (%u)",icmp_134->m_o_res >> 7,
		(icmp_134->m_o_res >> 6) & 0x1);
	tprintf(", Router Lifetime (%us)",ntohs(icmp_134->router_lifetime));
	tprintf(", Reachable Time (%ums)",ntohl(icmp_134->reachable_time));
	tprintf(", Retrans Timer (%ums)",ntohl(icmp_134->retrans_timer));

	dissect_neighb_disc_ops(pkt);
}

static inline void dissect_icmpv6_type135(struct pkt_buff *pkt)
{
	char address[INET6_ADDRSTRLEN];
	struct icmpv6_type_135 *icmp_135;

	icmp_135 = (struct icmpv6_type_135 *)
		      pkt_pull(pkt,sizeof(*icmp_135));
	if (icmp_135 == NULL)
		return;

	tprintf(", Reserved (0x%x)",ntohl(icmp_135->res));
	tprintf(", Target Address: %s",
			inet_ntop(AF_INET6, &icmp_135->ipv6_addr,
				  address, sizeof(address)));

	dissect_neighb_disc_ops(pkt);
}

static inline void dissect_icmpv6_type136(struct pkt_buff *pkt)
{
	char address[INET6_ADDRSTRLEN];
	uint32_t r_s_o_res;
	struct icmpv6_type_136 *icmp_136;

	icmp_136 = (struct icmpv6_type_136 *)
		      pkt_pull(pkt,sizeof(*icmp_136));
	if (icmp_136 == NULL)
		return;
	r_s_o_res = ntohl(icmp_136->r_s_o_res);

	tprintf(", R (%u) S (%u) O (%u) Reserved (0x%x)", r_s_o_res >> 31,
		(r_s_o_res >> 30) & 0x1, (r_s_o_res >> 29) & 0x1,
		r_s_o_res & 0x1FFFFFFF);
	tprintf(", Target Address: %s",
			inet_ntop(AF_INET6, &icmp_136->ipv6_addr,
				  address, sizeof(address)));

	dissect_neighb_disc_ops(pkt);
}

static inline void dissect_icmpv6_type137(struct pkt_buff *pkt)
{
	char address[INET6_ADDRSTRLEN];
	struct icmpv6_type_137 *icmp_137;

	icmp_137 = (struct icmpv6_type_137 *)
		      pkt_pull(pkt,sizeof(*icmp_137));
	if (icmp_137 == NULL)
		return;

	tprintf(", Reserved (0x%x)",icmp_137->res);
	tprintf(", Target Address: %s",
			inet_ntop(AF_INET6, &icmp_137->ipv6_targ_addr,
				  address, sizeof(address)));
	tprintf(", Dest Address: %s",
			inet_ntop(AF_INET6, &icmp_137->ipv6_dest_addr,
				  address, sizeof(address)));

	dissect_neighb_disc_ops(pkt);
}

static inline void dissect_icmpv6_rr_body(struct pkt_buff *pkt)
{
	 /*
	  * Upgrade Dissector for Message Body
	  * from http://tools.ietf.org/html/rfc2894#section-3.2
	  */
	 if(pkt_len(pkt))
		tprintf(" Message Body recognized");
}

static inline char *icmpv6_type_138_codes(uint8_t code) {
	switch (code) {
	case 1:
		return "Router Renumbering Command";
	case 2:
		return "Router Renumbering Result";
	case 255:
		return "Sequence Number Reset";
	}
	
	return NULL;
};

static inline void dissect_icmpv6_type138(struct pkt_buff *pkt)
{
	struct icmpv6_type_138 *icmp_138;

	icmp_138 = (struct icmpv6_type_138 *)
		      pkt_pull(pkt,sizeof(*icmp_138));
	if (icmp_138 == NULL)
		return;

	tprintf(", Sequence Nr. (%u)",ntohl(icmp_138->seq_nr));
	tprintf(", Segment Nr. (%u)",icmp_138->seg_nr);
	tprintf(", T (%u) R (%u) A (%u) S (%u) P (%u) Res \
		(0x%x) ",icmp_138->flags >> 7, (icmp_138->flags >> 6) & 1,
		(icmp_138->flags >> 5) & 1, (icmp_138->flags >> 4) & 1,
		(icmp_138->flags >> 3) & 1, icmp_138->flags & 7);
	tprintf(", Max Delay (%ums)", ntohs(icmp_138->maxdelay));
	tprintf(", Res (0x%x)", ntohl(icmp_138->res));

	dissect_icmpv6_rr_body(pkt);
}

static inline void dissect_icmpv6_node_inf_data(struct pkt_buff *pkt)
{
	 /*
	  * Upgrade Dissector for Data field
	  * http://tools.ietf.org/html/rfc4620#section-4
	  */
	 if(pkt_len(pkt))
		tprintf(" Data recognized");
}

static char *icmpv6_node_inf_qtypes[] = {
	"NOOP",
	"unused",
	"Node Name",
	"Node Addresses",
	"IPv4 Addresses ",
};

static char *icmpv6_type_139_codes[] = {
	"Data contains IPv6 Address",
	"Data contains Name or nothing",
	"Data contains IPv4 Address",
};

static inline void dissect_icmpv6_type139(struct pkt_buff *pkt)
{
	char *qtype_name = "Unknown";
	uint16_t qtype_nr;
	struct icmpv6_type_139_140 *icmp_139;

	icmp_139 = (struct icmpv6_type_139_140 *)
		      pkt_pull(pkt,sizeof(*icmp_139));
	if (icmp_139 == NULL)
		return;

	qtype_nr = ntohs(icmp_139->qtype);
	if (icmpv6_code_range_valid(qtype_nr, icmpv6_node_inf_qtypes))
			qtype_name = icmpv6_node_inf_qtypes[qtype_nr];

	tprintf(", Qtype %s (%u)",qtype_name, qtype_nr);
	tprintf(", Flags (0x%x)",ntohs(icmp_139->flags));
	tprintf(", Nonce (0x%x)",ntohll(icmp_139->nonce));

	dissect_icmpv6_node_inf_data(pkt);
}

static char *icmpv6_type_140_codes[] = {
	"Successfull reply",
	"Responder refuses answer",
	"Qtype is unknown to the Responder",
};

static inline void dissect_icmpv6_type140(struct pkt_buff *pkt)
{
	dissect_icmpv6_type139(pkt);
}

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
		*optional = dissect_icmpv6_type131;
		return;
	case 132:
		*type = "Multicast Listener Done";
		*optional = dissect_icmpv6_type132;
		return;
	case 133:
		*type = "Router Solicitation";
		*optional = dissect_icmpv6_type133;
		return;
	case 134:
		*type = "Router Advertisement";
		*optional = dissect_icmpv6_type134;
		return;
	case 135:
		*type = "Neighbor Solicitation";
		*optional = dissect_icmpv6_type135;
		return;
	case 136:
		*type = "Neighbor Advertisement";
		*optional = dissect_icmpv6_type136;
		return;
	case 137:
		*type = "Redirect Message";
		*optional = dissect_icmpv6_type137;
		return;
	case 138:
		*type = "Router Renumbering";
		if(icmpv6_type_138_codes(icmp->h_code))
			*code = icmpv6_type_138_codes(icmp->h_code);
		*optional = dissect_icmpv6_type138;
		return;
	case 139:
		*type = "ICMP Node Information Query";
		if (icmpv6_code_range_valid(icmp->h_code,
					  icmpv6_type_139_codes))
			*code = icmpv6_type_139_codes[icmp->h_code];
		*optional = dissect_icmpv6_type139;
		return;
	case 140:
		*type = "ICMP Node Information Response";
		if (icmpv6_code_range_valid(icmp->h_code,
					  icmpv6_type_140_codes))
			*code = icmpv6_type_140_codes[icmp->h_code];
		*optional = dissect_icmpv6_type140;
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

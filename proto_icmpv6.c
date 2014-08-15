/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend <markus@netsniff-ng.org>, Deutsche Flugsicherung GmbH
 * Subject to the GPL, version 2.
 *
 * ICMPv6 described in RFC4443, RFC2710, RFC4861, RFC2894,
 * RFC4620, RFC3122, RFC3810, RFC3775, RFC3971, RFC4065
 * RFC4286
 * Look also for an good overview:
 * http://www.iana.org/assignments/icmpv6-parameters
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <asm/byteorder.h>

#include "proto.h"
#include "protos.h"
#include "pkt_buff.h"
#include "built_in.h"

#define icmpv6_code_range_valid(code, sarr)	((size_t) (code) < array_size((sarr)))

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
struct icmpv6_type_133_141_142 {
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

struct icmpv6_neighb_disc_ops_type_9_10 {
	uint16_t res1;
	uint32_t res2;
	uint8_t ip_hdr_data[0];
} __packed;

struct icmpv6_neighb_disc_ops_type_15 {
	uint8_t name_type;
	size_t pad_len;
	char name[0];
	uint8_t pad[0];
} __packed;

struct icmpv6_neighb_disc_ops_type_16 {
	uint8_t cert_type;
	uint8_t res;
	uint8_t cert[0];
	uint8_t pad[0];
} __packed;

struct icmpv6_neighb_disc_ops_type_17 {
	uint8_t opt_code;
	uint8_t prefix_len;
	uint8_t data[0];
} __packed;

struct icmpv6_neighb_disc_ops_type_17_1 {
	uint32_t res;
	struct in6_addr ipv6_addr;
} __packed;

struct icmpv6_neighb_disc_ops_type_17_2 {
	struct in6_addr ipv6_addr;
} __packed;

struct icmpv6_neighb_disc_ops_type_19 {
	uint8_t opt_code;
	uint8_t lla[0];
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

/* MLDv2 report */
struct icmpv6_type_143 {
	uint16_t res;
	uint16_t nr_rec;
	uint8_t addr_rec[0];
} __packed;

struct icmpv6_mldv2_addr_rec {
	uint8_t rec_type;
	uint8_t aux_data_len;
	uint16_t nr_src;
	struct in6_addr multic_addr;
	struct in6_addr src_addr[0];
} __packed;
/* end MLDv2 report */

/* ICMP Mobility Support */
struct icmpv6_type_144_146 {
	uint16_t id;
	uint16_t res;
} __packed;

struct icmpv6_type_145 {
	uint16_t id;
	uint16_t res;
	struct in6_addr home_agent_addr[0];
} __packed;

struct icmpv6_type_147 {
	uint16_t id;
	uint16_t m_o_res;
	uint8_t ops[0];
} __packed;
/* end ICMP Mobility Support */

/* SEcure Neighbor Discovery */
struct icmpv6_type_148 {
	uint16_t id;
	uint16_t comp;
	uint8_t ops[0];
} __packed;

struct icmpv6_type_149 {
	uint16_t id;
	uint16_t all_comp;
	uint16_t comp;
	uint16_t res;
	uint8_t ops[0];
} __packed;
/* end SEcure Neighbor Discovery */

struct icmpv6_type_150 {
	union {
		uint32_t subtype_res;
		struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
			uint32_t res     :24,
				 subtype :8;
#elif defined(__BIG_ENDIAN_BITFIELD)
			uint32_t subtype :8,
				 res     :24;
#else
# error "Please fix <asm/byteorder.h>"
#endif
		};
	};
	uint8_t ops[0];
} __packed;

/* Multicast Router Discovery */
struct icmpv6_type_151 {
	uint16_t query_intv;
	uint16_t rob_var;
} __packed;

struct icmpv6_type_152 {
	uint8_t null[0];
} __packed;

struct icmpv6_type_153 {
	uint8_t null[0];
} __packed;
/* end Multicast Router Discovery */

struct icmpv6_type_154 {
	uint8_t subtype;
	uint8_t res;
	uint16_t id;
	uint8_t ops[0];
} __packed;

static int8_t print_ipv6_addr_list(struct pkt_buff *pkt, uint8_t nr_addr)
{
	char address[INET6_ADDRSTRLEN];
	struct in6_addr *addr;
	
	while (nr_addr--) {
	    addr = (struct in6_addr *) pkt_pull(pkt, sizeof(*addr));
	    if (addr == NULL)
		    return 0;

	    tprintf("\n\t   Address: %s",
		    inet_ntop(AF_INET6, addr, address,
			      sizeof(address)));
	}

	return 1;
}

static const char *icmpv6_mcast_rec_types[] = {
	"MODE_IS_INCLUDE",
	"MODE_IS_EXCLUDE",
	"CHANGE_TO_INCLUDE_MODE",
	"CHANGE_TO_EXCLUDE_MODE",
	"ALLOW_NEW_SOURCES",
	"BLOCK_OLD_SOURCES",
};

static int8_t dissect_icmpv6_mcast_rec(struct pkt_buff *pkt,
				       uint16_t nr_rec)
{
	uint16_t nr_src, aux_data_len_bytes;
	char address[INET6_ADDRSTRLEN];
	struct icmpv6_mldv2_addr_rec *addr_rec;

	while (nr_rec--) {
		addr_rec = (struct icmpv6_mldv2_addr_rec *)
		      pkt_pull(pkt,sizeof(*addr_rec));
		if (addr_rec == NULL)
			return 0;
		aux_data_len_bytes = addr_rec->aux_data_len * 4;
		nr_src = ntohs(addr_rec->nr_src);

		tprintf(", Rec Type %s (%u)",
			icmpv6_code_range_valid(addr_rec->rec_type - 1,
			icmpv6_mcast_rec_types) ?
			icmpv6_mcast_rec_types[addr_rec->rec_type - 1]
			: "Unknown", addr_rec->rec_type);
		if (aux_data_len_bytes > pkt_len(pkt)) {
			tprintf(", Aux Data Len (%u, %u bytes) %s",
			      addr_rec->aux_data_len,
			      aux_data_len_bytes,
			      colorize_start_full(black, red) "invalid"
			      colorize_end());
			return 0;
		}
		tprintf(", Aux Data Len (%u, %u bytes)",addr_rec->aux_data_len,
			aux_data_len_bytes);
		tprintf(", Nr. of Sources (%u)",nr_src);
		tprintf(", Address: %s",
			inet_ntop(AF_INET6, &addr_rec->multic_addr,
				  address, sizeof(address)));

		if(!print_ipv6_addr_list(pkt, nr_src))
			return 0;

		if (aux_data_len_bytes > pkt_len(pkt)) {
			tprintf("\nAux Data Len %s",
			      colorize_start_full(black, red) "invalid"
			      colorize_end());
			return 0;
		}
		
		tprintf(", Aux Data: ");
		while (aux_data_len_bytes--) {
			uint8_t *data = pkt_pull(pkt, 1);

			if (data == NULL) {
				tprintf("%sINVALID%s", colorize_start_full(black, red),
					colorize_end());
				return 0;
			}

			tprintf("%x", *data);
		}
	}

	return 1;
}

static int8_t dissect_neighb_disc_ops_1(struct pkt_buff *pkt,
					ssize_t len)
{
	struct icmpv6_neighb_disc_ops_type_1_2 *icmp_neighb_disc_1;

	icmp_neighb_disc_1 = (struct icmpv6_neighb_disc_ops_type_1_2 *)
				pkt_pull(pkt,sizeof(*icmp_neighb_disc_1));
	if (icmp_neighb_disc_1 == NULL)
			return 0;
	len -= sizeof(*icmp_neighb_disc_1);
	if (len < 0)
	      return 0;

	tprintf("Address 0x");

	while (len--) {
		uint8_t *data = pkt_pull(pkt, 1);

		if (data == NULL) {
			tprintf("%sINVALID%s", colorize_start_full(black, red),
				colorize_end());
			return 0;
		}

		tprintf("%x", *data);
	}

	return 1;
}

static int8_t dissect_neighb_disc_ops_2(struct pkt_buff *pkt,
					ssize_t len)
{
	return dissect_neighb_disc_ops_1(pkt, len);
}

static int8_t dissect_neighb_disc_ops_3(struct pkt_buff *pkt,
				        ssize_t len)
{
	char address[INET6_ADDRSTRLEN];
	struct icmpv6_neighb_disc_ops_type_3 *icmp_neighb_disc_3;

	icmp_neighb_disc_3 = (struct icmpv6_neighb_disc_ops_type_3 *)
				pkt_pull(pkt,sizeof(*icmp_neighb_disc_3));
	if (icmp_neighb_disc_3 == NULL)
			return 0;
	len -= sizeof(*icmp_neighb_disc_3);
	if (len < 0)
	      return 0;

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
	tprintf("Prefix: %s ",
				inet_ntop(AF_INET6,&icmp_neighb_disc_3->prefix,
				address, sizeof(address)));

	return 1;
}

static int8_t dissect_neighb_disc_ops_4(struct pkt_buff *pkt,
					ssize_t len)
{
	struct icmpv6_neighb_disc_ops_type_4 *icmp_neighb_disc_4;

	icmp_neighb_disc_4 = (struct icmpv6_neighb_disc_ops_type_4 *)
				pkt_pull(pkt,sizeof(*icmp_neighb_disc_4));
	if (icmp_neighb_disc_4 == NULL)
			return 0;
	len -= sizeof(*icmp_neighb_disc_4);
	if (len < 0)
	      return 0;

	tprintf("Reserved 1 (0x%x) ", ntohs(icmp_neighb_disc_4->res1));
	tprintf("Reserved 2 (0x%x) ", ntohl(icmp_neighb_disc_4->res2));
	tprintf("IP header + data ");

	while (len--) {
		uint8_t *data = pkt_pull(pkt, 1);

		if (data == NULL) {
			tprintf("%sINVALID%s", colorize_start_full(black, red),
				colorize_end());
			return 0;
		}

		tprintf("%x", *data);
	}

	return 1;
}

static int8_t dissect_neighb_disc_ops_5(struct pkt_buff *pkt,
					ssize_t len)
{
	struct icmpv6_neighb_disc_ops_type_5 *icmp_neighb_disc_5;

	icmp_neighb_disc_5 = (struct icmpv6_neighb_disc_ops_type_5 *)
				pkt_pull(pkt,sizeof(*icmp_neighb_disc_5));
	if (icmp_neighb_disc_5 == NULL)
			return 0;
	len -= sizeof(*icmp_neighb_disc_5);
	if (len < 0)
	      return 0;

	tprintf("Reserved (0x%x) ", ntohs(icmp_neighb_disc_5->res1));
	tprintf("MTU (%u)", ntohl(icmp_neighb_disc_5->MTU));

	return 1;
}

static int8_t dissect_neighb_disc_ops_9(struct pkt_buff *pkt,
					ssize_t len)
{
	struct icmpv6_neighb_disc_ops_type_9_10 *icmp_neighb_disc_9;

	icmp_neighb_disc_9 = (struct icmpv6_neighb_disc_ops_type_9_10 *)
				pkt_pull(pkt,sizeof(*icmp_neighb_disc_9));
	if (icmp_neighb_disc_9 == NULL)
			return 0;
	len -= sizeof(*icmp_neighb_disc_9);
	if (len < 0)
	      return 0;

	tprintf("Reserved 1 (0x%x) ", ntohs(icmp_neighb_disc_9->res1));
	tprintf("Reserved 2 (0x%x) ", ntohl(icmp_neighb_disc_9->res2));

	return print_ipv6_addr_list(pkt, len / sizeof(struct in6_addr));
}

static int8_t dissect_neighb_disc_ops_10(struct pkt_buff *pkt,
					 ssize_t len)
{
	return dissect_neighb_disc_ops_9(pkt, len);
}

static const char *icmpv6_neighb_disc_ops_15_name[] = {
	"DER Encoded X.501 Name",
	"FQDN",
};

static int8_t dissect_neighb_disc_ops_15(struct pkt_buff *pkt,
					 ssize_t len)
{
	size_t pad_len;
	ssize_t name_len;
	struct icmpv6_neighb_disc_ops_type_15 *icmp_neighb_disc_15;

	icmp_neighb_disc_15 = (struct icmpv6_neighb_disc_ops_type_15 *)
				pkt_pull(pkt,sizeof(*icmp_neighb_disc_15));
	if (icmp_neighb_disc_15 == NULL)
			return 0;
	len -= sizeof(*icmp_neighb_disc_15);
	if (len < 0)
	      return 0;
	pad_len = icmp_neighb_disc_15->pad_len;

	tprintf("Name Type %s (%u) ",
		icmpv6_code_range_valid(icmp_neighb_disc_15->name_type - 1,
		icmpv6_neighb_disc_ops_15_name) ?
		icmpv6_neighb_disc_ops_15_name[
		icmp_neighb_disc_15->name_type - 1] : "Unknown",
		icmp_neighb_disc_15->name_type);
	if (pad_len > (size_t) len) {
		tprintf("Pad Len (%zu, invalid)\n%s", pad_len,
			colorize_start_full(black, red)
			"Skip Option" colorize_end());
		pkt_pull(pkt, len);
		return 1;
	}
	else
		tprintf("Pad Len (%zu) ", pad_len);

	name_len = len - pad_len;

	tprintf("Name (");
	while (name_len--) {
		uint8_t *data = pkt_pull(pkt, 1);

		if (data == NULL) {
			tprintf("%sINVALID%s", colorize_start_full(black, red),
				colorize_end());
			return 0;
		}

		tprintf("%c", *data);
	}
	tprintf(") ");

	tprintf("Padding (");

	while (pad_len--) {
		uint8_t *data = pkt_pull(pkt, 1);

		if (data == NULL) {
			tprintf("%sINVALID%s", colorize_start_full(black, red),
				colorize_end());
			break;
		}

		tprintf("%x", *data);
	}
	tprintf(")");

	return 1;
}

static const char *icmpv6_neighb_disc_ops_16_cert[] = {
	"X.509v3 Certificate",
};

static int8_t dissect_neighb_disc_ops_16(struct pkt_buff *pkt,
					 ssize_t len)
{
	struct icmpv6_neighb_disc_ops_type_16 *icmp_neighb_disc_16;

	icmp_neighb_disc_16 = (struct icmpv6_neighb_disc_ops_type_16 *)
				pkt_pull(pkt,sizeof(*icmp_neighb_disc_16));
	if (icmp_neighb_disc_16 == NULL)
			return 0;
	len -= sizeof(*icmp_neighb_disc_16);
	if (len < 0)
	      return 0;

	tprintf("Cert Type %s (%u) ",
		icmpv6_code_range_valid(icmp_neighb_disc_16->cert_type - 1,
		icmpv6_neighb_disc_ops_16_cert) ?
		icmpv6_neighb_disc_ops_16_cert[
		icmp_neighb_disc_16->cert_type - 1] : "Unknown",
		icmp_neighb_disc_16->cert_type);
	tprintf("Res (0x%x) ", icmp_neighb_disc_16->res);

	tprintf("Certificate + Padding (");
	while (len--) {
		uint8_t *data = pkt_pull(pkt, 1);

		if (data == NULL) {
			tprintf("%sINVALID%s", colorize_start_full(black, red),
				colorize_end());
			break;
		}

		tprintf("%x", *data);
	}
	tprintf(") ");

	return 1;
}

static const char *icmpv6_neighb_disc_ops_17_codes[] = {
	"Old Care-of Address",
	"New Care-of Address",
	"NAR's IP address",
	"NAR's Prefix",
};

static int8_t dissect_neighb_disc_ops_17(struct pkt_buff *pkt,
					 ssize_t len)
{
	char address[INET6_ADDRSTRLEN];
	struct icmpv6_neighb_disc_ops_type_17 *icmp_neighb_disc_17;

	icmp_neighb_disc_17 = (struct icmpv6_neighb_disc_ops_type_17 *)
				pkt_pull(pkt,sizeof(*icmp_neighb_disc_17));
	if (icmp_neighb_disc_17 == NULL)
			return 0;
	len -= sizeof(*icmp_neighb_disc_17);
	if (len < 0)
	      return 0;

	tprintf("Opt Code %s (%u) ",
		icmpv6_code_range_valid(icmp_neighb_disc_17->opt_code - 1,
		icmpv6_neighb_disc_ops_17_codes) ?
		icmpv6_neighb_disc_ops_17_codes[
		icmp_neighb_disc_17->opt_code - 1] : "Unknown",
		icmp_neighb_disc_17->opt_code);
	tprintf("Prefix Len (%u) ", icmp_neighb_disc_17->prefix_len);

	if (len == sizeof(struct icmpv6_neighb_disc_ops_type_17_1)) {
		    struct icmpv6_neighb_disc_ops_type_17_1
						      *icmp_neighb_disc_17_1;
						      
		    icmp_neighb_disc_17_1 =
				  (struct icmpv6_neighb_disc_ops_type_17_1 *)
				  pkt_pull(pkt,sizeof(*icmp_neighb_disc_17_1));
		    if (icmp_neighb_disc_17_1 == NULL)
				  return 0;
		    len -= sizeof(*icmp_neighb_disc_17_1);
		    if (len < 0)
			  return 0;

		    tprintf("Res (0x%x) ",icmp_neighb_disc_17_1->res);
		    tprintf("Addr: %s ",
			  inet_ntop(AF_INET6,&icmp_neighb_disc_17_1->ipv6_addr,
			  address, sizeof(address)));
	}
	else if (len == sizeof(struct icmpv6_neighb_disc_ops_type_17_2)) {
		    struct icmpv6_neighb_disc_ops_type_17_2
						      *icmp_neighb_disc_17_2;

		    icmp_neighb_disc_17_2 =
				  (struct icmpv6_neighb_disc_ops_type_17_2 *)
				  pkt_pull(pkt,sizeof(*icmp_neighb_disc_17_2));
		    if (icmp_neighb_disc_17_2 == NULL)
				  return 0;
		    len -= sizeof(*icmp_neighb_disc_17_2);
		    if (len < 0)
			  return 0;

		    tprintf("Addr: %s ",
			  inet_ntop(AF_INET6,&icmp_neighb_disc_17_2->ipv6_addr,
			  address, sizeof(address)));
	}
	else {
		    tprintf("%s (", colorize_start_full(black, red)
			      "Error Wrong Length. Skip Option" colorize_end());
		    while (len--) {
			uint8_t *data = pkt_pull(pkt, 1);

			if (data == NULL) {
				tprintf("%sINVALID%s", colorize_start_full(black, red),
					colorize_end());
				break;
			}

			tprintf("%x", *data);
		    }
		    tprintf(") ");
	}

	return 1;
}

static const char *icmpv6_neighb_disc_ops_19_codes[] = {
	"Wildcard requesting resolution for all nearby access points",
	"Link-Layer Address of the New Access Point",
	"Link-Layer Address of the MN",
	"Link-Layer Address of the NAR",
	"Link-Layer Address of the source of RtSolPr or PrRtAdv \
         message",
	"The access point identified by the LLA belongs to the \
         current interface of the router",
	"No prefix information available for the access point \
         identified by the LLA",
	"No fast handover support available for the access point \
         identified by the LLA",
};

static int8_t dissect_neighb_disc_ops_19(struct pkt_buff *pkt,
					 ssize_t len)
{
	struct icmpv6_neighb_disc_ops_type_19 *icmp_neighb_disc_19;

	icmp_neighb_disc_19 = (struct icmpv6_neighb_disc_ops_type_19 *)
				pkt_pull(pkt,sizeof(*icmp_neighb_disc_19));
	if (icmp_neighb_disc_19 == NULL)
			return 0;
	len -= sizeof(*icmp_neighb_disc_19);
	if (len < 0)
	      return 0;

	tprintf("Opt Code %s (%u) ",
		icmpv6_code_range_valid(icmp_neighb_disc_19->opt_code,
		icmpv6_neighb_disc_ops_19_codes) ?
		icmpv6_neighb_disc_ops_19_codes[
		icmp_neighb_disc_19->opt_code] : "Unknown",
		icmp_neighb_disc_19->opt_code);

	tprintf("LLA (");
	while(len--) {
		uint8_t *data = pkt_pull(pkt, 1);

		if (data == NULL) {
			tprintf("%sINVALID%s", colorize_start_full(black, red),
				colorize_end());
			return 0;
		}

		tprintf("%x", *data);
	}
	tprintf(") ");

	return 1;
}

static inline char *icmpv6_neighb_disc_ops(uint8_t code) {
	switch (code) {
	case  1: return "Source Link-Layer Address";
	case  2: return "Target Link-Layer Address";
	case  3: return "Prefix Information";
	case  4: return "Redirected Header";
	case  5: return "MTU";
	case  6: return "NBMA Shortcut Limit Option";
	case  7: return "Advertisement Interval Option";
	case  8: return "Home Agent Information Option";
	case  9: return "Source Address List";
	case 10: return "Target Address List";
	case 11: return "CGA option";
	case 12: return "RSA Signature option";
	case 13: return "Timestamp option";
	case 14: return "Nonce option";
	case 15: return "Trust Anchor option";
	case 16: return "Certificate option";
	case 17: return "IP Address/Prefix Option";
	case 18: return "New Router Prefix Information Option";
	case 19: return "Link-layer Address Option";
	case 20: return "Neighbor Advertisement Acknowledgment Option";

	case 23: return "Prefix Information";
	case 24: return "Redirected Header";
	case 25: return "MTU";
	case 26: return "NBMA Shortcut Limit Option";
	case 27: return "Advertisement Interval Option";
	case 28: return "Home Agent Information Option";
	case 29: return "Source Address List";
	case 30: return "Target Address List";
	case 31: return "DNS Search List Option";
	case 32: return "Proxy Signature (PS)";

	case 138: return "CARD Request option";
	case 139: return "CARD Reply option";

	case 253: return "RFC3692-style Experiment 1";
	case 254: return "RFC3692-style Experiment 2";
	}

	return NULL;
};

static int8_t dissect_neighb_disc_ops(struct pkt_buff *pkt)
{
	size_t pad_bytes;
	uint16_t ops_total_len;
	ssize_t ops_payl_len;
	struct icmpv6_neighb_disc_ops_general *icmp_neighb_disc;

	while(pkt_len(pkt)) {
		icmp_neighb_disc = (struct icmpv6_neighb_disc_ops_general *)
				pkt_pull(pkt,sizeof(*icmp_neighb_disc));
		if (icmp_neighb_disc == NULL)
			return 0;

		ops_total_len = icmp_neighb_disc->len * 8;
		pad_bytes = (size_t) (ops_total_len % 8);
		ops_payl_len = ops_total_len - sizeof(*icmp_neighb_disc) -
								pad_bytes;

		tprintf("\n\tOption %s (%u) ",
			  icmpv6_neighb_disc_ops(icmp_neighb_disc->type) ?
			  icmpv6_neighb_disc_ops(icmp_neighb_disc->type)
			  : "Type Unknown", icmp_neighb_disc->type);
		if (ops_payl_len > pkt_len(pkt) || ops_payl_len < 0) {
			tprintf("Length (%u, %u bytes, %s%s%s) ",
					  icmp_neighb_disc->len,
					  ops_total_len,
					  colorize_start_full(black, red),
					  "invalid", colorize_end());
			return 0;
		}

		tprintf("Length (%u, %u bytes) ",icmp_neighb_disc->len,
						 ops_total_len);

		switch (icmp_neighb_disc->type) {
		case 1:
			if (!dissect_neighb_disc_ops_1(pkt, ops_payl_len))
			      return 0;
			break;
		case 2:
			if (!dissect_neighb_disc_ops_2(pkt, ops_payl_len))
			      return 0;
			break;
		case 3:
			if (!dissect_neighb_disc_ops_3(pkt, ops_payl_len))
			      return 0;
			break;
		case 4:
			if (!dissect_neighb_disc_ops_4(pkt, ops_payl_len))
			      return 0;
			break;
		case 5:
			if (!dissect_neighb_disc_ops_5(pkt, ops_payl_len))
			      return 0;
			break;
		/* Type 9 and 10 defined in
		 * http://tools.ietf.org/html/rfc3122#section-3.1
		 */
		case 9:
			if (!dissect_neighb_disc_ops_9(pkt, ops_payl_len))
			      return 0;
			break;
		case 10:
			if (!dissect_neighb_disc_ops_10(pkt, ops_payl_len))
			      return 0;
			break;
		/* Type 15 and 16 defined in
		 * http://tools.ietf.org/html/rfc3971#section-6.4.3
		 * http://tools.ietf.org/html/rfc3971#section-6.4.4
		 */
		case 15:
			if (!dissect_neighb_disc_ops_15(pkt, ops_payl_len))
			      return 0;
			break;
		case 16:
			if (!dissect_neighb_disc_ops_16(pkt, ops_payl_len))
			      return 0;
			break;
		/* Type 17 and 19 defined in
		 * http://tools.ietf.org/html/rfc5568#section-6.4
		 */
		case 17:
			if (!dissect_neighb_disc_ops_17(pkt, ops_payl_len))
			      return 0;
			break;
		case 19:
			if (!dissect_neighb_disc_ops_19(pkt, ops_payl_len))
			      return 0;
			break;
		default:
			pkt_pull(pkt, ops_payl_len);
		}

		/* Skip Padding Bytes */
		if (pad_bytes > pkt_len(pkt)) {
			tprintf(" %s",colorize_start_full(black, red)
			"Invalid Padding" colorize_end());
			return 0;
		}
		pkt_pull(pkt, pad_bytes);
	}

	return 1;
}

static const char *icmpv6_type_1_codes[] = {
	"No route to destination",
	"Communication with destination administratively prohibited",
	"Beyond scope of source address",
	"Address unreachable",
	"Port unreachable",
	"Source address failed ingress/egress policy",
	"Reject route to destination",
	"Error in Source Routing Header",
};

static int8_t dissect_icmpv6_type1(struct pkt_buff *pkt)
{
	struct icmpv6_type_1_3 *icmp_1;
	
	icmp_1 = (struct icmpv6_type_1_3 *) pkt_pull(pkt,sizeof(*icmp_1));
	if (icmp_1 == NULL)
		return 0;

	tprintf(", Unused (0x%x)",ntohl(icmp_1->unused));
	tprintf(" Payload include as much of invoking packet");

	return 1;
}

static int8_t dissect_icmpv6_type2(struct pkt_buff *pkt)
{
	struct icmpv6_type_2 *icmp_2;

	icmp_2 = (struct icmpv6_type_2 *) pkt_pull(pkt,sizeof(*icmp_2));
	if (icmp_2 == NULL)
		return 0;

	tprintf(", MTU (0x%x)",ntohl(icmp_2->MTU));
	tprintf(" Payload include as much of invoking packet");

	return 1;
}

static const char *icmpv6_type_3_codes[] = {
	"Hop limit exceeded in transit",
	"Fragment reassembly time exceeded",
};

static int8_t dissect_icmpv6_type3(struct pkt_buff *pkt)
{
	struct icmpv6_type_1_3 *icmp_3;

	icmp_3 = (struct icmpv6_type_1_3 *) pkt_pull(pkt,sizeof(*icmp_3));
	if (icmp_3 == NULL)
		return 0;

	tprintf(", Unused (0x%x)",ntohl(icmp_3->unused));
	tprintf(" Payload include as much of invoking packet");

	return 1;
}

static const char *icmpv6_type_4_codes[] = {
	"Erroneous header field encountered",
	"Unrecognized Next Header type encountered",
	"Unrecognized IPv6 option encountered",
};

static int8_t dissect_icmpv6_type4(struct pkt_buff *pkt)
{
	struct icmpv6_type_4 *icmp_4;

	icmp_4 = (struct icmpv6_type_4 *) pkt_pull(pkt,sizeof(*icmp_4));
	if (icmp_4 == NULL)
		return 0;

	tprintf(", Pointer (0x%x)",ntohl(icmp_4->pointer));
	tprintf(" Payload include as much of invoking packet");

	return 1;
}

static int8_t dissect_icmpv6_type128(struct pkt_buff *pkt)
{
	struct icmpv6_type_128_129 *icmp_128;

	icmp_128 = (struct icmpv6_type_128_129 *)
		      pkt_pull(pkt,sizeof(*icmp_128));
	if (icmp_128 == NULL)
		return 0;

	tprintf(", ID (0x%x)",ntohs(icmp_128->id));
	tprintf(", Seq. Nr. (%u)",ntohs(icmp_128->sn));
	tprintf(" Payload include Data");

	return 1;
}

static int8_t dissect_icmpv6_type129(struct pkt_buff *pkt)
{
	struct icmpv6_type_128_129 *icmp_129;

	icmp_129 = (struct icmpv6_type_128_129 *)
		      pkt_pull(pkt,sizeof(*icmp_129));
	if (icmp_129 == NULL)
		return 0;

	tprintf(", ID (0x%x)",ntohs(icmp_129->id));
	tprintf(", Seq. Nr. (%u)",ntohs(icmp_129->sn));
	tprintf(" Payload include Data");

	return 1;
}

static int8_t dissect_icmpv6_type130(struct pkt_buff *pkt)
{
	char address[INET6_ADDRSTRLEN];
	uint16_t nr_src, maxrespdel;
	uint8_t switch_mldv2 = 0;
	struct icmpv6_type_130_131_132 *icmp_130;

	icmp_130 = (struct icmpv6_type_130_131_132 *)
		      pkt_pull(pkt,sizeof(*icmp_130));
	if (icmp_130 == NULL)
		return 0;
	maxrespdel = ntohs(icmp_130->maxrespdel);

	if(pkt_len(pkt) >= sizeof(struct icmpv6_type_130_mldv2))
		  switch_mldv2 = 1;

	if(switch_mldv2)
		tprintf(", MLDv2, Max Resp Delay (%ums)", maxrespdel >> 15 ?
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
			return 0;
		
		nr_src = ntohs(icmp_130_mldv2->nr_src);

		tprintf(", Resv (0x%x)",icmp_130_mldv2->resv_S_QRV >> 4);
		tprintf(", S (%u)",(icmp_130_mldv2->resv_S_QRV >> 3) & 0x1);
		tprintf(", QRV (0x%x)",icmp_130_mldv2->resv_S_QRV & 0x3);
		tprintf(", QQIC (%u)",icmp_130_mldv2->QQIC);
		tprintf(", Nr Src (%u)",nr_src);

		return print_ipv6_addr_list(pkt, nr_src);
	}

	return 1;
}

static int8_t dissect_icmpv6_type131(struct pkt_buff *pkt)
{
	char address[INET6_ADDRSTRLEN];
	struct icmpv6_type_130_131_132 *icmp_131;

	icmp_131 = (struct icmpv6_type_130_131_132 *)
		      pkt_pull(pkt,sizeof(*icmp_131));
	if (icmp_131 == NULL)
		return 0;

	tprintf(", Max Resp Delay (%ums)",ntohs(icmp_131->maxrespdel));
	tprintf(", Res (0x%x)",ntohs(icmp_131->res));
	tprintf(", Address: %s",
			inet_ntop(AF_INET6, &icmp_131->ipv6_addr,
				  address, sizeof(address)));

	return 1;
}

static inline int8_t dissect_icmpv6_type132(struct pkt_buff *pkt)
{
	return dissect_icmpv6_type131(pkt);
}

static int8_t dissect_icmpv6_type133(struct pkt_buff *pkt)
{
	struct icmpv6_type_133_141_142 *icmp_133;

	icmp_133 = (struct icmpv6_type_133_141_142 *)
		      pkt_pull(pkt,sizeof(*icmp_133));
	if (icmp_133 == NULL)
		return 0;

	tprintf(", Reserved (0x%x)",ntohl(icmp_133->res));

	return dissect_neighb_disc_ops(pkt);
}

static int8_t dissect_icmpv6_type134(struct pkt_buff *pkt)
{
	struct icmpv6_type_134 *icmp_134;

	icmp_134 = (struct icmpv6_type_134 *)
		      pkt_pull(pkt,sizeof(*icmp_134));
	if (icmp_134 == NULL)
		return 0;

	tprintf(", Cur Hop Limit (%u)",icmp_134->cur_hop_limit);
	tprintf(", M (%u) O (%u)",icmp_134->m_o_res >> 7,
		(icmp_134->m_o_res >> 6) & 0x1);
	tprintf(", Router Lifetime (%us)",ntohs(icmp_134->router_lifetime));
	tprintf(", Reachable Time (%ums)",ntohl(icmp_134->reachable_time));
	tprintf(", Retrans Timer (%ums)",ntohl(icmp_134->retrans_timer));

	return dissect_neighb_disc_ops(pkt);
}

static int8_t dissect_icmpv6_type135(struct pkt_buff *pkt)
{
	char address[INET6_ADDRSTRLEN];
	struct icmpv6_type_135 *icmp_135;

	icmp_135 = (struct icmpv6_type_135 *)
		      pkt_pull(pkt,sizeof(*icmp_135));
	if (icmp_135 == NULL)
		return 0;

	tprintf(", Reserved (0x%x)",ntohl(icmp_135->res));
	tprintf(", Target Address: %s",
			inet_ntop(AF_INET6, &icmp_135->ipv6_addr,
				  address, sizeof(address)));

	return dissect_neighb_disc_ops(pkt);
}

static int8_t dissect_icmpv6_type136(struct pkt_buff *pkt)
{
	char address[INET6_ADDRSTRLEN];
	uint32_t r_s_o_res;
	struct icmpv6_type_136 *icmp_136;

	icmp_136 = (struct icmpv6_type_136 *)
		      pkt_pull(pkt,sizeof(*icmp_136));
	if (icmp_136 == NULL)
		return 0;
	r_s_o_res = ntohl(icmp_136->r_s_o_res);

	tprintf(", R (%u) S (%u) O (%u) Reserved (0x%x)", r_s_o_res >> 31,
		(r_s_o_res >> 30) & 0x1, (r_s_o_res >> 29) & 0x1,
		r_s_o_res & 0x1FFFFFFF);
	tprintf(", Target Address: %s",
			inet_ntop(AF_INET6, &icmp_136->ipv6_addr,
				  address, sizeof(address)));

	return dissect_neighb_disc_ops(pkt);
}

static int8_t dissect_icmpv6_type137(struct pkt_buff *pkt)
{
	char address[INET6_ADDRSTRLEN];
	struct icmpv6_type_137 *icmp_137;

	icmp_137 = (struct icmpv6_type_137 *)
		      pkt_pull(pkt,sizeof(*icmp_137));
	if (icmp_137 == NULL)
		return 0;

	tprintf(", Reserved (0x%x)",icmp_137->res);
	tprintf(", Target Address: %s",
			inet_ntop(AF_INET6, &icmp_137->ipv6_targ_addr,
				  address, sizeof(address)));
	tprintf(", Dest Address: %s",
			inet_ntop(AF_INET6, &icmp_137->ipv6_dest_addr,
				  address, sizeof(address)));

	return dissect_neighb_disc_ops(pkt);
}

static void dissect_icmpv6_rr_body(struct pkt_buff *pkt)
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
	case   1: return "Router Renumbering Command";
	case   2: return "Router Renumbering Result";
	case 255: return "Sequence Number Reset";
	}
	
	return NULL;
};

static int8_t dissect_icmpv6_type138(struct pkt_buff *pkt)
{
	struct icmpv6_type_138 *icmp_138;

	icmp_138 = (struct icmpv6_type_138 *)
		      pkt_pull(pkt,sizeof(*icmp_138));
	if (icmp_138 == NULL)
		return 0;

	tprintf(", Sequence Nr. (%u)",ntohl(icmp_138->seq_nr));
	tprintf(", Segment Nr. (%u)",icmp_138->seg_nr);
	tprintf(", T (%u) R (%u) A (%u) S (%u) P (%u) Res \
		(0x%x) ",icmp_138->flags >> 7, (icmp_138->flags >> 6) & 1,
		(icmp_138->flags >> 5) & 1, (icmp_138->flags >> 4) & 1,
		(icmp_138->flags >> 3) & 1, icmp_138->flags & 7);
	tprintf(", Max Delay (%ums)", ntohs(icmp_138->maxdelay));
	tprintf(", Res (0x%x)", ntohl(icmp_138->res));

	dissect_icmpv6_rr_body(pkt);

	return 1;
}

static void dissect_icmpv6_node_inf_data(struct pkt_buff *pkt)
{
	 /*
	  * Upgrade Dissector for Data field
	  * http://tools.ietf.org/html/rfc4620#section-4
	  */
	 if(pkt_len(pkt))
		tprintf(" Data recognized");
}

static const char *icmpv6_node_inf_qtypes[] = {
	"NOOP",
	"unused",
	"Node Name",
	"Node Addresses",
	"IPv4 Addresses ",
};

static const char *icmpv6_type_139_codes[] = {
	"Data contains IPv6 Address",
	"Data contains Name or nothing",
	"Data contains IPv4 Address",
};

static int8_t dissect_icmpv6_type139(struct pkt_buff *pkt)
{
	const char *qtype_name = "Unknown";
	uint16_t qtype_nr;
	struct icmpv6_type_139_140 *icmp_139;

	icmp_139 = (struct icmpv6_type_139_140 *)
		      pkt_pull(pkt,sizeof(*icmp_139));
	if (icmp_139 == NULL)
		return 0;

	qtype_nr = ntohs(icmp_139->qtype);
	if (icmpv6_code_range_valid(qtype_nr, icmpv6_node_inf_qtypes))
			qtype_name = icmpv6_node_inf_qtypes[qtype_nr];

	tprintf(", Qtype %s (%u)", qtype_name, qtype_nr);
	tprintf(", Flags (0x%x)", ntohs(icmp_139->flags));
	tprintf(", Nonce (0x%"PRIx64")", ntohll(icmp_139->nonce));

	dissect_icmpv6_node_inf_data(pkt);

	return 1;
}

static char *icmpv6_type_140_codes[] = {
	"Successfull reply",
	"Responder refuses answer",
	"Qtype is unknown to the Responder",
};

static inline int8_t dissect_icmpv6_type140(struct pkt_buff *pkt)
{
	return dissect_icmpv6_type139(pkt);
}

static inline int8_t dissect_icmpv6_type141(struct pkt_buff *pkt)
{
	return dissect_icmpv6_type133(pkt);
}

static inline int8_t dissect_icmpv6_type142(struct pkt_buff *pkt)
{
	return dissect_icmpv6_type133(pkt);
}

static int8_t dissect_icmpv6_type143(struct pkt_buff *pkt)
{
	uint16_t nr_rec;
	struct icmpv6_type_143 *icmp_143;

	icmp_143 = (struct icmpv6_type_143 *)
		      pkt_pull(pkt,sizeof(*icmp_143));
	if (icmp_143 == NULL)
		return 0;
	nr_rec = ntohs(icmp_143->nr_rec);
	
	tprintf(", Res (0x%x)",ntohs(icmp_143->res));
	tprintf(", Nr. Mcast Addr Records (%u)",nr_rec);

	return dissect_icmpv6_mcast_rec(pkt, nr_rec);
}

static int8_t dissect_icmpv6_type144(struct pkt_buff *pkt)
{
	struct icmpv6_type_144_146 *icmp_144;

	icmp_144 = (struct icmpv6_type_144_146 *)
		      pkt_pull(pkt,sizeof(*icmp_144));
	if (icmp_144 == NULL)
		return 0;

	tprintf(", ID (%u)",ntohs(icmp_144->id));
	tprintf(", Res (0x%x)",ntohs(icmp_144->res));

	return 1;
}

static int8_t dissect_icmpv6_type145(struct pkt_buff *pkt)
{
	struct icmpv6_type_145 *icmp_145;

	icmp_145 = (struct icmpv6_type_145 *)
		      pkt_pull(pkt,sizeof(*icmp_145));
	if (icmp_145 == NULL)
		return 0;

	tprintf(", ID (%u)",ntohs(icmp_145->id));
	tprintf(", Res (0x%x)",ntohs(icmp_145->res));

	return print_ipv6_addr_list(pkt, pkt_len(pkt) /
					sizeof(struct in6_addr));
}

static inline int8_t dissect_icmpv6_type146(struct pkt_buff *pkt)
{
	return dissect_icmpv6_type144(pkt);
}

static int8_t dissect_icmpv6_type147(struct pkt_buff *pkt)
{
	uint16_t m_o_res;
	struct icmpv6_type_147 *icmp_147;

	icmp_147 = (struct icmpv6_type_147 *)
		      pkt_pull(pkt,sizeof(*icmp_147));
	if (icmp_147 == NULL)
		return 0;
	m_o_res = ntohs(icmp_147->m_o_res);

	tprintf(", ID (%u)",ntohs(icmp_147->id));
	tprintf(", M (%u) O (%u) Res (0x%x)",m_o_res >> 15,
		      (m_o_res >> 14) & 1, m_o_res & 0x3FFF);

	return dissect_neighb_disc_ops(pkt);
}

static int8_t dissect_icmpv6_type148(struct pkt_buff *pkt)
{
	struct icmpv6_type_148 *icmp_148;

	icmp_148 = (struct icmpv6_type_148 *)
		      pkt_pull(pkt,sizeof(*icmp_148));
	if (icmp_148 == NULL)
		return 0;

	tprintf(", ID (%u)",ntohs(icmp_148->id));
	tprintf(", Component (%u)",ntohs(icmp_148->comp));

	return dissect_neighb_disc_ops(pkt);
}

static int8_t dissect_icmpv6_type149(struct pkt_buff *pkt)
{
	struct icmpv6_type_149 *icmp_149;

	icmp_149 = (struct icmpv6_type_149 *)
		      pkt_pull(pkt,sizeof(*icmp_149));
	if (icmp_149 == NULL)
		return 0;

	tprintf(", ID (%u)",ntohs(icmp_149->id));
	tprintf(", All Components (%u)",ntohs(icmp_149->all_comp));
	tprintf(", Component (%u)",ntohs(icmp_149->comp));
	tprintf(", Res (0x%x)",ntohs(icmp_149->res));

	return dissect_neighb_disc_ops(pkt);
}

static int8_t dissect_icmpv6_type150(struct pkt_buff *pkt)
{
	struct icmpv6_type_150 *icmp_150;

	icmp_150 = (struct icmpv6_type_150 *)
		      pkt_pull(pkt,sizeof(*icmp_150));
	if (icmp_150 == NULL)
		return 0;

	tprintf(", Subtype (%u)",icmp_150->subtype);
	tprintf(", Res (0x%x)",icmp_150->res);
	tprintf(", Options in Payload");

	return 1;
}

static int8_t dissect_icmpv6_type151(struct pkt_buff *pkt)
{
	struct icmpv6_type_151 *icmp_151;

	icmp_151 = (struct icmpv6_type_151 *)
		      pkt_pull(pkt,sizeof(*icmp_151));
	if (icmp_151 == NULL)
		return 0;

	tprintf(", Query Interval (%us)",ntohs(icmp_151->query_intv));
	tprintf(", Robustness Variable  (%u)",ntohs(icmp_151->rob_var));

	return 1;
}

static int8_t dissect_icmpv6_type152(struct pkt_buff *pkt)
{
	struct icmpv6_type_152 *icmp_152;

	icmp_152 = (struct icmpv6_type_152 *)
		      pkt_pull(pkt,sizeof(*icmp_152));
	if (icmp_152 == NULL)
		return 0;

	return 1;
}

static int8_t dissect_icmpv6_type153(struct pkt_buff *pkt)
{
	struct icmpv6_type_153 *icmp_153;

	icmp_153 = (struct icmpv6_type_153 *)
		      pkt_pull(pkt,sizeof(*icmp_153));
	if (icmp_153 == NULL)
		return 0;

	return 1;
}

static int8_t dissect_icmpv6_type154(struct pkt_buff *pkt)
{
	struct icmpv6_type_154 *icmp_154;

	icmp_154 = (struct icmpv6_type_154 *)
		      pkt_pull(pkt,sizeof(*icmp_154));
	if (icmp_154 == NULL)
		return 0;

	tprintf(", Subtype (%u)",icmp_154->subtype);
	tprintf(", Res (0x%x)",icmp_154->res);
	tprintf(", ID (%u)",ntohs(icmp_154->id));

	return dissect_neighb_disc_ops(pkt);
}

static inline char *icmpv6_type_155_codes(uint8_t code) {
	switch (code) {
	case 0x00: return "DODAG Information Solicitation";
	case 0x01: return "DODAG Information Object";
	case 0x02: return "Destination Advertisement Object";
	case 0x03: return "Destination Advertisement Object Acknowledgment";
	case 0x80: return "Secure DODAG Information Solicitation";
	case 0x81: return "Secure DODAG Information Object";
	case 0x82: return "Secure Destination Advertisement Object";
	case 0x83: return "Secure Destination Advertisement Object Acknowledgment";
	case 0x8A: return "Consistency Check";
	}

	return NULL;
};

static void icmpv6_process(struct icmpv6_general_hdr *icmp, const char **type,
			   const char **code, int8_t (**optional)(struct pkt_buff *pkt))
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
		*optional = dissect_icmpv6_type141;
		return;
	case 142:
		*type = "Inverse Neighbor Discovery Advertisement Message";
		*optional = dissect_icmpv6_type142;
		return;
	case 143:
		*type = "Multicast Listener Report v2";
		*optional = dissect_icmpv6_type143;
		return;
	case 144:
		*type = "Home Agent Address Discovery Request Message";
		*optional = dissect_icmpv6_type144;
		return;
	case 145:
		*type = "Home Agent Address Discovery Reply Message";
		*optional = dissect_icmpv6_type145;
		return;
	case 146:
		*type = "Mobile Prefix Solicitation";
		*optional = dissect_icmpv6_type146;
		return;
	case 147:
		*type = "Mobile Prefix Advertisement";
		*optional = dissect_icmpv6_type147;
		return;
	case 148:
		*type = "Certification Path Solicitation";
		*optional = dissect_icmpv6_type148;
		return;
	case 149:
		*type = "Certification Path Advertisement";
		*optional = dissect_icmpv6_type149;
		return;
	case 150:
		*type = "ICMP messages utilized by experimental mobility "
			"protocols such as Seamoby";
		*optional = dissect_icmpv6_type150;
		return;
	case 151:
		*type = "Multicast Router Advertisement";
		*code = "Ad. Interval";
		*optional = dissect_icmpv6_type151;
		return;
	case 152:
		*type = "Multicast Router Solicitation";
		*code = "Reserved";
		*optional = dissect_icmpv6_type152;
		return;
	case 153:
		*type = "Multicast Router Termination";
		*code = "Reserved";
		*optional = dissect_icmpv6_type153;
		return;
	case 154:
		*type = "FMIPv6 Messages";
		*optional = dissect_icmpv6_type154;
		return;
	case 155:
		*type = "RPL Control Message";
		if(icmpv6_type_155_codes(icmp->h_code))
			*code = icmpv6_type_155_codes(icmp->h_code);
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

static void icmpv6(struct pkt_buff *pkt)
{
	const char *type = NULL, *code = NULL;
	int8_t (*optional)(struct pkt_buff *pkt) = NULL;
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
		if (!((*optional) (pkt)))
		      tprintf("\n%s%s%s", colorize_start_full(black, red),
			    "Failed to dissect Message", colorize_end());
	tprintf(" ]\n");
}

static void icmpv6_less(struct pkt_buff *pkt)
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

/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012, 2013 Tobias Klauser <tklauser@distanz.ch>
 * Subject to the GPL, version 2.
 */

#include <stdint.h>
#include <arpa/inet.h>		/* for inet_ntop() */
#include <netinet/in.h>		/* for ntohs()/ntohl() */

#include "built_in.h"
#include "oui.h"
#include "pkt_buff.h"
#include "proto.h"
#include "protos.h"

#define EXTRACT_16BIT(x)	ntohs(*((uint16_t *) (x)))
#define EXTRACT_32BIT(x)	ntohl(*((uint32_t *) (x)))

#define LLDP_TLV_TYPE(tlv)	(((tlv) & 0xFE00) >> 9)
#define LLDP_TLV_LENGTH(tlv)	 ((tlv) & 0x01FF)

/*
 * LLDP TLV types
 */
#define LLDP_TLV_END			0
#define LLDP_TLV_CHASSIS_ID		1
#define LLDP_TLV_PORT_ID		2
#define LLDP_TLV_TTL			3
#define LLDP_TLV_PORT_DESC		4
#define LLDP_TLV_SYSTEM_NAME		5
#define LLDP_TLV_SYSTEM_DESC		6
#define LLDP_TLV_SYSTEM_CAP		7
#define LLDP_TLV_MGMT_ADDR		8
#define LLDP_TLV_ORG_SPECIFIC		127

/*
 * Chassis ID subtypes
 */
#define LLDP_CHASSIS_SUBTYPE_CHASSIS	1
#define LLDP_CHASSIS_SUBTYPE_IF_ALIAS	2
#define LLDP_CHASSIS_SUBTYPE_PORT	3
#define LLDP_CHASSIS_SUBTYPE_MAC_ADDR	4
#define LLDP_CHASSIS_SUBTYPE_NET_ADDR	5
#define LLDP_CHASSIS_SUBTYPE_IF_NAME	6
#define LLDP_CHASSIS_SUBTYPE_LOCAL	7

/*
 * Port ID subtypes
 */
#define LLDP_PORT_SUBTYPE_IF_ALIAS	1
#define LLDP_PORT_SUBTYPE_PORT_COMP	2
#define LLDP_PORT_SUBTYPE_MAC_ADDR	3
#define LLDP_PORT_SUBTYPE_NET_ADDR	4
#define LLDP_PORT_SUBTYPE_IF_NAME	5
#define LLDP_PORT_SUBTYPE_AGENT_CIRC_ID	6
#define LLDP_PORT_SUBTYPE_LOCAL		7

/*
 * System capabilits bit masks
 */
#define LLDP_SYSTEM_CAP_OTHER		(1 << 0)
#define LLDP_SYSTEM_CAP_REPEATER	(1 << 1)
#define LLDP_SYSTEM_CAP_BRIDGE		(1 << 2)
#define LLDP_SYSTEM_CAP_WLAN_AP		(1 << 3)
#define LLDP_SYSTEM_CAP_ROUTER		(1 << 4)
#define LLDP_SYSTEM_CAP_TELEPHONE	(1 << 5)
#define LLDP_SYSTEM_CAP_DOCSIS		(1 << 6)
#define LLDP_SYSTEM_CAP_STATION_ONLY	(1 << 7)

/*
 * Interface number subtypes (for Management addres TLV)
 */
#define LLDP_IFACE_NUM_SUBTYPE_UNKNOWN	1
#define LLDP_IFACE_NUM_SUBTYPE_IF_INDEX	2
#define LLDP_IFACE_NUM_SUBTYPE_SYS_PORT	3

/*
 * IANA address family numbers (only the ones we actually use)
 * http://www.iana.org/assignments/address-family-numbers/address-family-numbers.txt
 *
 * TODO: Move these into own header if there are other users?
 */
#define IANA_AF_IPV4	1
#define IANA_AF_IPV6	2
#define IANA_AF_802	6

static int lldp_print_net_addr(const uint8_t *addr, size_t addrlen)
{
	uint8_t af;
	char buf[64];

	if (addrlen < 1)
		return -EINVAL;

	af = *addr++;
	addrlen--;
	switch (af) {
	case IANA_AF_IPV4:
		if (addrlen < 4)
			return -EINVAL;
		inet_ntop(AF_INET, addr, buf, sizeof(buf));
		tprintf("%s", buf);
		break;
	case IANA_AF_IPV6:
		if (addrlen < 16)
			return -EINVAL;
		inet_ntop(AF_INET6, addr, buf, sizeof(buf));
		tprintf("%s", buf);
		break;
	case IANA_AF_802:
		if (addrlen < 6)
			return -EINVAL;
		tprintf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
			addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
		break;
	default:
		tprintf("unknown address family");
		break;
	}

	return 0;
}

static inline void lldp_print_cap_one(const char *cap, unsigned int *prev)
{
	tprintf("%s%s", *prev ? ", " : "", cap);
	(*prev)++;
}

static void lldp_print_cap(uint16_t cap)
{
	unsigned int prev = 0;

	if (cap & LLDP_SYSTEM_CAP_OTHER)
		lldp_print_cap_one("Other", &prev);
	if (cap & LLDP_SYSTEM_CAP_REPEATER)
		lldp_print_cap_one("Repeater", &prev);
	if (cap & LLDP_SYSTEM_CAP_BRIDGE)
		lldp_print_cap_one("Bridge", &prev);
	if (cap & LLDP_SYSTEM_CAP_WLAN_AP)
		lldp_print_cap_one("WLAN AP", &prev);
	if (cap & LLDP_SYSTEM_CAP_ROUTER)
		lldp_print_cap_one("Router", &prev);
	if (cap & LLDP_SYSTEM_CAP_TELEPHONE)
		lldp_print_cap_one("Telephone", &prev);
	if (cap & LLDP_SYSTEM_CAP_DOCSIS)
		lldp_print_cap_one("DOCSIS", &prev);
	if (cap & LLDP_SYSTEM_CAP_STATION_ONLY)
		lldp_print_cap_one("Station only", &prev);
}

static void lldp(struct pkt_buff *pkt)
{
	unsigned int n_tlv = 0;
	uint8_t subtype, mgmt_alen, mgmt_oidlen;
	uint16_t tlv_hdr;
	unsigned int tlv_type, tlv_len;
	unsigned int len;
	uint8_t *tlv_info_str;
	uint16_t sys_cap, en_cap;
	uint32_t oui;

	len = pkt_len(pkt);
	if (len == 0)
		return;

	tprintf(" [ LLDP ");

	while (len >= sizeof(tlv_hdr)) {
		uint8_t *data = pkt_pull(pkt, sizeof(tlv_hdr));
		if (data == NULL)
			goto out_invalid;

		tlv_hdr = EXTRACT_16BIT(data);
		tlv_type = LLDP_TLV_TYPE(tlv_hdr);
		tlv_len = LLDP_TLV_LENGTH(tlv_hdr);

		len -= sizeof(tlv_hdr);

		if (tlv_type == LLDP_TLV_END && tlv_len == 0) {
			/* Chassis ID, Port ID and TTL are mandatory */
			if (n_tlv < 3)
				goto out_invalid;
			else
				break;
		}
		if (len < tlv_len)
			goto out_invalid;

		switch (tlv_type) {
		case LLDP_TLV_CHASSIS_ID:
			/*
			 * The mandatory chassis ID shall be the first TLV and
			 * shall appear exactly once.
			 */
			if (n_tlv != 0)
				goto out_invalid;

			tprintf("Chassis ID");

			if (tlv_len < 2)
				goto out_invalid;

			tlv_info_str = pkt_pull(pkt, tlv_len);
			if (tlv_info_str == NULL)
				goto out_invalid;

			subtype = *tlv_info_str++;
			tprintf(" (Subtype %u => ", subtype);

			switch (subtype) {
			case LLDP_CHASSIS_SUBTYPE_MAC_ADDR:
				if (tlv_len < 7)
					goto out_invalid;

				tprintf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
					tlv_info_str[0], tlv_info_str[1],
					tlv_info_str[2], tlv_info_str[3],
					tlv_info_str[4], tlv_info_str[5]);
				break;
			case LLDP_CHASSIS_SUBTYPE_NET_ADDR:
				if (lldp_print_net_addr(tlv_info_str, tlv_len))
					goto out_invalid;
				break;
			case LLDP_CHASSIS_SUBTYPE_CHASSIS:
			case LLDP_CHASSIS_SUBTYPE_IF_ALIAS:
			case LLDP_CHASSIS_SUBTYPE_PORT:
			case LLDP_CHASSIS_SUBTYPE_IF_NAME:
			case LLDP_CHASSIS_SUBTYPE_LOCAL:
				tputs_safe((const char *) tlv_info_str, tlv_len - 1);
				break;
			default:
				tprintf("Reserved");
				break;
			}

			tprintf(")");
			break;
		case LLDP_TLV_PORT_ID:
			/*
			 * The mandatory port ID shall be the second TLV and
			 * shall appear exactly once.
			 */
			if (n_tlv != 1)
				goto out_invalid;

			tprintf(", Port ID");

			if (tlv_len < 2)
				goto out_invalid;

			tlv_info_str = pkt_pull(pkt, tlv_len);
			if (tlv_info_str == NULL)
				goto out_invalid;

			subtype = *tlv_info_str++;
			tprintf(" (Subtype %u => ", subtype);

			switch (subtype) {
			case LLDP_PORT_SUBTYPE_MAC_ADDR:
				if (tlv_len < 7)
					goto out_invalid;

				tprintf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
					tlv_info_str[0], tlv_info_str[1],
					tlv_info_str[2], tlv_info_str[3],
					tlv_info_str[4], tlv_info_str[5]);
				break;
			case LLDP_PORT_SUBTYPE_NET_ADDR:
				if (lldp_print_net_addr(tlv_info_str, tlv_len))
					goto out_invalid;
				break;
			case LLDP_PORT_SUBTYPE_IF_ALIAS:
			case LLDP_PORT_SUBTYPE_PORT_COMP:
			case LLDP_PORT_SUBTYPE_IF_NAME:
			case LLDP_PORT_SUBTYPE_AGENT_CIRC_ID:
			case LLDP_PORT_SUBTYPE_LOCAL:
				tputs_safe((const char *) tlv_info_str, tlv_len - 1);
				break;
			default:
				tprintf("Reserved");
				break;
			}

			tprintf(")");
			break;
		case LLDP_TLV_TTL:
			/*
			 * The mandatory TTL shall be the third TLV and
			 * shall appear exactly once.
			 */
			if (n_tlv != 2)
				goto out_invalid;

			tprintf(", TTL");

			if (tlv_len != 2)
				goto out_invalid;

			tlv_info_str = pkt_pull(pkt, tlv_len);
			if (tlv_info_str == NULL)
				goto out_invalid;

			tprintf(" (%u)", EXTRACT_16BIT(tlv_info_str));
			break;
		case LLDP_TLV_PORT_DESC:
			tprintf(", Port desc (");

			tlv_info_str = pkt_pull(pkt, tlv_len);
			if (tlv_info_str == NULL)
				tprintf("none");
			else
				tputs_safe((const char *) tlv_info_str, tlv_len);

			tprintf(")");
			break;
		case LLDP_TLV_SYSTEM_NAME:
			tprintf(", Sys name (");

			tlv_info_str = pkt_pull(pkt, tlv_len);
			if (tlv_info_str == NULL)
				tprintf("none");
			else
				tputs_safe((const char *) tlv_info_str, tlv_len);

			tprintf(")");
			break;
		case LLDP_TLV_SYSTEM_DESC:
			tprintf(", Sys desc (");

			tlv_info_str = pkt_pull(pkt, tlv_len);
			if (tlv_info_str == NULL)
				tprintf("none");
			else
				tputs_safe((const char *) tlv_info_str, tlv_len);

			tprintf(")");
			break;
		case LLDP_TLV_SYSTEM_CAP:
			tprintf(", Sys Cap");

			if (tlv_len != 4)
				goto out_invalid;

			tlv_info_str = pkt_pull(pkt, tlv_len);
			if (tlv_info_str == NULL)
				goto out_invalid;

			sys_cap = EXTRACT_16BIT(tlv_info_str);
			tlv_info_str += sizeof(uint32_t);
			en_cap = EXTRACT_16BIT(tlv_info_str);

			tprintf(" (");
			lldp_print_cap(sys_cap);
			tprintf(")");
			tprintf(" Ena Cap (");
			lldp_print_cap(en_cap);
			tprintf(")");
			break;
		case LLDP_TLV_MGMT_ADDR:
			tprintf(", Mgmt Addr (");

			if (tlv_len < 9 || tlv_len > 167)
				goto out_invalid;

			tlv_info_str = pkt_pull(pkt, tlv_len);
			if (tlv_info_str == NULL)
				goto out_invalid;

			mgmt_alen = *tlv_info_str;
			tlv_info_str++;
			if (tlv_len - 1 < mgmt_alen)
				goto out_invalid;

			if (lldp_print_net_addr(tlv_info_str, mgmt_alen))
				goto out_invalid;
			tlv_info_str += mgmt_alen;

			tprintf(", Iface Subtype %d/", *tlv_info_str);
			switch (*tlv_info_str) {
			case LLDP_IFACE_NUM_SUBTYPE_IF_INDEX:
				tprintf("ifIndex");
				break;
			case LLDP_IFACE_NUM_SUBTYPE_SYS_PORT:
				tprintf("System Port Number");
				break;
			default:
				tprintf("Unknown");
				break;
			}

			tlv_info_str++;
			tprintf(", Iface Number %u", EXTRACT_32BIT(tlv_info_str));

			tlv_info_str += 4;
			mgmt_oidlen = *tlv_info_str;
			if (tlv_len - mgmt_alen - sizeof(uint32_t) - 3 < mgmt_oidlen)
				goto out_invalid;
			if (mgmt_oidlen > 0) {
				tprintf(", OID ");
				tputs_safe((const char *) tlv_info_str + 1, mgmt_oidlen);
			}

			tprintf(")");
			break;
		case LLDP_TLV_ORG_SPECIFIC:
			tprintf(", Org specific");

			if (tlv_len < 4)
				goto out_invalid;

			tlv_info_str = pkt_pull(pkt, 4);
			if (tlv_info_str == NULL)
				goto out_invalid;

			oui = ntohl(*((uint32_t *) tlv_info_str));
			subtype = oui & 0xff;
			oui >>= 8;
			tprintf(" (OUI %s, Subtype %u)", lookup_vendor_str(oui),
				subtype);

			/* Just eat it up, we don't know how to interpret it */
			pkt_pull(pkt, tlv_len - 4);
			break;
		default:
			tprintf(", Unknown TLV %u", tlv_type);
			pkt_pull(pkt, tlv_len);
			break;
		}

		n_tlv++;
	}

	len -= tlv_len;

	tprintf(" ]\n");
	return;

out_invalid:
	tprintf(" %sINVALID%s ]\n", colorize_start_full(black, red),
		colorize_end());
}

static void lldp_less(struct pkt_buff *pkt)
{
	unsigned int len, n_tlv = 0;
	unsigned int tlv_type, tlv_len;
	uint16_t tlv_hdr;

	len = pkt_len(pkt);

	while (len >= sizeof(tlv_hdr)) {
		uint8_t *data = pkt_pull(pkt, sizeof(tlv_hdr));
		if (data == NULL)
			break;

		tlv_hdr = EXTRACT_16BIT(data);
		tlv_type = LLDP_TLV_TYPE(tlv_hdr);
		tlv_len = LLDP_TLV_LENGTH(tlv_hdr);

		n_tlv++;
		len -= sizeof(tlv_hdr);

		if (tlv_type == LLDP_TLV_END || tlv_len == 0)
			break;
		if (len < tlv_len)
			break;

		pkt_pull(pkt, tlv_len);

		len -= tlv_len;
	}

	tprintf(" %u TLV%s", n_tlv, n_tlv == 1 ? "" : "s");
}

struct protocol lldp_ops = {
	.key = 0x88cc,
	.print_full = lldp,
	.print_less = lldp_less,
};

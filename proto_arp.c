/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>    /* for ntohs() */
#include <linux/if_ether.h>

#include "proto.h"
#include "protos.h"
#include "lookup.h"
#include "pkt_buff.h"
#include "built_in.h"

struct arphdr {
	uint16_t ar_hrd;   /* format of hardware address */
	uint16_t ar_pro;   /* format of protocol address */
	uint8_t ar_hln;    /* length of hardware address */
	uint8_t ar_pln;    /* length of protocol address */
	uint16_t ar_op;    /* ARP opcode (command)       */
	uint8_t ar_sha[6]; /* sender hardware address    */
	uint8_t ar_sip[4]; /* sender IP address          */
	uint8_t ar_tha[6]; /* target hardware address    */
	uint8_t ar_tip[4]; /* target IP address          */
} __packed;

#define ARPHRD_ETHER	1
#define ARPHRD_IEEE802	6
#define ARPHRD_ARCNET	7
#define ARPHRD_ATM	16
#define ARPHRD_ATM2	19
#define ARPHRD_SERIAL	20
#define ARPHRD_ATM3	21
#define ARPHRD_IEEE1394	24

#define ARPOP_REQUEST   1  /* ARP request                */
#define ARPOP_REPLY     2  /* ARP reply                  */
#define ARPOP_RREQUEST  3  /* RARP request               */
#define ARPOP_RREPLY    4  /* RARP reply                 */
#define ARPOP_InREQUEST 8  /* InARP request              */
#define ARPOP_InREPLY   9  /* InARP reply                */
#define ARPOP_NAK       10 /* (ATM)ARP NAK               */

enum addr_direct {
	ADDR_SENDER,
	ADDR_TARGET,
};

static void arp_print_addrs(struct arphdr *arp, enum addr_direct addr_dir)
{
	const char *dir = addr_dir == ADDR_SENDER ? "Sender" : "Target";

	if (ntohs(arp->ar_hrd) == ARPHRD_ETHER) {
		uint8_t *mac;

		mac = addr_dir == ADDR_SENDER ? &arp->ar_sha[0] : &arp->ar_tha[0];

		tprintf(", %s MAC (%.2x:%.2x:%.2x:%.2x:%.2x:%.2x)",
			 dir, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}

	if (ntohs(arp->ar_pro) == ETH_P_IP) {
		char ip_str[INET_ADDRSTRLEN];
		uint32_t ip;

		if (addr_dir == ADDR_SENDER)
			ip = *(uint32_t *)&arp->ar_sip[0];
		else
			ip = *(uint32_t *)&arp->ar_tip[0];

		inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));

		tprintf(", %s IP (%s)", dir, ip_str);
	}
}

static void arp(struct pkt_buff *pkt)
{
	char *hrd;
	const char *pro;
	char *opcode;
	struct arphdr *arp = (struct arphdr *) pkt_pull(pkt, sizeof(*arp));

	if (arp == NULL)
		return;

	switch (ntohs(arp->ar_hrd)) {
	case ARPHRD_ETHER:
		hrd = "Ethernet";
		break;
	case ARPHRD_IEEE802:
		hrd = "IEEE 802";
		break;
	case ARPHRD_ARCNET:
		hrd = "ARCNET";
		break;
	case ARPHRD_ATM:
	case ARPHRD_ATM2:
	case ARPHRD_ATM3:
		hrd = "ATM";
		break;
	case ARPHRD_SERIAL:
		hrd = "Serial Line";
		break;
	case ARPHRD_IEEE1394:
		hrd = "IEEE 1394.1995";
		break;
	default:
		hrd = "Unknown";
		break;
	}

	pro = lookup_ether_type(ntohs(arp->ar_pro));
	if (pro == NULL)
		pro = "Unknown";

	switch (ntohs(arp->ar_op)) {
	case ARPOP_REQUEST:
		opcode = "ARP request";
		break;
	case ARPOP_REPLY:
		opcode = "ARP reply";
		break;
	case ARPOP_RREQUEST:
		opcode = "RARP request";
		break;
	case ARPOP_RREPLY:
		opcode = "RARP reply";
		break;
	case ARPOP_InREQUEST:
		opcode = "InARP request";
		break;
	case ARPOP_InREPLY:
		opcode = "InARP reply";
		break;
	case ARPOP_NAK:
		opcode = "(ATM) ARP NAK";
		break;
	default:
		opcode = "Unknown";
		break;
	};

	tprintf(" [ ARP ");
	tprintf("Format HA (%u => %s), ", ntohs(arp->ar_hrd), hrd);
	tprintf("Format Proto (0x%.4x => %s), ", ntohs(arp->ar_pro), pro);
	tprintf("HA Len (%u), ", arp->ar_hln);
	tprintf("Proto Len (%u), ", arp->ar_pln);
	tprintf("Opcode (%u => %s)", ntohs(arp->ar_op), opcode);

	arp_print_addrs(arp, ADDR_SENDER);
	arp_print_addrs(arp, ADDR_TARGET);

	tprintf(" ]\n");
}

static void arp_less(struct pkt_buff *pkt)
{
	char *opcode = NULL;
	struct arphdr *arp = (struct arphdr *) pkt_pull(pkt, sizeof(*arp));

	if (arp == NULL)
		return;

	switch (ntohs(arp->ar_op)) {
	case ARPOP_REQUEST:
		opcode = "ARP request";
		break;
	case ARPOP_REPLY:
		opcode = "ARP reply";
		break;
	case ARPOP_RREQUEST:
		opcode = "RARP request";
		break;
	case ARPOP_RREPLY:
		opcode = "RARP reply";
		break;
	case ARPOP_InREQUEST:
		opcode = "InARP request";
		break;
	case ARPOP_InREPLY:
		opcode = "InARP reply";
		break;
	case ARPOP_NAK:
		opcode = "(ATM) ARP NAK";
		break;
	default:
		opcode = "Unknown";
		break;
	};

	tprintf(" Op %s", opcode);
}

struct protocol arp_ops = {
	.key = 0x0806,
	.print_full = arp,
	.print_less = arp_less,
};

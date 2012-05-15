/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdint.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto.h"
#include "protos.h"
#include "dissector_eth.h"
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

#define ARPOP_REQUEST   1  /* ARP request                */
#define ARPOP_REPLY     2  /* ARP reply                  */
#define ARPOP_RREQUEST  3  /* RARP request               */
#define ARPOP_RREPLY    4  /* RARP reply                 */
#define ARPOP_InREQUEST 8  /* InARP request              */
#define ARPOP_InREPLY   9  /* InARP reply                */
#define ARPOP_NAK       10 /* (ATM)ARP NAK               */

static void arp(struct pkt_buff *pkt)
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

	tprintf(" [ ARP ");
	tprintf("Format HA (%u), ", ntohs(arp->ar_hrd));
	tprintf("Format Proto (%u), ", ntohs(arp->ar_pro));
	tprintf("HA Len (%u), ", ntohs(arp->ar_hln));
	tprintf("Proto Len (%u), ", ntohs(arp->ar_pln));
	tprintf("Opcode (%u => %s)", ntohs(arp->ar_op), opcode);
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

EXPORT_SYMBOL(arp_ops);

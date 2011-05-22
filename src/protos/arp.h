/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto_struct.h"
#include "dissector_eth.h"

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
} __attribute__((packed));

#define ARPOP_REQUEST   1  /* ARP request                */
#define ARPOP_REPLY     2  /* ARP reply                  */
#define ARPOP_RREQUEST  3  /* RARP request               */
#define ARPOP_RREPLY    4  /* RARP reply                 */
#define ARPOP_InREQUEST 8  /* InARP request              */
#define ARPOP_InREPLY   9  /* InARP reply                */
#define ARPOP_NAK       10 /* (ATM)ARP NAK               */

static inline void arp(uint8_t *packet, size_t len)
{
	char *opcode = NULL;
	struct arphdr *arp = (struct arphdr *) packet;

	if (len < sizeof(struct arphdr))
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

static inline void arp_less(uint8_t *packet, size_t len)
{
	char *opcode = NULL;
	struct arphdr *arp = (struct arphdr *) packet;

	if (len < sizeof(struct arphdr))
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

	tprintf(" ARP Op %s", opcode);
}

struct protocol arp_ops = {
	.key = 0x0806,
	.print_full = arp,
	.print_less = arp_less,
	.print_pay_ascii = empty,
	.print_pay_hex = empty,
	.print_pay_none = arp,
	.print_all_cstyle = NULL,
	.print_all_hex = NULL,
	.proto_next = NULL,
};

#endif /* ARP_H */

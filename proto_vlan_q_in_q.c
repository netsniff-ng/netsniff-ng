/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2012 Markus Amend <markus@netsniff-ng.org>, Deutsche Flugsicherung GmbH
 * Subject to the GPL, version 2.
 *
 * http://www.ieee802.org/1/pages/802.1ad.html
 */

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto.h"
#include "dissector_eth.h"
#include "built_in.h"
#include "pkt_buff.h"

struct QinQhdr {
	uint16_t TCI;
	uint16_t TPID;
} __packed;

static void QinQ_full(struct pkt_buff *pkt)
{
	uint16_t tci;
	struct QinQhdr *QinQ = (struct QinQhdr *) pkt_pull(pkt, sizeof(*QinQ));

	if (QinQ == NULL)
		return;

	tci = ntohs(QinQ->TCI);

	tprintf(" [ VLAN QinQ ");
	tprintf("Prio (%d), ", (tci & 0xE000) >> 13);
	tprintf("DEI (%d), ", (tci & 0x1000) >> 12);
	tprintf("ID (%d), ", (tci & 0x0FFF));
	tprintf("Proto (0x%.4x)", ntohs(QinQ->TPID));
	tprintf(" ]\n");

	pkt_set_proto(pkt, &eth_lay2, ntohs(QinQ->TPID));
}

static void QinQ_less(struct pkt_buff *pkt)
{
	uint16_t tci;
	struct QinQhdr *QinQ = (struct QinQhdr *) pkt_pull(pkt, sizeof(*QinQ));

	if (QinQ == NULL)
		return;

	tci = ntohs(QinQ->TCI);

	tprintf(" VLAN%d", (tci & 0x0FFF));

	pkt_set_proto(pkt, &eth_lay2, ntohs(QinQ->TPID));
}

struct protocol QinQ_ops = {
	.key = 0x88a8,
	.print_full = QinQ_full,
	.print_less = QinQ_less,
};

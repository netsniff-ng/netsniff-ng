/*
 * This file is part of netsniff-ng - the packet sniffing beast.
 * Copyright (C) 2012 Christoph Jaeger <christoph@netsniff-ng.org>
 * Subject to the GPL, version 2.
 */

#ifndef PKT_BUFF_H
#define PKT_BUFF_H

#include <assert.h>
#include <stdlib.h>

#include "hash.h"
#include "proto_struct.h"
#include "xmalloc.h"

struct pkt_buff {
	/* invariant: head <= data <= tail */
	uint8_t      *head;
	uint8_t      *data;
	uint8_t      *tail;
	unsigned int  size;

	struct protocol *proto;
};

static struct pkt_buff *pkt_alloc(uint8_t *packet, unsigned int len)
{
	struct pkt_buff *pkt = xmalloc(sizeof(*pkt));

	pkt->head = packet;
	pkt->data = packet;
	pkt->tail = packet + len;
	pkt->size = len;

	pkt->proto = NULL;

	return pkt;
}

static inline unsigned int pkt_len(struct pkt_buff *pkt)
{
	assert(pkt && pkt->data <= pkt->tail);
	return pkt->tail - pkt->data;
}

static uint8_t *pkt_pull_head(struct pkt_buff *pkt, unsigned int len)
{
	uint8_t *data = NULL;

	assert(pkt && pkt->head <= pkt->data && pkt->data <= pkt->tail);

	if (pkt_len(pkt) && pkt->data + len <= pkt->tail) {
		data = pkt->data;
		pkt->data += len;
	}
	return data;
}

static uint8_t *pkt_pull_tail(struct pkt_buff *pkt, unsigned int len)
{
	uint8_t *tail = NULL;

	assert(pkt && pkt->head <= pkt->data && pkt->data <= pkt->tail);

	if (pkt_len(pkt) && pkt->tail - len >= pkt->data) {
		tail = pkt->tail;
		pkt->tail -= len;
	}
	return tail;
}

static void pkt_set_proto(struct pkt_buff *pkt, struct hash_table *table,
			unsigned int key)
{
	assert(pkt && table);

	pkt->proto = (struct protocol *) lookup_hash(key, table);
	while (pkt->proto && key != pkt->proto->key)
		pkt->proto = pkt->proto->next;
}

#endif /* PKT_BUFF_H */

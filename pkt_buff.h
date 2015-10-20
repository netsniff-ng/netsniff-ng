/*
 * netsniff-ng - the packet sniffing beast
 * Copyright (C) 2012 Christoph Jaeger <christoph@netsniff-ng.org>
 * Subject to the GPL, version 2.
 */

#ifndef PKT_BUFF_H
#define PKT_BUFF_H

#include "hash.h"
#include "built_in.h"
#include "proto.h"
#include "xmalloc.h"

struct pkt_buff {
	/* invariant: head <= data <= tail */
	uint8_t *head;
	uint8_t *data;
	uint8_t *tail;

	struct protocol *dissector;
	uint32_t link_type;
	struct sockaddr_ll *sll;
};

static inline struct pkt_buff *pkt_alloc(uint8_t *packet, unsigned int len)
{
	struct pkt_buff *pkt = xmalloc(sizeof(*pkt));

	pkt->head = packet;
	pkt->data = packet;
	pkt->tail = packet + len;
	pkt->dissector = NULL;

	return pkt;
}

static inline void pkt_free(struct pkt_buff *pkt)
{
	xfree(pkt);
}

static inline unsigned int pkt_len(struct pkt_buff *pkt)
{
	bug_on(!pkt || pkt->data > pkt->tail);

	return pkt->tail - pkt->data;
}

static inline uint8_t *pkt_pull(struct pkt_buff *pkt, unsigned int len)
{
	uint8_t *data = NULL;

	bug_on(!pkt || pkt->head > pkt->data || pkt->data > pkt->tail);

	if (len <= pkt_len(pkt)) {
		data = pkt->data;
		pkt->data += len;
	}

	bug_on(!pkt || pkt->head > pkt->data || pkt->data > pkt->tail);

	return data;
}

static inline uint8_t *pkt_peek(struct pkt_buff *pkt)
{
	bug_on(!pkt || pkt->head > pkt->data || pkt->data > pkt->tail);

	return pkt->data;
}

static inline unsigned int pkt_trim(struct pkt_buff *pkt, unsigned int len)
{
	unsigned int ret = 0;

	bug_on(!pkt || pkt->head > pkt->data || pkt->data > pkt->tail);

	if (len <= pkt_len(pkt))
		ret = len;

	pkt->tail -= ret;
	bug_on(!pkt || pkt->head > pkt->data || pkt->data > pkt->tail);

	return ret;
}

static inline uint8_t *pkt_pull_tail(struct pkt_buff *pkt, unsigned int len)
{
	uint8_t *tail = NULL;

	bug_on(!pkt || pkt->head > pkt->data || pkt->data > pkt->tail);

	if (len <= pkt_len(pkt)) {
		tail = pkt->tail;
		pkt->tail -= len;
	}

	return tail;
}

static inline void pkt_set_dissector(struct pkt_buff *pkt, struct hash_table *table,
				     unsigned int key)
{
	bug_on(!pkt || !table);

	pkt->dissector = lookup_hash(key, table);
	while (pkt->dissector && key != pkt->dissector->key)
		pkt->dissector = pkt->dissector->next;
}

#endif /* PKT_BUFF_H */

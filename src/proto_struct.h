/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>.
 * Copyright (C) 2009, 2010 Daniel Borkmann
 * Copyright (C) 2012 Christoph Jaeger <christoph@netsniff-ng.org>
 * Subject to the GPL, version 2.
 */

#ifndef PROTO_H
#define PROTO_H

#include <stdint.h>

#include "hash.h"
#include "tprintf.h"

/* necessary forward declarations */
struct pkt_buff;
static inline unsigned int pkt_len(struct pkt_buff *pkt);
static uint8_t *pkt_pull_head(struct pkt_buff *pkt, unsigned int len);

struct protocol {
	/* Needs to be filled out by user */
	unsigned int key;
	void (*print_full)     (struct pkt_buff *pkt);
	void (*print_less)     (struct pkt_buff *pkt);
	void (*print_pay_ascii)(struct pkt_buff *pkt);
	void (*print_pay_hex)  (struct pkt_buff *pkt);
	void (*print_pay_none) (struct pkt_buff *pkt);
	void (*print_all_hex)  (struct pkt_buff *pkt);
	/* Used by program logic */
	struct protocol *next;
	void (*process)        (struct pkt_buff *pkt);
};

static inline void empty(struct pkt_buff *pkt) {}

static inline void hex(struct pkt_buff *pkt)
{
	uint8_t *buff;
	unsigned int len = pkt_len(pkt);

	for (buff = pkt_pull_head(pkt, len); buff && len-- > 0; buff++)
		tprintf("%.2x ", *buff);
}

#endif /* PROTO_H */

/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef PROTO_H
#define PROTO_H

#include <stdint.h>

#include "hash.h"
#include "tprintf.h"

struct protocol {
	/* Needs to be filled out by user */
	unsigned int key;
	void (*print_full)(uint8_t *packet, size_t len);
	void (*print_less)(uint8_t *packet, size_t len);
	void (*print_pay_ascii)(uint8_t *packet, size_t len);
	void (*print_pay_hex)(uint8_t *packet, size_t len);
	void (*print_pay_none)(uint8_t *packet, size_t len);
	void (*print_all_cstyle)(uint8_t *packet, size_t len);
	void (*print_all_hex)(uint8_t *packet, size_t len);
	/* Used by program logic */
	struct protocol *next;
	void (*process)(uint8_t *packet, size_t len);
	void (*proto_next)(uint8_t *packet, size_t len, 
			   struct hash_table **table,
			   unsigned int *key, size_t *off);
};

static inline void empty(uint8_t *packet, size_t len) { }

static inline void __hex(uint8_t *packet, size_t len)
{
	uint8_t *buff;
	for (buff = packet; len-- > 0; buff++)
		tprintf("%.2x ", *buff);
}

#endif /* PROTO_H */

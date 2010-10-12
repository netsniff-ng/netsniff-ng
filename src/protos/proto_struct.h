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

struct protocol {
	/* Needs to be filled out by user */
	unsigned int key;
	void (*print_full)(uint8_t *packet, size_t len);
	void (*print_less)(uint8_t *packet, size_t len);
	/* Used by program logic */
	struct protocol *next;
	void (*process)(uint8_t *packet, size_t len);
	void (*proto_next)(uint8_t *packet, size_t len, 
			   struct hash_table **table,
			   unsigned int *key, size_t *off);
};

#endif /* PROTO_H */

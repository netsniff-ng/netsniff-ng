/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef TRAFGEN_CONF
#define TRAFGEN_CONF

#include <stdint.h>
#include <stdio.h>

#define TYPE_INC	0
#define TYPE_DEC	1

struct counter {
	uint16_t id;
	uint8_t min;
	uint8_t max;
	uint8_t inc;
	uint8_t val;
	int type;
	off_t off;
};

struct randomizer {
	uint8_t val;
	off_t off;
};

struct packet {
	uint8_t *payload;
	size_t plen;
	struct counter *cnt;
	size_t clen;
	struct randomizer *rnd;
	size_t rlen;
};

struct pktconf {
	unsigned long num;
	unsigned long gap;
	struct packet *pkts;
	size_t len;
};

#endif /* TRAFGEN_CONF */

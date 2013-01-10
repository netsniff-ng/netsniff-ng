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
#include <sys/types.h>

#define TYPE_INC	0
#define TYPE_DEC	1

struct counter {
	int type;
	uint8_t min, max, inc, val;
	off_t off;
};

struct randomizer {
	off_t off;
};

struct csum16 {
	off_t off, from, to;
};

struct packet {
	uint8_t *payload;
	size_t len;
};

struct packet_dyn {
	struct counter *cnt;
	size_t clen;
	struct randomizer *rnd;
	size_t rlen;
	struct csum16 *csum;
	size_t slen;
};

extern int compile_packets(char *file, int verbose, int cpu);
extern void cleanup_packets(void);

#endif /* TRAFGEN_CONF */

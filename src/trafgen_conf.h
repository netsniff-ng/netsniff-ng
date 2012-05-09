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

struct mode;

struct counter {
	int type;
	uint8_t min;
	uint8_t max;
	uint8_t inc;
	uint8_t val;
	off_t off;
};

struct randomizer {
	uint8_t val;
	off_t off;
};

struct packet {
	uint8_t *payload;
	size_t len;
};

struct packet_dynamics {
	struct counter *counter;
	size_t counter_len;
	struct randomizer *randomizer;
	size_t randomizer_len;
};

extern int compile_packets(char *file, int verbose);
extern void cleanup_packets(void);

extern int main_loop_interactive(struct mode *mode, char *confname);

#endif /* TRAFGEN_CONF */

/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef STUN_H
#define STUN_H

#include <stdint.h>

extern void print_stun_probe(char *server, uint16_t sport, uint16_t tunport);

#endif /* STUN_H */

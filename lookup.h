/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010 Daniel Borkmann.
 * Copyright 2014 Tobias Klauser
 * Subject to the GPL, version 2.
 */

#ifndef LOOKUP_H
#define LOOKUP_H

enum ports {
	PORTS_UDP,
	PORTS_TCP,
	PORTS_ETHER,
	PORTS_MAX,
};

extern void lookup_init_ports(enum ports which);
extern void lookup_cleanup_ports(enum ports which);

extern char *lookup_port_udp(unsigned int id);
extern char *lookup_port_tcp(unsigned int id);
extern char *lookup_ether_type(unsigned int id);

#endif /* LOOKUP_H */

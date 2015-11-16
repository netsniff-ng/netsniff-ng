/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010 Daniel Borkmann.
 * Copyright 2014, 2015 Tobias Klauser
 * Subject to the GPL, version 2.
 */

#ifndef LOOKUP_H
#define LOOKUP_H

enum lookup_type {
	LT_PORTS_UDP,
	LT_PORTS_TCP,
	LT_ETHERTYPES,
	LT_OUI,
	LT_MAX,
};

extern void lookup_init(enum lookup_type which);
extern void lookup_cleanup(enum lookup_type which);

extern const char *lookup_port_udp(unsigned int id);
extern const char *lookup_port_tcp(unsigned int id);
extern const char *lookup_ether_type(unsigned int id);
extern const char *lookup_vendor(unsigned int id);

static inline const char *lookup_vendor_str(unsigned int id)
{
	return lookup_vendor(id) ? : "Unknown";
}

#endif /* LOOKUP_H */

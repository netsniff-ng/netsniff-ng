/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef ASLOOKUP_H
#define ASLOOKUP_H

struct asrecord {
	char number[16], ip[64], prefix[96], country[16], registry[256];
	char since[64], name[256];
};

extern int aslookup(const char *lhost, struct asrecord *rec);
extern int aslookup_prepare(const char *server, const char *port);

#endif /* ASLOOKUP_H */

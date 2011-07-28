/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef ASLOOKUP_H
#define ASLOOKUP_H

struct asrecord {
	char number[16];
	char ip[64];
	char prefix[96];
	char country[16];
	char registry[256];
	char since[64];
	char name[256];
};

extern int aslookup(char *lhost, size_t len, struct asrecord *rec,
		    char *server, char *port);

#endif /* ASLOOKUP_H */

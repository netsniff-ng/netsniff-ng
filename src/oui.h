/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2012 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef OUI_H
#define OUI_H

extern char *lookup_vendor(unsigned int id);
extern void dissector_init_oui(void);
extern void dissector_cleanup_oui(void);

#endif /* OUI_H */

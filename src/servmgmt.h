/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef SERVMGMT_H
#define SERVMGMT_H

extern void parse_userfile_and_generate_serv_store_or_die(char *homedir);
extern void dump_serv_store(void);
extern void destroy_serv_store(void);

#endif /* SERVMGMT_H */


#ifndef CT_SERVMGMT_H
#define CT_SERVMGMT_H

#include <stdio.h>
#include "curve.h"

extern void parse_userfile_and_generate_serv_store_or_die(char *homedir);
extern void dump_serv_store(void);
extern void get_serv_store_entry_by_alias(char *alias, size_t len,
					  char **host, char **port, int *udp);
extern struct curve25519_proto *get_serv_store_entry_proto_inf(void);
extern unsigned char *get_serv_store_entry_auth_token(void);
extern void destroy_serv_store(void);

#endif /* CT_SERVMGMT_H */

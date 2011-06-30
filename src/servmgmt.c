/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

#include "servmgmt.h"

void parse_userfile_and_generate_serv_store_or_die(char *homedir)
{
}

void dump_serv_store(void)
{
}

void destroy_serv_store(void)
{
}

void get_serv_store_entry_by_alias(char *alias, size_t len,
				   char **host, char **port, int *udp)
{
	/* if alias == 0, take the first entry */

	(*host) = NULL;
	(*port) = NULL;
	(*udp) = 0;
}


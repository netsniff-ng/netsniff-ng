/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "die.h"
#include "parser.h"
#include "locking.h"
#include "xmalloc.h"
#include "curvetun.h"
#include "strlcpy.h"
#include "curve.h"
#include "servmgmt.h"
#include "crypto_box_curve25519xsalsa20poly1305.h"

#define crypto_box_pub_key_size crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES

/* Config line format: alias;serverip|servername;port;udp|tcp;pubkey\n */

struct server_store {
	char alias[256];
	char host[256];
	char port[6]; /* 5 + \0 */
	int udp;
	unsigned char publickey[crypto_box_pub_key_size];
	struct server_store *next;
};

static struct server_store *store = NULL;

static struct rwlock store_lock;

static struct server_store *server_store_alloc(void)
{
	return xzmalloc(sizeof(struct server_store));
}

static void server_store_free(struct server_store *ss)
{
	if (!ss)
		return;
	memset(ss, 0, sizeof(struct server_store));
	xfree(ss);
}

void parse_userfile_and_generate_serv_store_or_die(char *homedir)
{
	rwlock_init(&store_lock);
	rwlock_wr_lock(&store_lock);
	/* TODO */
	if (store == NULL)
		panic("No registered servers found!\n");
	rwlock_unlock(&store_lock);
}

void dump_serv_store(void)
{
	int i;
	struct server_store *elem;

	rwlock_rd_lock(&store_lock);
	elem = store;
	while (elem) {
		printf("[%s] -> %s:%s via %s -> ", elem->alias,
		       elem->host, elem->port,
		       elem->udp ? "udp" : "tcp");
		for (i = 0; i < sizeof(elem->publickey); ++i)
			if (i == (sizeof(elem->publickey) - 1))
				printf("%02x\n", (unsigned char)
				       elem->publickey[i]);
			else
				printf("%02x:", (unsigned char)
				       elem->publickey[i]);
		elem = elem->next;
	}
	rwlock_unlock(&store_lock);
}

void destroy_serv_store(void)
{
	struct server_store *elem, *nelem = NULL;

	rwlock_wr_lock(&store_lock);
	elem = store;
	while (elem) {
		nelem = elem->next;
		elem->next = NULL;
		server_store_free(elem);
		elem = nelem;
	}
	rwlock_unlock(&store_lock);
	rwlock_destroy(&store_lock);
}

void get_serv_store_entry_by_alias(char *alias, size_t len,
				   char **host, char **port, int *udp)
{
	/* if alias == 0, take the first entry */

	(*host) = NULL;
	(*port) = NULL;
	(*udp) = 0;
}


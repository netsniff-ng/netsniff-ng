/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "die.h"
#include "built_in.h"
#include "locking.h"
#include "xmalloc.h"
#include "curvetun.h"
#include "xstring.h"
#include "curve.h"
#include "servmgmt.h"
#include "crypto_box_curve25519xsalsa20poly1305.h"
#include "crypto_auth_hmacsha512256.h"

#define crypto_box_pub_key_size crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES

/* Config line format: alias;serverip|servername;port;udp|tcp;pubkey\n */

struct server_store {
	char alias[256];
	char host[256];
	char port[6]; /* 5 + \0 */
	int udp;
	unsigned char publickey[crypto_box_pub_key_size];
	struct curve25519_proto proto_inf;
	unsigned char auth_token[crypto_auth_hmacsha512256_KEYBYTES];
	struct server_store *next;
};

static struct server_store *store = NULL;

static struct server_store *selected = NULL;

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
	FILE *fp;
	char path[PATH_MAX], buff[1024], *alias, *host, *port, *udp, *key;
	unsigned char pkey[crypto_box_pub_key_size];
	int line = 1, __udp = 0, ret;
	struct server_store *elem;

	memset(path, 0, sizeof(path));
	slprintf(path, sizeof(path), "%s/%s", homedir, FILE_SERVERS);

	rwlock_init(&store_lock);
	rwlock_wr_lock(&store_lock);

	fp = fopen(path, "r");
	if (!fp)
		panic("Cannot open server file!\n");
	memset(buff, 0, sizeof(buff));

	/* TODO: this is huge crap. needs to be rewritten! */
	while (fgets(buff, sizeof(buff), fp) != NULL) {
		buff[sizeof(buff) - 1] = 0;
		/* A comment. Skip this line */
		if (buff[0] == '#' || buff[0] == '\n') {
			memset(buff, 0, sizeof(buff));
			line++;
			continue;
		}
		alias = skips(buff);
		host = alias;
		while (*host != ';' &&
		       *host != '\0' &&
		       *host != ' ' &&
		       *host != '\t')
			host++;
		if (*host != ';')
			panic("Parse error! No alias found in l.%d!\n", line);
		*host = '\0';
		host++;
		if (*host == '\n')
			panic("Parse error! No host found in l.%d!\n", line);
		port = host;
		while (*port != ';' &&
		       *port != '\0' &&
		       *port != ' ' &&
		       *port != '\t')
			port++;
		if (*port != ';')
			panic("Parse error! No host found in l.%d!\n", line);
		*port = '\0';
		port++;
		if (*port == '\n')
			panic("Parse error! No port found in l.%d!\n", line);
		udp = port;
		while (*udp != ';' &&
		       *udp != '\0' &&
		       *udp != ' ' &&
		       *udp != '\t')
			udp++;
		if (*udp != ';')
			panic("Parse error! No port found in l.%d!\n", line);
		*udp = '\0';
		udp++;
		if (*udp == '\n')
			panic("Parse error! No udp|tcp found in l.%d!\n", line);
		if (udp[0] == 'u' && udp[1] == 'd' && udp[2] == 'p')
			__udp = 1;
		else if (udp[0] == 't' && udp[1] == 'c' && udp[2] == 'p')
			__udp = 0;
		else
			panic("Parse error! No udp|tcp found in l.%d!\n", line);
		udp += 3;
		if (*udp != ';')
			panic("Parse error! No key found in l.%d!\n", line);
		*udp = '\0';
		udp++;
		if (*udp == '\n')
			panic("Parse error! No key found in l.%d!\n", line);
		key = udp;
		key[strlen(key) - 1] = 0;
		memset(pkey, 0, sizeof(pkey));
		if (!curve25519_pubkey_hexparse_32(pkey, sizeof(pkey),
						   key, strlen(key)))
			panic("Parse error! No key found in l.%d!\n", line);

		if (strlen(alias) + 1 > sizeof(elem->alias))
			panic("Alias too long in l.%d!\n", line);
		if (strlen(host) + 1 > sizeof(elem->host))
			panic("Host too long in l.%d!\n", line);
		if (strlen(port) + 1 > sizeof(elem->port))
			panic("Port too long in l.%d!\n", line);
		if (strstr(alias, " ") || strstr(alias, "\t"))
			panic("Alias consists of whitespace in l.%d!\n", line);
		if (strstr(host, " ") || strstr(host, "\t"))
			panic("Host consists of whitespace in l.%d!\n", line);
		if (strstr(port, " ") || strstr(port, "\t"))
			panic("Port consists of whitespace in l.%d!\n", line);

		elem = server_store_alloc();
		elem->next = store;
		elem->udp = __udp;
		strlcpy(elem->alias, alias, sizeof(elem->alias));
		strlcpy(elem->host, host, sizeof(elem->host));
		strlcpy(elem->port, port, sizeof(elem->port));
		memcpy(elem->publickey, pkey, sizeof(elem->publickey));
		memcpy(elem->auth_token, elem->publickey, sizeof(elem->auth_token));
		ret = curve25519_proto_init(&elem->proto_inf,
					    elem->publickey,
					    sizeof(elem->publickey),
					    homedir, 0);
		if (ret)
			panic("Cannot init curve25519 proto on server!\n");
		store = elem;
		memset(buff, 0, sizeof(buff));
		line++;
	}

	fclose(fp);
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
	selected = NULL;
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
	struct server_store *elem;

	rwlock_rd_lock(&store_lock);
	elem = store;
	if (!alias) {
		while (elem && elem->next)
			elem = elem->next;
		if (elem) {
			(*host) = elem->host;
			(*port) = elem->port;
			(*udp) = elem->udp;
			selected = elem;
		} else {
			rwlock_unlock(&store_lock);
			goto nothing;
		}
	} else {
		while (elem) {
			if (!strncmp(elem->alias, alias,
				     min(len, strlen(elem->alias) + 1)))
				break;
			elem = elem->next;
		}
		if (elem) {
			(*host) = elem->host;
			(*port) = elem->port;
			(*udp) = elem->udp;
			selected = elem;
		} else {
			rwlock_unlock(&store_lock);
			goto nothing;
		}
	}
	rwlock_unlock(&store_lock);
	return;
nothing:
	(*host) = NULL;
	(*port) = NULL;
	(*udp) = -1;
}

struct curve25519_proto *get_serv_store_entry_proto_inf(void)
{
	struct curve25519_proto *ret = NULL;
	rwlock_rd_lock(&store_lock);
	if (selected)
		ret = &selected->proto_inf;
	rwlock_unlock(&store_lock);
	return ret;
}

unsigned char *get_serv_store_entry_auth_token(void)
{
	unsigned char *ret = NULL;
	rwlock_rd_lock(&store_lock);
	if (selected)
		ret = selected->auth_token;
	rwlock_unlock(&store_lock);
	return ret;
}


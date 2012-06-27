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
#include "xutils.h"
#include "curve.h"
#include "ct_servmgmt.h"
#include "crypto_box_curve25519xsalsa20poly1305.h"
#include "crypto_auth_hmacsha512256.h"

#define crypto_box_pub_key_size crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES

/* Config line format: alias;serverip|servername;port;udp|tcp;pubkey\n */

struct server_store {
	int udp;
	char alias[256];
	char host[256];
	char port[6]; /* 5 + \0 */
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

enum parse_states {
	PARSE_ALIAS,
	PARSE_SERVER,
	PARSE_PORT,
	PARSE_CARRIER,
	PARSE_PUBKEY,
	PARSE_DONE,
};

static int parse_line(char *line, char *homedir)
{
	int ret;
	char *str;
	enum parse_states s = PARSE_ALIAS;
	struct server_store *elem;
	unsigned char pkey[crypto_box_pub_key_size];

	elem = server_store_alloc();
	elem->next = store;

	str = strtok(line, ";");
	for (; str != NULL;) {
		switch (s) {
		case PARSE_ALIAS:
			strlcpy(elem->alias, str, sizeof(elem->alias));
			s = PARSE_SERVER;
			break;
		case PARSE_SERVER:
			strlcpy(elem->host, str, sizeof(elem->host));
			s = PARSE_PORT;
			break;
		case PARSE_PORT:
			strlcpy(elem->port, str, sizeof(elem->port));
			s = PARSE_CARRIER;
			break;
		case PARSE_CARRIER:
			if (!strncmp("udp", str, strlen("udp")))
				elem->udp = 1;
			else
				elem->udp = 0;
			s = PARSE_PUBKEY;
			break;
		case PARSE_PUBKEY:
			if (!curve25519_pubkey_hexparse_32(pkey, sizeof(pkey),
							   str, strlen(str)))
				return -EINVAL;
			memcpy(elem->publickey, pkey, sizeof(elem->publickey));
			memcpy(elem->auth_token, pkey, sizeof(elem->auth_token));
			ret = curve25519_proto_init(&elem->proto_inf,
					 	    elem->publickey,
						    sizeof(elem->publickey),
						    homedir, 1);
			if (ret)
				return -EIO;
			s = PARSE_DONE;
			break;
		case PARSE_DONE:
			break;
		default:
			return -EIO;
		}

		str = strtok(NULL, ";");
	}

	store = elem;
	return s == PARSE_DONE ? 0 : -EIO;
}

void parse_userfile_and_generate_serv_store_or_die(char *homedir)
{
	FILE *fp;
	char path[PATH_MAX], buff[1024];
	int line = 1, ret;

	memset(path, 0, sizeof(path));
	slprintf(path, sizeof(path), "%s/%s", homedir, FILE_SERVERS);

	rwlock_init(&store_lock);
	rwlock_wr_lock(&store_lock);

	fp = fopen(path, "r");
	if (!fp)
		panic("Cannot open server file!\n");

	memset(buff, 0, sizeof(buff));
	while (fgets(buff, sizeof(buff), fp) != NULL) {
		buff[sizeof(buff) - 1] = 0;
		/* A comment. Skip this line */
		if (buff[0] == '#' || buff[0] == '\n') {
			memset(buff, 0, sizeof(buff));
			line++;
			continue;
		}

		ret = parse_line(buff, homedir);
		if (ret < 0)
			panic("Cannot parse line %d from clients!\n", line);
		line++;
		memset(buff, 0, sizeof(buff));
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

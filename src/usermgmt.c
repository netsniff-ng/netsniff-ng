/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>

#include "die.h"
#include "usermgmt.h"
#include "parser.h"
#include "locking.h"
#include "xmalloc.h"
#include "write_or_die.h"
#include "curvetun.h"
#include "strlcpy.h"
#include "curve.h"
#include "hash.h"
#include "crypto_verify_32.h"
#include "crypto_hash_sha512.h"
#include "crypto_box_curve25519xsalsa20poly1305.h"

#define crypto_box_pub_key_size crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES

/* Config line format: username;pubkey\n */

struct user_store {
	char username[256];
	unsigned char publickey[crypto_box_pub_key_size];
	struct curve25519_proto proto_inf;
	struct user_store *next;
};

struct sock_map_entry {
	int fd;
	struct curve25519_proto *proto;
	struct sock_map_entry *next;
};

struct sockaddr_map_entry {
	struct sockaddr_storage *sa;
	size_t sa_len;
	struct curve25519_proto *proto;
	struct sockaddr_map_entry *next;
};

static struct user_store *store = NULL;
static struct rwlock store_lock;

static struct hash_table sock_mapper;
static struct rwlock sock_map_lock;

static struct hash_table sockaddr_mapper;
static struct rwlock sockaddr_map_lock;

static void init_sock_mapper(void)
{
	rwlock_init(&sock_map_lock);
	rwlock_wr_lock(&sock_map_lock);
	memset(&sock_mapper, 0, sizeof(sock_mapper));
	init_hash(&sock_mapper);
	rwlock_unlock(&sock_map_lock);
}

static void init_sockaddr_mapper(void)
{
	rwlock_init(&sockaddr_map_lock);
	rwlock_wr_lock(&sockaddr_map_lock);
	memset(&sockaddr_mapper, 0, sizeof(sockaddr_mapper));
	init_hash(&sockaddr_mapper);
	rwlock_unlock(&sockaddr_map_lock);
}

static int cleanup_batch_sock_mapper(void *ptr)
{
	struct sock_map_entry *next;
	struct sock_map_entry *e = ptr;

	if (!e)
		return 0;
	while ((next = e->next)) {
		e->next = NULL;
		xfree(e);
		e = next;
	}
	xfree(e);
	return 0;
}

static void destroy_sock_mapper(void)
{
	rwlock_wr_lock(&sock_map_lock);
	for_each_hash(&sock_mapper, cleanup_batch_sock_mapper);
	free_hash(&sock_mapper);
	rwlock_unlock(&sock_map_lock);
	rwlock_destroy(&sock_map_lock);
}

static int cleanup_batch_sockaddr_mapper(void *ptr)
{
	struct sockaddr_map_entry *next;
	struct sockaddr_map_entry *e = ptr;

	if (!e)
		return 0;
	while ((next = e->next)) {
		e->next = NULL;
		xfree(e);
		e = next;
	}
	xfree(e);
	return 0;
}

static void destroy_sockaddr_mapper(void)
{
	rwlock_wr_lock(&sockaddr_map_lock);
	for_each_hash(&sockaddr_mapper, cleanup_batch_sockaddr_mapper);
	free_hash(&sockaddr_mapper);
	rwlock_unlock(&sockaddr_map_lock);
	rwlock_destroy(&sockaddr_map_lock);
}

static struct user_store *user_store_alloc(void)
{
	return xzmalloc(sizeof(struct user_store));
}

static void user_store_free(struct user_store *us)
{
	if (!us)
		return;
	memset(us, 0, sizeof(struct user_store));
	xfree(us);
}

/* already in lock */
static int __check_duplicate_username(char *username, size_t len)
{
	int duplicate = 0;
	struct user_store *elem = store;
	while (elem) {
		if (!memcmp(elem->username, username,
			    strlen(elem->username) + 1)) {
			duplicate = 1;
			break;
		}
		elem = elem->next;
	}
	return duplicate;
}

/* already in lock */
static int __check_duplicate_pubkey(unsigned char *pubkey, size_t len)
{
	int duplicate = 0;
	struct user_store *elem = store;
	while (elem) {
		if (!memcmp(elem->publickey, pubkey,
			    sizeof(elem->publickey))) {
			duplicate = 1;
			break;
		}
		elem = elem->next;
	}
	return duplicate;
}

void parse_userfile_and_generate_user_store_or_die(char *homedir)
{
	FILE *fp;
	char path[512], buff[512], *username, *key;
	unsigned char pkey[crypto_box_pub_key_size];
	int line = 1, ret;
	struct user_store *elem;

	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), "%s/%s", homedir, FILE_CLIENTS);
	path[sizeof(path) - 1] = 0;

	rwlock_init(&store_lock);
	rwlock_wr_lock(&store_lock);

	fp = fopen(path, "r");
	if (!fp)
		panic("Cannot open client file!\n");
	memset(buff, 0, sizeof(buff));

	while (fgets(buff, sizeof(buff), fp) != NULL) {
		buff[sizeof(buff) - 1] = 0;
		/* A comment. Skip this line */
		if (buff[0] == '#' || buff[0] == '\n') {
			memset(buff, 0, sizeof(buff));
			line++;
			continue;
		}
		username = skips(buff);
		key = username;
		while (*key != ';' &&
		       *key != '\0' &&
		       *key != ' ' &&
		       *key != '\t')
			key++;
		if (*key != ';')
			panic("Parse error! No key found in l.%d!\n", line);
		*key = '\0';
		key++;
		if (*key == '\n')
			panic("Parse error! No key found in l.%d!\n", line);
		key = strtrim_right(key, '\n');
		memset(pkey, 0, sizeof(pkey));
		if (!curve25519_pubkey_hexparse_32(pkey, sizeof(pkey),
						   key, strlen(key)))
			panic("Parse error! No key found in l.%d!\n", line);
		if (strlen(username) + 1 > sizeof(elem->username))
			panic("Username too long in l.%d!\n", line);
		if (__check_duplicate_username(username, strlen(username) + 1))
			panic("Duplicate username in l.%d!\n", line);
		if (__check_duplicate_pubkey(pkey, sizeof(pkey)))
			panic("Duplicate publickey in l.%d!\n", line);
		if (strstr(username, " "))
			panic("Username consists of whitespace in l.%d!\n", line);
		if (strstr(username, "\t"))
			panic("Username consists of whitespace in l.%d!\n", line);
		elem = user_store_alloc();
		elem->next = store;
		strlcpy(elem->username, username, sizeof(elem->username));
		memcpy(elem->publickey, pkey, sizeof(elem->publickey));
		ret = curve25519_proto_init(&elem->proto_inf,
					    elem->publickey,
					    sizeof(elem->publickey),
					    homedir, 1);
		if (ret)
			panic("Cannot init curve25519 proto on user!\n");
		store = elem;
		smp_wmb();
		memset(buff, 0, sizeof(buff));
		line++;
	}

	fclose(fp);
	if (store == NULL)
		panic("No registered clients found!\n");
	rwlock_unlock(&store_lock);

	init_sock_mapper();
	init_sockaddr_mapper();
}

void dump_user_store(void)
{
	int i;
	struct user_store *elem;

	rwlock_rd_lock(&store_lock);
	elem = store;
	while (elem) {
		printf("%s -> ", elem->username);
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

void destroy_user_store(void)
{
	struct user_store *elem, *nelem = NULL;

	rwlock_wr_lock(&store_lock);
	elem = store;
	while (elem) {
		nelem = elem->next;
		elem->next = NULL;
		user_store_free(elem);
		elem = nelem;
	}
	rwlock_unlock(&store_lock);
	rwlock_destroy(&store_lock);

	destroy_sock_mapper();
	destroy_sockaddr_mapper();
}

int username_msg(char *username, size_t len, char *dst, size_t dlen)
{
	int fd;
	ssize_t ret;
	uint32_t salt;
	unsigned char h[crypto_hash_sha512_BYTES];
	struct username_struct *us = (struct username_struct *) dst;
	struct taia ts;
	char *uname;
	size_t uname_len;

	if (dlen < sizeof(struct username_struct))
		return -ENOMEM;

	uname_len = 512;
	uname = xzmalloc(uname_len);

	fd = open_or_die("/dev/random", O_RDONLY);
	ret = read_exact(fd, &salt, sizeof(salt), 0);
	if (ret != sizeof(salt))
		panic("Cannot read from /dev/random!\n");
	close(fd);

	snprintf(uname, uname_len, "%s%u", username, salt);
	uname[uname_len - 1] = 0;
	crypto_hash_sha512(h, (unsigned char *) uname, strlen(uname));

	memset(&ts, 0, sizeof(ts));
	taia_now(&ts);

	us->salt = htonl(salt);
	memcpy(us->hash, h, sizeof(us->hash));
	taia_pack(us->taia, &ts);

	xfree(uname);
	return 0;
}

static struct taia tolerance_taia = {
	.sec.x = 0,
	.nano = 250000000ULL,
	.atto = 0,
};

enum is_user_enum username_msg_is_user(char *src, size_t slen, char *username,
				       size_t len, struct taia *arrival_taia)
{
	int not_same = 1, is_ts_good = 0;
	enum is_user_enum ret = USERNAMES_NE;
	char *uname;
	size_t uname_len;
	uint32_t salt;
	struct username_struct *us = (struct username_struct *) src;
	struct taia ts, sub_res;
	unsigned char h[crypto_hash_sha512_BYTES];

	if (slen < sizeof(struct username_struct)) {
		errno = ENOMEM;
		return USERNAMES_ERR;
	}

	uname_len = 512;
	uname = xzmalloc(uname_len);

	salt = ntohl(us->salt);

	snprintf(uname, uname_len, "%s%u", username, salt);
	uname[uname_len - 1] = 0;
	crypto_hash_sha512(h, (unsigned char *) uname, strlen(uname));

	if (!crypto_verify_32(&h[0], &us->hash[0]) &&
	    !crypto_verify_32(&h[32], &us->hash[32]))
		not_same = 0;
	else
		not_same = 1;

	taia_unpack(us->taia, &ts);
	if (taia_less(arrival_taia, &ts)) {
		taia_sub(&sub_res, &ts, arrival_taia);
		if (taia_less(&sub_res, &tolerance_taia))
			is_ts_good = 1;
		else
			is_ts_good = 0;
	} else {
		taia_sub(&sub_res, arrival_taia, &ts);
		if (taia_less(&sub_res, &tolerance_taia))
			is_ts_good = 1;
		else
			is_ts_good = 0;
	}

	if (!not_same && is_ts_good)
		ret = USERNAMES_OK;
	else if (!not_same && !is_ts_good)
		ret = USERNAMES_TS;
	else
		ret = USERNAMES_NE;

	xfree(uname);
	return ret;
}

static int register_user_by_socket(int fd, struct curve25519_proto *proto)
{
	void **pos;
	struct sock_map_entry *entry;

	rwlock_wr_lock(&sock_map_lock);
	entry = xzmalloc(sizeof(*entry));
	entry->fd = fd;
	entry->proto = proto;
	pos = insert_hash(entry->fd, entry, &sock_mapper);
	if (pos) {
		entry->next = (*pos);
		(*pos) = entry;
	}
	rwlock_unlock(&sock_map_lock);

	return 0;
}

static int register_user_by_sockaddr(int sock, struct curve25519_proto *proto)
{
	return 0;
}

int try_register_user_by_socket(struct curve25519_struct *c,
				char *src, size_t slen, int sock)
{
	int ret = -1;
	struct user_store *elem;
	enum is_user_enum err;
	struct taia arrival_tai;

	rwlock_rd_lock(&store_lock);
	elem = store;
	taia_now(&arrival_tai);
	while (elem) {
//		clen = curve25519_decode(c, &elem->proto_inf,
//					 (unsigned char *) src,
//					 slen, &cbuff);
//		printf("clen: %d\n", clen);
//		if (clen <= 0)
//			goto next;
		err = username_msg_is_user((char *) src, slen,
					   elem->username,
					   strlen(elem->username) + 1,
					   &arrival_tai);
		if (err == USERNAMES_OK) {
			syslog(LOG_INFO, "Found user %s for id %d!\n",
			       elem->username, sock);
			ret = register_user_by_socket(sock, &elem->proto_inf);
			break;
		} else if (err == USERNAMES_TS)
			break;
		elem = elem->next;
	}
	rwlock_unlock(&store_lock);

	return ret;
}

int try_register_user_by_sockaddr(struct curve25519_struct *c,
				  char *src, size_t slen,
				  struct sockaddr_storage *sa,
				  size_t sa_len)
{
	return -1;
}

int get_user_by_socket(int fd, struct curve25519_proto **proto)
{
	int ret = -1;
	struct sock_map_entry *entry;

	errno = 0;
	rwlock_rd_lock(&sock_map_lock);
	entry = lookup_hash(fd, &sock_mapper);
	while (entry && fd != entry->fd)
		entry = entry->next;
	if (entry && fd == entry->fd) {
		(*proto) = entry->proto;
		ret = 0;
	} else {
		(*proto) = NULL;
		errno = ENOENT;
	}
	rwlock_unlock(&sock_map_lock);

	return ret;
}

int get_user_by_sockaddr(struct sockaddr_storage *sa, size_t sa_len,
			 struct curve25519_proto **proto)
{
	return -1;
}

static struct sock_map_entry *socket_to_sock_map_entry(int fd)
{
	struct sock_map_entry *entry, *ret = NULL;

	errno = 0;
	rwlock_rd_lock(&sock_map_lock);
	entry = lookup_hash(fd, &sock_mapper);
	while (entry && fd != entry->fd)
		entry = entry->next;
	if (entry && fd == entry->fd)
		ret = entry;
	else
		errno = ENOENT;
	rwlock_unlock(&sock_map_lock);

	return ret;
}

void remove_user_by_socket(int fd)
{
	struct sock_map_entry *pos;
	struct sock_map_entry *entry = socket_to_sock_map_entry(fd);

	if (!entry == 0 && errno == ENOENT)
		return;
	rwlock_wr_lock(&sock_map_lock);
	pos = remove_hash(entry->fd, entry, entry->next, &sock_mapper);
	while (pos && pos->next && pos->next != entry)
		pos = pos->next;
	if (pos && pos->next && pos->next == entry)
		pos->next = entry->next;
	entry->next = NULL;
	xfree(entry);
	rwlock_unlock(&sock_map_lock);
}

void remove_user_by_sockaddr(struct sockaddr_storage *sa, size_t sa_len)
{
}


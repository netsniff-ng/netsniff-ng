/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <syslog.h>
#include <limits.h>
#include <arpa/inet.h>

#include "die.h"
#include "ct_usermgmt.h"
#include "locking.h"
#include "xmalloc.h"
#include "xio.h"
#include "curvetun.h"
#include "xutils.h"
#include "curve.h"
#include "hash.h"
#include "crypto_verify_32.h"
#include "crypto_hash_sha512.h"
#include "crypto_box_curve25519xsalsa20poly1305.h"
#include "crypto_auth_hmacsha512256.h"

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

static unsigned char token[crypto_auth_hmacsha512256_KEYBYTES];

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

enum parse_states {
	PARSE_USERNAME,
	PARSE_PUBKEY,
	PARSE_DONE,
};

static int parse_line(char *line, char *homedir)
{
	int ret;
	char *str;
	enum parse_states s = PARSE_USERNAME;
	struct user_store *elem;
	unsigned char pkey[crypto_box_pub_key_size];

	elem = user_store_alloc();
	elem->next = store;

	str = strtok(line, ";");
	for (; str != NULL;) {
		switch (s) {
		case PARSE_USERNAME:
			if (__check_duplicate_username(str, strlen(str) + 1))
				return -EINVAL;
			strlcpy(elem->username, str, sizeof(elem->username));
			s = PARSE_PUBKEY;
			break;
		case PARSE_PUBKEY:
			if (!curve25519_pubkey_hexparse_32(pkey, sizeof(pkey),
							   str, strlen(str)))
				return -EINVAL;
			if (__check_duplicate_pubkey(pkey, sizeof(pkey)))
				return -EINVAL;
			memcpy(elem->publickey, pkey, sizeof(elem->publickey));
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

void parse_userfile_and_generate_user_store_or_die(char *homedir)
{
	FILE *fp;
	char path[PATH_MAX], buff[512];
	int line = 1, ret, fd;

	memset(path, 0, sizeof(path));
	slprintf(path, sizeof(path), "%s/%s", homedir, FILE_CLIENTS);

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

		ret = parse_line(buff, homedir);
		if (ret < 0)
			panic("Cannot parse line %d from clients!\n", line);
		line++;
		memset(buff, 0, sizeof(buff));
	}

	fclose(fp);

	if (store == NULL)
		panic("No registered clients found!\n");

	rwlock_unlock(&store_lock);

	init_sock_mapper();
	init_sockaddr_mapper();

	/*
	 * Pubkey is also used as a hmac of the initial packet to check
	 * the integrity of the packet, so that we know if it's just random
	 * garbage or a 'valid' packet. Again, just for the integrity!
	 */

	memset(path, 0, sizeof(path));
	slprintf(path, sizeof(path), "%s/%s", homedir, FILE_PUBKEY);

	fd = open_or_die(path, O_RDONLY);
	ret = read(fd, token, sizeof(token));
	if (ret != crypto_auth_hmacsha512256_KEYBYTES)
		panic("Cannot read public key!\n");
	close(fd);
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

	slprintf(uname, uname_len, "%s%u", username, salt);
	crypto_hash_sha512(h, (unsigned char *) uname, strlen(uname));

	us->salt = htonl(salt);
	memcpy(us->hash, h, sizeof(us->hash));

	xfree(uname);
	return 0;
}

enum is_user_enum username_msg_is_user(char *src, size_t slen, char *username,
				       size_t len)
{
	char *uname;
	size_t uname_len;
	uint32_t salt;
	struct username_struct *us = (struct username_struct *) src;
	unsigned char h[crypto_hash_sha512_BYTES];

	if (slen < sizeof(struct username_struct)) {
		errno = ENOMEM;
		return USERNAMES_ERR;
	}

	uname_len = 512;
	uname = xzmalloc(uname_len);

	salt = ntohl(us->salt);

	slprintf(uname, uname_len, "%s%u", username, salt);
	crypto_hash_sha512(h, (unsigned char *) uname, strlen(uname));
	xfree(uname);

	if (!crypto_verify_32(&h[0], &us->hash[0]) &&
	    !crypto_verify_32(&h[32], &us->hash[32]))
		return USERNAMES_OK;
	else
		return USERNAMES_NE;
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

static int register_user_by_sockaddr(struct sockaddr_storage *sa,
				     size_t sa_len,
				     struct curve25519_proto *proto)
{
	void **pos;
	struct sockaddr_map_entry *entry;
	unsigned int hash = hash_name((char *) sa, sa_len);

	rwlock_wr_lock(&sockaddr_map_lock);

	entry = xzmalloc(sizeof(*entry));
	entry->sa = xmemdupz(sa, sa_len);
	entry->sa_len = sa_len;
	entry->proto = proto;

	pos = insert_hash(hash, entry, &sockaddr_mapper);
	if (pos) {
		entry->next = (*pos);
		(*pos) = entry;
	}

	rwlock_unlock(&sockaddr_map_lock);

	return 0;
}

int try_register_user_by_socket(struct curve25519_struct *c,
				char *src, size_t slen, int sock, int log)
{
	int ret = -1;
	char *cbuff = NULL;
	size_t real_len = 132;
	ssize_t clen;
	struct user_store *elem;
	enum is_user_enum err;
	unsigned char auth[crypto_auth_hmacsha512256_BYTES];
	struct taia arrival_taia;

	/* assert(132 == clen + sizeof(auth)); */
	/*
	 * Check hmac first, if malicious, drop immediately before we
	 * investigate more efforts.
	 */
	if (slen < real_len)
		return -1;

	taia_now(&arrival_taia);

	memcpy(auth, src, sizeof(auth));

	src += sizeof(auth);
	real_len -= sizeof(auth);

	if (crypto_auth_hmacsha512256_verify(auth, (unsigned char *) src,
					     real_len, token)) {
		syslog(LOG_ERR, "Bad packet hmac for id %d! Dropping!\n", sock);
		return -1;
	} else {
		if (log)
			syslog(LOG_INFO, "Good packet hmac for id %d!\n", sock);
	}

	rwlock_rd_lock(&store_lock);

	elem = store;
	while (elem) {
		clen = curve25519_decode(c, &elem->proto_inf,
					 (unsigned char *) src, real_len,
					 (unsigned char **) &cbuff,
					 &arrival_taia);
		if (clen <= 0) {
			elem = elem->next;
			continue;
		}

		cbuff += crypto_box_zerobytes;
		clen -= crypto_box_zerobytes;

		if (log)
			syslog(LOG_INFO, "Packet decoded sucessfully for id %d!\n", sock);

		err = username_msg_is_user(cbuff, clen, elem->username,
					   strlen(elem->username) + 1);
		if (err == USERNAMES_OK) {
			if (log)
				syslog(LOG_INFO, "Found user %s for id %d! Registering ...\n",
				       elem->username, sock);
			ret = register_user_by_socket(sock, &elem->proto_inf);
			break;
		}

		elem = elem->next;
	}

	rwlock_unlock(&store_lock);

	if (ret == -1)
		syslog(LOG_ERR, "User not found! Dropping connection!\n");

	return ret;
}

int try_register_user_by_sockaddr(struct curve25519_struct *c,
				  char *src, size_t slen,
				  struct sockaddr_storage *sa,
				  size_t sa_len, int log)
{
	int ret = -1;
	char *cbuff = NULL;
	struct user_store *elem;
	ssize_t clen;
	size_t real_len = 132;
	enum is_user_enum err;
	unsigned char auth[crypto_auth_hmacsha512256_BYTES];
	struct taia arrival_taia;

	/* assert(132 == clen + sizeof(auth)); */
	/*
	 * Check hmac first, if malicious, drop immediately before we
	 * investigate more efforts.
	 */
	if (slen < real_len)
		return -1;

	taia_now(&arrival_taia);

	memcpy(auth, src, sizeof(auth));

	src += sizeof(auth);
	real_len -= sizeof(auth);

	if (crypto_auth_hmacsha512256_verify(auth, (unsigned char *) src,
					     real_len, token)) {
		syslog(LOG_ERR, "Got bad packet hmac! Dropping!\n");
		return -1;
	} else {
		if (log)
			syslog(LOG_INFO, "Got good packet hmac!\n");
	}

	rwlock_rd_lock(&store_lock);

	elem = store;
	while (elem) {
		clen = curve25519_decode(c, &elem->proto_inf,
					 (unsigned char *) src, real_len,
					 (unsigned char **) &cbuff,
					 &arrival_taia);
		if (clen <= 0) {
			elem = elem->next;
			continue;
		}

		cbuff += crypto_box_zerobytes;
		clen -= crypto_box_zerobytes;

		if (log)
			syslog(LOG_INFO, "Packet decoded sucessfully!\n");

		err = username_msg_is_user(cbuff, clen, elem->username,
					   strlen(elem->username) + 1);
		if (err == USERNAMES_OK) {
			if (log)
				syslog(LOG_INFO, "Found user %s! Registering ...\n",
				       elem->username);
			ret = register_user_by_sockaddr(sa, sa_len,
							&elem->proto_inf);
			break;
		}

		elem = elem->next;
	}

	rwlock_unlock(&store_lock);

	if (ret == -1)
		syslog(LOG_ERR, "User not found! Dropping connection!\n");

	return ret;
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
	int ret = -1;
	struct sockaddr_map_entry *entry;
	unsigned int hash = hash_name((char *) sa, sa_len);

	errno = 0;

	rwlock_rd_lock(&sockaddr_map_lock);

	entry = lookup_hash(hash, &sockaddr_mapper);
	while (entry && entry->sa_len == sa_len &&
	       memcmp(sa, entry->sa, entry->sa_len))
		entry = entry->next;
	if (entry && entry->sa_len == sa_len &&
	    !memcmp(sa, entry->sa, entry->sa_len)) {
		(*proto) = entry->proto;
		ret = 0;
	} else {
		(*proto) = NULL;
		errno = ENOENT;
	}

	rwlock_unlock(&sockaddr_map_lock);

	return ret;
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

	if (!entry)
		return;

	rwlock_wr_lock(&sock_map_lock);

	pos = remove_hash(entry->fd, entry, entry->next, &sock_mapper);
	while (pos && pos->next && pos->next != entry)
		pos = pos->next;
	if (pos && pos->next && pos->next == entry)
		pos->next = entry->next;

	memset(entry->proto->enonce, 0, sizeof(entry->proto->enonce));
	memset(entry->proto->dnonce, 0, sizeof(entry->proto->dnonce));

	entry->proto = NULL;
	entry->next = NULL;

	xfree(entry);

	rwlock_unlock(&sock_map_lock);
}

static struct sockaddr_map_entry *
sockaddr_to_sockaddr_map_entry(struct sockaddr_storage *sa, size_t sa_len)
{
	struct sockaddr_map_entry *entry, *ret = NULL;
	unsigned int hash = hash_name((char *) sa, sa_len);

	errno = 0;

	rwlock_rd_lock(&sockaddr_map_lock);

	entry = lookup_hash(hash, &sockaddr_mapper);
	while (entry && entry->sa_len == sa_len &&
	       memcmp(sa, entry->sa, entry->sa_len))
		entry = entry->next;
	if (entry && entry->sa_len == sa_len &&
	    !memcmp(sa, entry->sa, entry->sa_len))
		ret = entry;
	else
		errno = ENOENT;

	rwlock_unlock(&sockaddr_map_lock);

	return ret;
}

void remove_user_by_sockaddr(struct sockaddr_storage *sa, size_t sa_len)
{
	struct sockaddr_map_entry *pos;
	struct sockaddr_map_entry *entry;
	unsigned int hash = hash_name((char *) sa, sa_len);

	entry = sockaddr_to_sockaddr_map_entry(sa, sa_len);
	if (!entry)
		return;

	rwlock_wr_lock(&sockaddr_map_lock);

	pos = remove_hash(hash, entry, entry->next, &sockaddr_mapper);
	while (pos && pos->next && pos->next != entry)
		pos = pos->next;
	if (pos && pos->next && pos->next == entry)
		pos->next = entry->next;

	memset(entry->proto->enonce, 0, sizeof(entry->proto->enonce));
	memset(entry->proto->dnonce, 0, sizeof(entry->proto->dnonce));

	entry->proto = NULL;
	entry->next = NULL;

	xfree(entry->sa);
	xfree(entry);

	rwlock_unlock(&sockaddr_map_lock);
}

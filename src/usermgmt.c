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
#include <arpa/inet.h>

#include "die.h"
#include "usermgmt.h"
#include "locking.h"
#include "xmalloc.h"
#include "write_or_die.h"
#include "curvetun.h"
#include "curve.h"
#include "crypto_verify_32.h"
#include "crypto_hash_sha512.h"
#include "crypto_box_curve25519xsalsa20poly1305.h"

#define crypto_box_pub_key_size crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES

struct user_store {
	int socket;
	struct sockaddr_storage *addr;
	char username[256];
	unsigned char publickey[crypto_box_pub_key_size];
	struct curve25519_proto proto_inf;
	struct user_store *next;
};

static struct user_store *store = NULL;

static struct rwlock store_lock;

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

void parse_userfile_and_generate_store_or_die(void)
{
	rwlock_init(&store_lock);
	rwlock_wr_lock(&store_lock);
	/* parse ~/.curvetun/clients file */
	rwlock_unlock(&store_lock);
}

void destroy_store(void)
{
	rwlock_wr_lock(&store_lock);
	/* free store */
	rwlock_unlock(&store_lock);
	rwlock_destroy(&store_lock);
}

void get_curve25519_proto_by_socket(int sock, struct curve25519_proto **proto)
{
}

void get_curve25519_proto_by_sockaddr(struct sockaddr_storage *sa,
				      struct curve25519_proto **proto)
{
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


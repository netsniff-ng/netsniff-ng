/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

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
#include "crypto_hash_sha512.h"
#include "crypto_box_curve25519xsalsa20poly1305.h"

#define crypto_box_pub_key_size crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES

struct user_store {
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

/* dst: |--32 Byte Salt--|--64 Byte Hash--| */
/* This function is meant to make the ascii username not visible in the proto */
int username_msg(char *username, size_t len, char *dst, size_t dlen)
{
	int fd, i;
	ssize_t ret;
	uint32_t salt, *curr;
	unsigned char h[crypto_hash_sha512_BYTES];
	struct username_struct *us = (struct username_struct *) dst;
	unsigned char *uname;

	if (dlen < sizeof(*us))
		return -ENOMEM;

	uname = (unsigned char *) xstrdup(username);

	fd = open_or_die("/dev/random", O_RDONLY);
	ret = read_exact(fd, &salt, sizeof(salt), 0);
	if (ret != sizeof(salt))
		panic("Cannot read from /dev/random!\n");
	close(fd);

	for (i = 0; i < len; i += sizeof(salt)) {
		curr = (uint32_t *) ((void *) (&uname[i]));
		(*curr) = (*curr) ^ salt;
	}

	crypto_hash_sha512(h, uname, len);

	us->salt = htonl(salt);
	memcpy(us->hash, h, sizeof(us->hash));

	xfree(uname);
	return 0;
}

/* return 1 if names match, 0 if not */
int username_msg_is_user(char *src, size_t slen, char *username, size_t len)
{
	int i, is_same = 1;
	unsigned char *uname;
	uint32_t salt, *curr;
	struct username_struct *us = (struct username_struct *) src;
	unsigned char h[crypto_hash_sha512_BYTES];

	if (slen < sizeof(*us))
		return -ENOMEM;

	uname = (unsigned char *) xstrdup(username);

	salt = ntohl(us->salt);
	for (i = 0; i < len; i += sizeof(salt)) {
		curr = (uint32_t *) ((void *) &uname[i]);
		(*curr) = (*curr) ^ salt;
	}

	crypto_hash_sha512(h, uname, len);

	for (i = 0; i < sizeof(h); ++i) {
		if (h[i] != us->hash[i])
			is_same = 0;
	}

	xfree(uname);
	return is_same;
}


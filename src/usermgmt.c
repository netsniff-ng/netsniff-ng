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
#include "crypto_hash_sha512.h"
#include "write_or_die.h"

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


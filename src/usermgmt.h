/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef USERMGMT_H
#define USERMGMT_H

#include <stdint.h>

#include "crypto_hash_sha512.h"

struct username_struct {
	uint32_t salt;
	uint8_t  hash[crypto_hash_sha512_BYTES];
};

extern int username_msg(char *username, size_t len, char *dst, size_t dlen);
extern int username_msg_is_user(char *src, size_t slen, char *username,
				size_t len);

#endif /* USERMGMT_H */

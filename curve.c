/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2011 - 2013 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "built_in.h"
#include "xmalloc.h"
#include "curve.h"
#include "ioops.h"
#include "rnd.h"
#include "die.h"
#include "str.h"
#include "curvetun.h"
#include "locking.h"
#include "crypto.h"

int curve25519_pubkey_hexparse_32(unsigned char *bin, size_t blen,
				  const char *ascii, size_t alen)
{
	int ret = sscanf(ascii,
		     "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:"
		     "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:"
		     "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:"
		     "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
		      &bin[0],  &bin[1],  &bin[2],  &bin[3],  &bin[4],
		      &bin[5],  &bin[6],  &bin[7],  &bin[8],  &bin[9],
		     &bin[10], &bin[11], &bin[12], &bin[13], &bin[14],
		     &bin[15], &bin[16], &bin[17], &bin[18], &bin[19],
		     &bin[20], &bin[21], &bin[22], &bin[23], &bin[24],
		     &bin[25], &bin[26], &bin[27], &bin[28], &bin[29],
		     &bin[30], &bin[31]);
	return ret == 32;
}

void curve25519_alloc_or_maybe_die(struct curve25519_struct *curve)
{
	curve->enc_size = curve->dec_size = TUNBUFF_SIZ;

	curve->enc = xmalloc_aligned(curve->enc_size, 16);
	curve->dec = xmalloc_aligned(curve->dec_size, 16);

	spinlock_init(&curve->enc_lock);
	spinlock_init(&curve->dec_lock);
}

void curve25519_free(void *curvep)
{
	struct curve25519_struct *curve = curvep;

	memset(curve->enc, 0, curve->enc_size);
	memset(curve->dec, 0, curve->dec_size);

        xfree(curve->enc);
        xfree(curve->dec);

        spinlock_destroy(&curve->enc_lock);
        spinlock_destroy(&curve->dec_lock);
}

int curve25519_proto_init(struct curve25519_proto *proto, unsigned char *pubkey_remote,
			  size_t len, char *home, int server)
{
	int fd;
	ssize_t ret;
	char path[PATH_MAX];
	unsigned char secretkey_own[crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES];
	unsigned char publickey_own[crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES];

	fmemset(secretkey_own, 0, sizeof(secretkey_own));
	fmemset(publickey_own, 0, sizeof(publickey_own));

	if (!pubkey_remote || len != sizeof(publickey_own))
		return -EINVAL;

	slprintf(path, sizeof(path), "%s/%s", home, FILE_PRIVKEY);
	fd = open_or_die(path, O_RDONLY);

	ret = read(fd, secretkey_own, sizeof(secretkey_own));
	if (ret != sizeof(secretkey_own)) {
		xmemset(secretkey_own, 0, sizeof(secretkey_own));
		panic("Cannot read private key!\n");
	}

	close(fd);

	crypto_scalarmult_curve25519_base(publickey_own, secretkey_own);

	if (!crypto_verify_32(publickey_own, pubkey_remote)) {
		xmemset(secretkey_own, 0, sizeof(secretkey_own));
		xmemset(publickey_own, 0, sizeof(publickey_own));
		panic("PANIC: remote end has same public key as you have!!!\n");
	}

	crypto_box_beforenm(proto->key, pubkey_remote, secretkey_own);

	xmemset(proto->enonce, 0, sizeof(proto->enonce));
	xmemset(proto->dnonce, 0, sizeof(proto->dnonce));

	xmemset(secretkey_own, 0, sizeof(secretkey_own));
	xmemset(publickey_own, 0, sizeof(publickey_own));

	return 0;
}

ssize_t curve25519_encode(struct curve25519_struct *curve, struct curve25519_proto *proto,
			  unsigned char *plaintext, size_t size, unsigned char **chipertext)
{
	int ret, i;
	ssize_t done = size;
	struct taia packet_taia;

	spinlock_lock(&curve->enc_lock);

	if (unlikely(size > curve->enc_size)) {
		done = -ENOMEM;
		goto out;
	}

	taia_now(&packet_taia);
	taia_pack(proto->enonce + NONCE_OFFSET, &packet_taia);

	memset(curve->enc, 0, curve->enc_size);
	ret = crypto_box_afternm(curve->enc, plaintext, size, proto->enonce, proto->key);
	if (unlikely(ret)) {
		done = -EIO;
		goto out;
	}

	fmemcpy(curve->enc + crypto_box_boxzerobytes - NONCE_LENGTH,
	       proto->enonce + NONCE_OFFSET, NONCE_LENGTH);

	for (i = 0; i < crypto_box_boxzerobytes - NONCE_LENGTH; ++i)
		curve->enc[i] = (uint8_t) secrand();

	(*chipertext) = curve->enc;
out:
	spinlock_unlock(&curve->enc_lock);
	return done;
}

ssize_t curve25519_decode(struct curve25519_struct *curve, struct curve25519_proto *proto,
			  unsigned char *chipertext, size_t size, unsigned char **plaintext,
			  struct taia *arrival_taia)
{
	int ret;
	ssize_t done = size;
	struct taia packet_taia, arrival_taia2;

	spinlock_lock(&curve->dec_lock);

	if (unlikely(size > curve->dec_size)) {
		done = -ENOMEM;
		goto out;
	}
	if (unlikely(size < crypto_box_boxzerobytes + NONCE_LENGTH)) {
		done = 0;
		goto out;
	}
	if (arrival_taia == NULL) {
		taia_now(&arrival_taia2);
		arrival_taia = &arrival_taia2;
	}

	taia_unpack(chipertext + crypto_box_boxzerobytes - NONCE_LENGTH, &packet_taia);
        if (taia_looks_good(arrival_taia, &packet_taia) == 0) {
		syslog(LOG_ERR, "Bad packet time! Dropping connection!\n");
		done = 0;
		goto out;
	}

	memcpy(proto->dnonce + NONCE_OFFSET, chipertext + crypto_box_boxzerobytes - NONCE_LENGTH, NONCE_LENGTH);
	memset(curve->dec, 0, curve->dec_size);

	ret = crypto_box_open_afternm(curve->dec, chipertext, size, proto->dnonce, proto->key);
	if (unlikely(ret)) {
		done = -EIO;
		goto out;
	}

	(*plaintext) = curve->dec;
out:
	spinlock_unlock(&curve->dec_lock);
	return done;
}

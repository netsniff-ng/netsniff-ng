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
#include <pwd.h>
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
#include "config.h"

static void curve25519_init(struct curve25519_struct *curve)
{
	curve->enc_size = curve->dec_size = TUNBUFF_SIZ;

	curve->enc = xmalloc_aligned(curve->enc_size, 16);
	curve->dec = xmalloc_aligned(curve->dec_size, 16);

	spinlock_init(&curve->enc_lock);
	spinlock_init(&curve->dec_lock);
}

static void curve25519_destroy(struct curve25519_struct *curve)
{
        spinlock_destroy(&curve->enc_lock);
        spinlock_destroy(&curve->dec_lock);

	xzfree(curve->enc, curve->enc_size);
	xzfree(curve->dec, curve->dec_size);
}

struct curve25519_struct *curve25519_tfm_alloc(void)
{
	struct curve25519_struct *tfm;

	tfm = xzmalloc_aligned(sizeof(*tfm), 16);
	curve25519_init(tfm);

	return tfm;
}

void curve25519_tfm_free(struct curve25519_struct *tfm)
{
	curve25519_destroy(tfm);
	xzfree(tfm, sizeof(*tfm));
}

void curve25519_tfm_free_void(void *tfm)
{
	curve25519_tfm_free(tfm);
}

void curve25519_proto_init(struct curve25519_proto *proto,
			   unsigned char *pubkey_remote, size_t len)
{
	int result;
	char file[128];
	struct passwd *pw = getpwuid(getuid());
	unsigned char secretkey_own[crypto_box_sec_key_size];
	unsigned char publickey_own[crypto_box_pub_key_size];

	fmemset(secretkey_own, 0, sizeof(secretkey_own));
	fmemset(publickey_own, 0, sizeof(publickey_own));

	if (unlikely(!pubkey_remote || len != sizeof(publickey_own)))
		panic("Invalid argument on curve25519_proto_init!\n");

	slprintf(file, sizeof(file), "%s/%s", pw->pw_dir, FILE_PRIVKEY);
	read_blob_or_die(file, secretkey_own, sizeof(secretkey_own));

	crypto_scalarmult_curve25519_base(publickey_own, secretkey_own);
	result = crypto_verify_32(publickey_own, pubkey_remote);

	if (result == 0)
		panic("Remote end has same public key as you have!\n");

	crypto_box_beforenm(proto->key, pubkey_remote, secretkey_own);

	fmemset(proto->enonce, 0, sizeof(proto->enonce));
	fmemset(proto->dnonce, 0, sizeof(proto->dnonce));

	xmemset(secretkey_own, 0, sizeof(secretkey_own));
	xmemset(publickey_own, 0, sizeof(publickey_own));
}

ssize_t curve25519_encode(struct curve25519_struct *curve,
			  struct curve25519_proto *proto,
			  unsigned char *plaintext, size_t size,
			  unsigned char **ciphertext)
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
	taia_pack(NONCE_EDN_OFFSET(proto->enonce), &packet_taia);

	fmemset(curve->enc, 0, curve->enc_size);
	ret = crypto_box_afternm(curve->enc, plaintext, size,
				 proto->enonce, proto->key);
	if (unlikely(ret)) {
		done = -EIO;
		goto out;
	}

	fmemcpy(NONCE_PKT_OFFSET(curve->enc),
		NONCE_EDN_OFFSET(proto->enonce), NONCE_LENGTH);
	for (i = 0; i < NONCE_RND_LENGTH; ++i)
		curve->enc[i] = (uint8_t) secrand();

	(*ciphertext) = curve->enc;
out:
	spinlock_unlock(&curve->enc_lock);
	return done;
}

ssize_t curve25519_decode(struct curve25519_struct *curve,
			  struct curve25519_proto *proto,
			  unsigned char *ciphertext, size_t size,
			  unsigned char **plaintext,
			  struct taia *arrival_taia)
{
	int ret;
	ssize_t done = size;
	struct taia packet_taia, tmp_taia;

	spinlock_lock(&curve->dec_lock);
	if (unlikely(size > curve->dec_size || size < NONCE_ALL_LENGTH)) {
		done = size < NONCE_ALL_LENGTH ? 0 : -ENOMEM;
		goto out;
	}

	if (arrival_taia == NULL) {
		taia_now(&tmp_taia);
		arrival_taia = &tmp_taia;
	}

	taia_unpack(NONCE_PKT_OFFSET(ciphertext), &packet_taia);
        if (taia_looks_good(arrival_taia, &packet_taia) == 0) {
		done = 0;
		goto out;
	}

	fmemcpy(NONCE_EDN_OFFSET(proto->dnonce),
		NONCE_PKT_OFFSET(ciphertext), NONCE_LENGTH);
	fmemset(curve->dec, 0, curve->dec_size);

	ret = crypto_box_open_afternm(curve->dec, ciphertext, size,
				      proto->dnonce, proto->key);
	if (unlikely(ret)) {
		done = -EIO;
		goto out;
	}

	(*plaintext) = curve->dec;
out:
	spinlock_unlock(&curve->dec_lock);
	return done;
}

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

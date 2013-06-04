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

#define NONCE_LENGTH	(sizeof(struct taia))
#define NONCE_OFFSET	(crypto_box_noncebytes - NONCE_LENGTH)

void curve25519_selftest(void)
{
	int i;
	unsigned char alicesk[32] = {
		0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
		0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
		0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
		0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
	};
	unsigned char bobpk[32] = {
		0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
		0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
		0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
		0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
	};
	unsigned char nonce[24] = {
		0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
		0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
		0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37
	};
	unsigned char m[163] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x81, 0xf2, 0xd5,
		0xcf, 0x14, 0x13, 0x16, 0xeb, 0xeb, 0x0c, 0x7b,
		0x52, 0x28, 0xc5, 0x2a, 0x4c, 0x62, 0xcb, 0xd4,
		0x4b, 0x66, 0x84, 0x9b, 0x64, 0x24, 0x4f, 0xfc,
		0xe5, 0xec, 0xba, 0xaf, 0x33, 0xbd, 0x75, 0x1a,
		0x1a, 0xc7, 0x28, 0xd4, 0x5e, 0x6c, 0x61, 0x29,
		0x6c, 0xdc, 0x3c, 0x01, 0x23, 0x35, 0x61, 0xf4,
		0x1d, 0xb6, 0x6c, 0xce, 0x31, 0x4a, 0xdb, 0x31,
		0x0e, 0x3b, 0xe8, 0x25, 0x0c, 0x46, 0xf0, 0x6d,
		0xce, 0xea, 0x3a, 0x7f, 0xa1, 0x34, 0x80, 0x57,
		0xe2, 0xf6, 0x55, 0x6a, 0xd6, 0xb1, 0x31, 0x8a,
		0x02, 0x4a, 0x83, 0x8f, 0x21, 0xaf, 0x1f, 0xde,
		0x04, 0x89, 0x77, 0xeb, 0x48, 0xf5, 0x9f, 0xfd,
		0x49, 0x24, 0xca, 0x1c, 0x60, 0x90, 0x2e, 0x52,
		0xf0, 0xa0, 0x89, 0xbc, 0x76, 0x89, 0x70, 0x40,
		0xe0, 0x82, 0xf9, 0x37, 0x76, 0x38, 0x48, 0x64,
		0x5e, 0x07, 0x05
	};
	unsigned char c[163];
	unsigned char result[147] = {
		0xf3, 0xff, 0xc7, 0x70, 0x3f, 0x94, 0x00, 0xe5,
		0x2a, 0x7d, 0xfb, 0x4b, 0x3d, 0x33, 0x05, 0xd9,
		0x8e, 0x99, 0x3b, 0x9f, 0x48, 0x68, 0x12, 0x73,
		0xc2, 0x96, 0x50, 0xba, 0x32, 0xfc, 0x76, 0xce,
		0x48, 0x33, 0x2e, 0xa7, 0x16, 0x4d, 0x96, 0xa4,
		0x47, 0x6f, 0xb8, 0xc5, 0x31, 0xa1, 0x18, 0x6a,
		0xc0, 0xdf, 0xc1, 0x7c, 0x98, 0xdc, 0xe8, 0x7b,
		0x4d, 0xa7, 0xf0, 0x11, 0xec, 0x48, 0xc9, 0x72,
		0x71, 0xd2, 0xc2, 0x0f, 0x9b, 0x92, 0x8f, 0xe2,
		0x27, 0x0d, 0x6f, 0xb8, 0x63, 0xd5, 0x17, 0x38,
		0xb4, 0x8e, 0xee, 0xe3, 0x14, 0xa7, 0xcc, 0x8a,
		0xb9, 0x32, 0x16, 0x45, 0x48, 0xe5, 0x26, 0xae,
		0x90, 0x22, 0x43, 0x68, 0x51, 0x7a, 0xcf, 0xea,
		0xbd, 0x6b, 0xb3, 0x73, 0x2b, 0xc0, 0xe9, 0xda,
		0x99, 0x83, 0x2b, 0x61, 0xca, 0x01, 0xb6, 0xde,
		0x56, 0x24, 0x4a, 0x9e, 0x88, 0xd5, 0xf9, 0xb3,
		0x79, 0x73, 0xf6, 0x22, 0xa4, 0x3d, 0x14, 0xa6,
		0x59, 0x9b, 0x1f, 0x65, 0x4c, 0xb4, 0x5a, 0x74,
		0xe3, 0x55, 0xa5
	};

	bug_on(NONCE_LENGTH != 16);

	crypto_box_curve25519xsalsa20poly1305(c, m, 163, nonce, bobpk, alicesk);

	for (i = 16; i < 163; ++i) {
		if (c[i] != result[i - 16])
			panic("Crypto selftest failed! :-(\n");
	}
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

void curve25519_alloc_or_maybe_die(struct curve25519_struct *curve)
{
	curve->enc_buf_size = curve->dec_buf_size = TUNBUFF_SIZ;

	curve->enc_buf = xmalloc_aligned(curve->enc_buf_size, 16);
	curve->dec_buf = xmalloc_aligned(curve->dec_buf_size, 16);

	spinlock_init(&curve->enc_lock);
	spinlock_init(&curve->dec_lock);
}

void curve25519_free(void *curvep)
{
	struct curve25519_struct *curve = curvep;

	memset(curve->enc_buf, 0, curve->enc_buf_size);
	memset(curve->dec_buf, 0, curve->dec_buf_size);

        xfree(curve->enc_buf);
        xfree(curve->dec_buf);

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

	if (unlikely(size > curve->enc_buf_size)) {
		done = -ENOMEM;
		goto out;
	}

	taia_now(&packet_taia);
	taia_pack(proto->enonce + NONCE_OFFSET, &packet_taia);

	memset(curve->enc_buf, 0, curve->enc_buf_size);
	ret = crypto_box_afternm(curve->enc_buf, plaintext, size, proto->enonce, proto->key);
	if (unlikely(ret)) {
		done = -EIO;
		goto out;
	}

	fmemcpy(curve->enc_buf + crypto_box_boxzerobytes - NONCE_LENGTH,
	       proto->enonce + NONCE_OFFSET, NONCE_LENGTH);

	for (i = 0; i < crypto_box_boxzerobytes - NONCE_LENGTH; ++i)
		curve->enc_buf[i] = (uint8_t) secrand();

	(*chipertext) = curve->enc_buf;
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

	if (unlikely(size > curve->dec_buf_size)) {
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
	memset(curve->dec_buf, 0, curve->dec_buf_size);

	ret = crypto_box_open_afternm(curve->dec_buf, chipertext, size, proto->dnonce, proto->key);
	if (unlikely(ret)) {
		done = -EIO;
		goto out;
	}

	(*plaintext) = curve->dec_buf;
out:
	spinlock_unlock(&curve->dec_lock);
	return done;
}

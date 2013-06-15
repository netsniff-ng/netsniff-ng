#ifndef CURVE_H
#define CURVE_H

#include "locking.h"
#include "built_in.h"
#include "ioops.h"
#include "rnd.h"
#include "taia.h"
#include "crypto.h"

struct curve25519_proto {
	unsigned char enonce[crypto_box_noncebytes] __aligned_16;
	unsigned char dnonce[crypto_box_noncebytes] __aligned_16;
	unsigned char key[crypto_box_beforenmbytes] __aligned_16;
};

struct curve25519_struct {
	unsigned char *enc, *dec;
	size_t enc_size, dec_size;
	struct spinlock enc_lock, dec_lock;
};

extern void curve25519_selftest(void);

extern struct curve25519_struct *curve25519_tfm_alloc(void);
extern void curve25519_tfm_free(struct curve25519_struct *tfm);
extern void curve25519_tfm_free_void(void *tfm);

extern void curve25519_proto_init(struct curve25519_proto *proto,
				  unsigned char *pubkey_remote, size_t len);
extern int curve25519_pubkey_hexparse_32(unsigned char *bin, size_t blen,
					 const char *ascii, size_t alen);

extern ssize_t curve25519_encode(struct curve25519_struct *curve,
				 struct curve25519_proto *proto,
				 unsigned char *plaintext, size_t size,
				 unsigned char **ciphertext);
extern ssize_t curve25519_decode(struct curve25519_struct *curve,
				 struct curve25519_proto *proto,
				 unsigned char *ciphertext, size_t size,
				 unsigned char **plaintext,
				 struct taia *arrival_taia);

#endif /* CURVE_H */

#ifndef CRYPTO_H
#define CRYPTO_H

#include "taia.h"
#include "crypto_verify_32.h"
#include "crypto_hash_sha512.h"
#include "crypto_box_curve25519xsalsa20poly1305.h"
#include "crypto_scalarmult_curve25519.h"
#include "crypto_auth_hmacsha512256.h"

#define crypto_box_zerobytes		crypto_box_curve25519xsalsa20poly1305_ZEROBYTES
#define crypto_box_boxzerobytes		crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES
#define crypto_box_noncebytes		crypto_box_curve25519xsalsa20poly1305_NONCEBYTES
#define crypto_box_beforenmbytes	crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES
#define crypto_box_beforenm		crypto_box_curve25519xsalsa20poly1305_beforenm
#define crypto_box_afternm		crypto_box_curve25519xsalsa20poly1305_afternm
#define crypto_box_open_afternm		crypto_box_curve25519xsalsa20poly1305_open_afternm
#define crypto_box_pub_key_size		crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES
#define crypto_box_sec_key_size		crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES

#define NONCE_LENGTH			(sizeof(struct taia))
#define NONCE_RND_LENGTH		(crypto_box_boxzerobytes - NONCE_LENGTH)
#define NONCE_ALL_LENGTH		(crypto_box_boxzerobytes + NONCE_LENGTH)
#define NONCE_OFFSET			(crypto_box_noncebytes - NONCE_LENGTH)
#define NONCE_EDN_OFFSET(x)		((x) + NONCE_OFFSET)
#define NONCE_PKT_OFFSET(x)		((x) + NONCE_RND_LENGTH)

#endif /* CRYPTO_H */

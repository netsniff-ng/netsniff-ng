#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <stdio.h>

#include "rnd.h"
#include "die.h"
#include "str.h"
#include "crypto.h"
#include "curve.h"
#include "ioops.h"
#include "config.h"
#include "keypair.h"

void generate_keypair(void)
{
	struct passwd *pw = getpwuid(getuid());
	unsigned char publickey[crypto_box_pub_key_size];
	unsigned char secretkey[crypto_box_sec_key_size];
	char file[128];

	xmemset(publickey, 0, sizeof(publickey));
	xmemset(secretkey, 0, sizeof(secretkey));

	curve25519_selftest();

	printf("Reading from %s (this may take a while) ...\n",
	       HIG_ENTROPY_SOURCE);

	gen_key_bytes(secretkey, sizeof(secretkey));
	crypto_scalarmult_curve25519_base(publickey, secretkey);

	slprintf(file, sizeof(file), "%s/%s", pw->pw_dir, FILE_PUBKEY);
	write_blob_or_die(file, publickey, sizeof(publickey));
	printf("Public key written to %s!\n", file);

	slprintf(file, sizeof(file), "%s/%s", pw->pw_dir, FILE_PRIVKEY);
	write_blob_or_die(file, secretkey, sizeof(secretkey));
	printf("Secret key written to %s!\n", file);

	xmemset(publickey, 0, sizeof(publickey));
	xmemset(secretkey, 0, sizeof(secretkey));
}

void verify_keypair(void)
{
	int result;
	struct passwd *pw = getpwuid(getuid());
	unsigned char publickey[crypto_box_pub_key_size];
	unsigned char publicres[crypto_box_pub_key_size];
	unsigned char secretkey[crypto_box_sec_key_size];
	char file[128];

	curve25519_selftest();

	xmemset(publickey, 0, sizeof(publickey));
	xmemset(publicres, 0, sizeof(publicres));
	xmemset(secretkey, 0, sizeof(secretkey));

	slprintf(file, sizeof(file), "%s/%s", pw->pw_dir, FILE_PUBKEY);
	read_blob_or_die(file, publickey, sizeof(publickey));

	slprintf(file, sizeof(file), "%s/%s", pw->pw_dir, FILE_PRIVKEY);
	read_blob_or_die(file, secretkey, sizeof(secretkey));

	crypto_scalarmult_curve25519_base(publicres, secretkey);
	result = crypto_verify_32(publicres, publickey);

	xmemset(publickey, 0, sizeof(publickey));
	xmemset(publicres, 0, sizeof(publicres));
	xmemset(secretkey, 0, sizeof(secretkey));

	if (result)
		panic("Keypair is corrupt! You need to regenerate!\n");
}

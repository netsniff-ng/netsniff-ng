#ifndef RND_H
#define RND_H

#define HIG_ENTROPY_SOURCE	"/dev/random"
#define LOW_ENTROPY_SOURCE	"/dev/urandom"

/* secrand is not really secure, but the name only suggests it's better to use
 * than rand(3) when transferring bytes over the network in non-security
 * critical structure members. secrand() is only used to fill up salts actually.
 */
extern int secrand(void);
extern void gen_key_bytes(unsigned char *area, size_t len);

#endif /* RND_H */

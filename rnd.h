#ifndef RND_H
#define RND_H

#define HIG_ENTROPY_SOURCE	"/dev/random"
#define LOW_ENTROPY_SOURCE	"/dev/urandom"

/* Note: it's not really secure, but the name only suggests it's better to use
 * than rand(3) when transferring bytes over the network in non-security
 * critical structure members. secrand() is only used to fill up salts actually.
 */
extern int secrand(void);

#endif /* RND_H */

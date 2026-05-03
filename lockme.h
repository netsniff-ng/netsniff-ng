#ifndef LOCKME_H
#define LOCKME_H

#include <sys/mman.h>

#include "die.h"

static inline void xlockme(void)
{
	if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0)
		fprintf(stderr, "Warning: cannot lock pages on macOS\n");
}

static inline void xunlockme(void)
{
	munlockall();
}

#endif /* LOCKME_H */

/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

#include <unistd.h>
#include <sys/types.h>

#include "error_and_die.h"

void check_for_root_maybe_die(void)
{
	if (geteuid() != 0)
		panic("Uhhuh, not root?!\n");
}


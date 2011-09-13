/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <assert.h>

#include "parser.h"
#include "die.h"

char *getuint(char *in, uint32_t *out)
{
	char * endptr = NULL;

	assert(in);
	assert(out);

	errno = 0;

	*out = strtoul(in, &endptr, 0);

	if ((endptr != NULL && *endptr != '\0') || errno != 0) {
		panic("Syntax error!\n");
	}

	return in;
}

char *strtrim_right(register char *p, register char c)
{
	register char *end;
	register int len;

	len = strlen(p);
	while (*p && len) {
		end = p + len - 1;
		if (c == *end)
			*end = 0;
		else
			break;
		len = strlen(p);
	}

	return p;
}

char *strtrim_left(register char *p, register char c)
{
	register int len;
	
	len = strlen(p);
	while (*p && len--) {
		if (c == *p)
			p++;
		else
			break;
	}
	
	return p;
}

/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef DEFLATE_H
#define DEFLATE_H

#include "zlib.h"
#include "locking.h"

struct z_buffer
{
	z_stream stream;
	unsigned char * buf;
	unsigned char * origin;
	size_t size;
	struct spinlock lock;
};

struct z_struct {
	size_t off;
	struct z_buffer inflate;
	struct z_buffer deflate;
};

extern int z_alloc_or_maybe_die(struct z_struct *z, int z_level, size_t off);
extern ssize_t z_deflate(struct z_struct *z, char *src, size_t size, char **dst);
extern ssize_t z_inflate(struct z_struct *z, char *src, size_t size, char **dst);
extern void z_free(void *z);
extern char *z_get_version(void);

#endif /* DEFLATE_H */

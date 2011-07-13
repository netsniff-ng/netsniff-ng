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

struct z_struct {
	size_t off;
	/* Inflate buffer */
	z_stream inf;
	unsigned char *inf_z_buf;
	unsigned char *inf_z_buf_orig;
	size_t inf_z_buf_size;
	struct spinlock inf_lock;
	/* Deflate buffer */
	z_stream def;
	unsigned char *def_z_buf;
	unsigned char *def_z_buf_orig;
	size_t def_z_buf_size;
	struct spinlock def_lock;
};

extern int z_alloc_or_maybe_die(struct z_struct *z, int z_level, size_t off);
extern ssize_t z_deflate(struct z_struct *z, char *src, size_t size, char **dst);
extern ssize_t z_inflate(struct z_struct *z, char *src, size_t size, char **dst);
extern void z_free(void *z);
extern char *z_get_version(void);

#endif /* DEFLATE_H */

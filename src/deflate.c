/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include "deflate.h"
#include "xmalloc.h"
#include "zlib.h"
#include "die.h"
#include "curve.h"
#include "locking.h"
#include "curvetun.h"

int z_alloc_or_maybe_die(struct z_struct *z, int z_level, size_t off)
{
	int ret;
	if (!z)
		return -EINVAL;
	if (z_level < Z_DEFAULT_COMPRESSION || z_level > Z_BEST_COMPRESSION)
		return -EINVAL;
	z->off = off;

	z->def.zalloc = Z_NULL;
	z->def.zfree  = Z_NULL;
	z->def.opaque = Z_NULL;
	z->inf.zalloc = Z_NULL;
	z->inf.zfree  = Z_NULL;
	z->inf.opaque = Z_NULL;

	z->inf_z_buf_size = TUNBUFF_SIZ;
	z->def_z_buf_size = TUNBUFF_SIZ;

	//TODO: Fix deflate/inflate bug, for now compression is turned off
	ret = deflateInit2(&z->def, /*z_level*/ 0, Z_DEFLATED, -15, 9,
			   Z_DEFAULT_STRATEGY);
	if (ret != Z_OK)
		panic("Can't initialize zLibs compressor!\n");

	ret = inflateInit2(&z->inf, -15);
	if (ret != Z_OK)
		panic("Can't initialize zLibs decompressor!\n");

	z->inf_z_buf_orig = xzmalloc(z->inf_z_buf_size + z->off);
	z->def_z_buf_orig = xzmalloc(z->def_z_buf_size + z->off);
	z->inf_z_buf = z->inf_z_buf_orig + z->off;
	z->def_z_buf = z->def_z_buf_orig + z->off;

	spinlock_init(&z->inf_lock);
	spinlock_init(&z->def_lock);

	return 0;
}

void z_free(void *vz)
{
	struct z_struct *z = vz;
	if (!z)
		return;

	deflateEnd(&z->def);
	inflateEnd(&z->inf);

	xfree(z->inf_z_buf_orig);
	xfree(z->def_z_buf_orig);

	spinlock_destroy(&z->inf_lock);
	spinlock_destroy(&z->def_lock);
}

char *z_get_version(void)
{
	return ZLIB_VERSION;
}

static void def_z_buf_expansion_or_die(struct z_struct *z, size_t size)
{
	z->def_z_buf_orig = xrealloc(z->def_z_buf_orig, 1,
				     z->def_z_buf_size + z->off + size);
	z->def_z_buf = z->def_z_buf_orig + z->off;
	z->def.next_out = z->def_z_buf + z->def_z_buf_size;
	z->def.avail_out = size;
	z->def_z_buf_size += size;
}

static void inf_z_buf_expansion_or_die(struct z_struct *z, size_t size)
{
	z->inf_z_buf_orig = xrealloc(z->inf_z_buf_orig, 1,
				     z->inf_z_buf_size + z->off + size);
	z->inf_z_buf = z->inf_z_buf_orig + z->off;
	z->inf.next_out = z->inf_z_buf + z->inf_z_buf_size;
	z->inf.avail_out = size;
	z->inf_z_buf_size += size;
}

ssize_t z_deflate(struct z_struct *z, char *src, size_t size,
		  char **dst)
{
	int ret;
	size_t todo, done = 0;  

	spinlock_lock(&z->def_lock);
	memset(z->def_z_buf, 0, z->def_z_buf_size);
	z->def.next_in = (void *) src;
	z->def.avail_in = size;
	z->def.next_out = (void *) z->def_z_buf;
	z->def.avail_out = z->def_z_buf_size;

	while (1) {
		todo = z->def.avail_out;
		ret = deflate(&z->def, Z_SYNC_FLUSH);
		if (ret != Z_OK) {
			whine("Deflate: %s\n", z->def.msg);
			spinlock_unlock(&z->def_lock);
			return -EIO;
		}

		done += (todo - z->def.avail_out);
		if (z->def.avail_in == 0)
			break;
		def_z_buf_expansion_or_die(z, 100);
	}

	*dst = (void *) z->def_z_buf;
	spinlock_unlock(&z->def_lock);

	return done;
}

ssize_t z_inflate(struct z_struct *z, char *src, size_t size,
		  char **dst)
{
	int ret;
	int todo, done = 0;

	spinlock_lock(&z->inf_lock);
	memset(z->inf_z_buf, 0, z->inf_z_buf_size);
	z->inf.next_in = (void *) src;
	z->inf.avail_in = size;
	z->inf.next_out = (void *) z->inf_z_buf;
	z->inf.avail_out = z->inf_z_buf_size;

	while (1) {
		todo = z->inf.avail_out;
		ret = inflate(&z->inf, Z_SYNC_FLUSH);
		if (ret != Z_OK) {
			whine("Inflate: %s\n", z->inf.msg);
			spinlock_unlock(&z->inf_lock);
			return -EIO;
		}

		done += (todo - z->inf.avail_out);
		if (z->inf.avail_in == 0)
			break;
		inf_z_buf_expansion_or_die(z, 100);
	}

	*dst = (void *) z->inf_z_buf;
	spinlock_unlock(&z->inf_lock);

	return done;
}


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
#include "locking.h"
#include "curvetun.h"

int z_alloc_or_maybe_die(struct z_struct *z, int z_level)
{
	int ret;

	if (!z)
		return -EINVAL;
	if (z_level < -1 || z_level > 9)
		return -EINVAL;

	z->def.zalloc = Z_NULL;
	z->def.zfree  = Z_NULL;
	z->def.opaque = Z_NULL;

	z->inf.zalloc = Z_NULL;
	z->inf.zfree  = Z_NULL;
	z->inf.opaque = Z_NULL;

	z->inf_z_buf_size = TUNBUFF_SIZ;
	z->def_z_buf_size = TUNBUFF_SIZ;

	ret = deflateInit(&z->def, z_level);
	if (ret != Z_OK)
		panic("Can't initialize zLibs compressor!\n");

	ret = inflateInit(&z->inf);
	if (ret != Z_OK)
		panic("Can't initialize zLibs decompressor!\n");

	z->inf_z_buf = xmalloc(z->inf_z_buf_size);
	z->def_z_buf = xmalloc(z->def_z_buf_size);

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

	xfree(z->inf_z_buf);
	xfree(z->def_z_buf);

	spinlock_destroy(&z->inf_lock);
	spinlock_destroy(&z->def_lock);
}

char *z_get_version(void)
{
	return ZLIB_VERSION;
}

static void def_z_buf_expansion_or_die(struct z_struct *z, size_t size)
{
	z->def_z_buf = xrealloc(z->def_z_buf, 1, z->def_z_buf_size + size);

	z->def.next_out = z->def_z_buf + z->def_z_buf_size;
	z->def.avail_out = size;

	z->def_z_buf_size += size;
}

static void inf_z_buf_expansion_or_die(struct z_struct *z, size_t size)
{
	z->inf_z_buf = xrealloc(z->inf_z_buf, 1, z->inf_z_buf_size + size);

	z->inf.next_out = z->inf_z_buf + z->inf_z_buf_size;
	z->inf.avail_out = size;

	z->inf_z_buf_size += size;
}
 
ssize_t z_deflate(struct z_struct *z, char *src, size_t size, char **dst)
{
	int ret;
	size_t todo, done = 0;  

	spinlock_lock(&z->def_lock);
	memset(z->def_z_buf, 0, z->def_z_buf_size);

	z->def.next_in = (void *) src;
	z->def.avail_in = size;
	z->def.next_out = (void *) z->def_z_buf;
	z->def.avail_out = z->def_z_buf_size;

	for (;;) {
		todo = z->def.avail_out;

		ret = deflate(&z->def, Z_SYNC_FLUSH);
		if (ret != Z_OK) {
			whine("Deflate error %d!\n", ret);
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

ssize_t z_inflate(struct z_struct *z, char *src, size_t size, char **dst)
{
	int ret;
	int todo, done = 0;     

	spinlock_lock(&z->inf_lock);
	memset(z->inf_z_buf, 0, z->inf_z_buf_size);

	z->inf.next_in = (void *) src;
	z->inf.avail_in = size;
	z->inf.next_out = (void *) z->inf_z_buf;
	z->inf.avail_out = z->inf_z_buf_size;

	for (;;) {
		todo = z->inf.avail_out;

		ret = inflate(&z->inf, Z_SYNC_FLUSH);
		if (ret != Z_OK) {
			whine("Inflate error %d!\n", ret);
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


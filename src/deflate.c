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

void z_buffer_init(struct z_buffer * zb, size_t off)
{
	if (!zb)
		return;

	zb->stream.zalloc = Z_NULL;
	zb->stream.zfree = Z_NULL;
	zb->stream.opaque = Z_NULL;
	zb->size = TUNBUFF_SIZ;
	zb->origin = xzmalloc(zb->size + off);
	zb->buf = zb->origin + off;
	spinlock_init(&zb->lock);
}

void z_buffer_destroy(struct z_buffer * zb)
{
	xfree(zb->origin);
	spinlock_destroy(&zb->lock);
}

int z_alloc_or_maybe_die(struct z_struct *z, int z_level, size_t off)
{
	int ret;
	if (!z)
		return -EINVAL;
	if (z_level < Z_DEFAULT_COMPRESSION || z_level > Z_BEST_COMPRESSION)
		return -EINVAL;
	z->off = off;

	z_buffer_init(&z->deflate, z->off);
	z_buffer_init(&z->inflate, z->off);

	//TODO: Fix deflate/inflate bug, for now compression is turned off
	ret = deflateInit2(&z->deflate.stream, Z_NO_COMPRESSION, Z_DEFLATED, -15, 9,
			   Z_DEFAULT_STRATEGY);
	if (ret != Z_OK)
		panic("Can't initialize zLibs compressor!\n");

	ret = inflateInit2(&z->inflate.stream, -15);
	if (ret != Z_OK)
		panic("Can't initialize zLibs decompressor!\n");

	return 0;
}

void z_free(void *vz)
{
	struct z_struct *z = vz;

	if (!z)
		return;

	deflateEnd(&z->deflate.stream);
	inflateEnd(&z->inflate.stream);

	z_buffer_destroy(&z->deflate);
	z_buffer_destroy(&z->inflate);
}

char *z_get_version(void)
{
	return ZLIB_VERSION;
}

static void z_buffer_realloc(struct z_buffer * zb, size_t off, size_t extra)
{
	zb->origin = xrealloc(zb->origin, 1, zb->size + off + extra);
	zb->buf = zb->origin + off;
	zb->stream.next_out = zb->buf + zb->size;
	zb->stream.avail_out = extra;
	zb->size += extra;
}

ssize_t z_deflate(struct z_struct *z, char *src, size_t size,
		  char **dst)
{
	struct z_buffer *zb = NULL;
	int ret;
	size_t todo, done = 0;

	zb = &z->deflate;

	spinlock_lock(&zb->lock);
	memset(zb->buf, 0, zb->size);
	zb->stream.next_in = (void *) src;
	zb->stream.avail_in = size;
	zb->stream.next_out = (void *) zb->buf;
	zb->stream.avail_out = zb->size;

	while (1) {
		todo = zb->stream.avail_out;
		ret = deflate(&zb->stream, Z_SYNC_FLUSH);
		if (ret != Z_OK) {
			whine("Deflate: %s\n", zb->stream.msg);
			spinlock_unlock(&zb->lock);
			return -EIO;
		}

		done += (todo - zb->stream.avail_out);
		if (zb->stream.avail_in == 0)
			break;
		z_buffer_realloc(zb, z->off, 100);
	}

	*dst = (void *) zb->buf;
	spinlock_unlock(&zb->lock);

	return done;
}

ssize_t z_inflate(struct z_struct *z, char *src, size_t size,
		  char **dst)
{
	struct z_buffer *zb = NULL;
	int ret;
	int todo, done = 0;

	zb = &z->inflate;

	spinlock_lock(&zb->lock);
	memset(zb->buf, 0, zb->size);
	zb->stream.next_in = (void *) src;
	zb->stream.avail_in = size;
	zb->stream.next_out = (void *) zb->buf;
	zb->stream.avail_out = zb->size;

	while (1) {
		todo = zb->stream.avail_out;
		ret = inflate(&zb->stream, Z_SYNC_FLUSH);
		if (ret != Z_OK) {
			whine("Inflate: %s\n", zb->stream.msg);
			spinlock_unlock(&zb->lock);
			return -EIO;
		}

		done += (todo - zb->stream.avail_out);
		if (zb->stream.avail_in == 0)
			break;
		z_buffer_realloc(zb, z->off, 100);
	}

	*dst = (void *) zb->buf;
	spinlock_unlock(&zb->lock);

	return done;
}


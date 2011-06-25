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

static z_stream inf, def;

static struct spinlock inf_lock;

static struct spinlock def_lock;

static unsigned char *inf_z_buf = NULL;

static int inf_z_buf_size = TUNBUFF_SIZ;

static unsigned char *def_z_buf = NULL;

static int def_z_buf_size = TUNBUFF_SIZ;

int z_alloc_or_maybe_die(int z_level)
{
	int ret;

	/* Usually can be Z_DEFAULT_COMPRESSION */
	if (z_level < -1 || z_level > 9)
		return -EINVAL;

	def.zalloc = Z_NULL;
	def.zfree  = Z_NULL;
	def.opaque = Z_NULL;

	inf.zalloc = Z_NULL;
	inf.zfree  = Z_NULL;
	inf.opaque = Z_NULL;

	ret = deflateInit(&def, z_level);
	if (ret != Z_OK)
		panic("Can't initialize zLibs compressor!\n");

	ret = inflateInit(&inf);
	if (ret != Z_OK)
		panic("Can't initialize zLibs decompressor!\n");

	inf_z_buf = xmalloc(inf_z_buf_size);
	def_z_buf = xmalloc(def_z_buf_size);

	spinlock_init(&inf_lock);
	spinlock_init(&def_lock);

	return 0;
}

void z_free(void)
{
	deflateEnd(&def);
	inflateEnd(&inf);

	xfree(inf_z_buf);
	xfree(def_z_buf);

	spinlock_destroy(&inf_lock);
	spinlock_destroy(&def_lock);
}

char *z_get_version(void)
{
	return ZLIB_VERSION;
}

static void def_z_buf_expansion_or_die(z_stream *stream, size_t size)
{
	def_z_buf = xrealloc(def_z_buf, 1, def_z_buf_size + size);

	stream->next_out = def_z_buf + def_z_buf_size;
	stream->avail_out = size;

	def_z_buf_size += size;
}

static void inf_z_buf_expansion_or_die(z_stream *stream, size_t size)
{
	inf_z_buf = xrealloc(inf_z_buf, 1, inf_z_buf_size + size);

	stream->next_out = inf_z_buf + inf_z_buf_size;
	stream->avail_out = size;

	inf_z_buf_size += size;
}
 
ssize_t z_deflate(char *src, size_t size, char **dst)
{
	int ret;
	size_t todo, done = 0;  

	spinlock_lock(&def_lock);

	def.next_in = (void *) src;
	def.avail_in = size;
	def.next_out = (void *) def_z_buf;
	def.avail_out = def_z_buf_size;

	for (;;) {
		todo = def.avail_out;
		ret = deflate(&def, Z_SYNC_FLUSH);
		if (ret != Z_OK) {
			whine("Deflate error %d!\n", ret);
			spinlock_unlock(&def_lock);
			return -EIO;
		}
		done += (todo - def.avail_out);
		if (def.avail_in == 0)
			break;
		def_z_buf_expansion_or_die(&def, 100);
	}
	*dst = (void *) def_z_buf;

	spinlock_unlock(&def_lock);

	return done;
}

ssize_t z_inflate(char *src, size_t size, char **dst)
{
	int ret;
	int todo, done = 0;     

	spinlock_lock(&inf_lock);

	inf.next_in = (void *) src;
	inf.avail_in = size;
	inf.next_out = (void *) inf_z_buf;
	inf.avail_out = inf_z_buf_size;

	for (;;) {
		todo = inf.avail_out;
		ret = inflate(&inf, Z_SYNC_FLUSH);
		if (ret != Z_OK) {
			whine("Inflate error %d!\n", ret);
			spinlock_unlock(&inf_lock);
			return -EIO;
		}
		done += (todo - inf.avail_out);
		if (inf.avail_in == 0)
			break;
		inf_z_buf_expansion_or_die(&inf, 100);
	}
	*dst = (void *) inf_z_buf;

	spinlock_unlock(&inf_lock);

	return done;
}

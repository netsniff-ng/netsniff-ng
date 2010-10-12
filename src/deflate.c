/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "xmalloc.h"
#include "zlib.h"
#include "error_and_die.h"

/* Not thread safe! */
static z_stream inf, def;

/* Maximum of a jumbo frame and some overhead */
static unsigned char *z_buf = NULL;
static int z_buf_size = 9200;

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
		error_and_die(EXIT_FAILURE, "Can't initialize zLibs "
			      "compressor!\n");

	ret = inflateInit(&inf);
	if (ret != Z_OK)
		error_and_die(EXIT_FAILURE, "Can't initialize zLibs "
			      "decompressor!\n");

	z_buf = xmalloc(z_buf_size);

	return 0;
}

void z_free(void)
{
	deflateEnd(&def);
	inflateEnd(&inf);

	xfree(z_buf);
}

char *z_get_version(void)
{
	return ZLIB_VERSION;
}

static void z_buf_expansion_or_die(z_stream *stream, size_t size)
{
	z_buf = xrealloc(z_buf, 1, z_buf_size + size);

	stream->next_out = z_buf + z_buf_size;
	stream->avail_out = size;

	z_buf_size += size;
}
 
ssize_t z_deflate(char *src, size_t size, char **dst)
{
	int ret;
	size_t todo, done = 0;  

	def.next_in = (void *) src;
	def.avail_in = size;
	def.next_out = (void *) z_buf;
	def.avail_out = z_buf_size;

	for (;;) {
		todo = def.avail_out;

		ret = deflate(&def, Z_SYNC_FLUSH);
		if (ret != Z_OK) {
			whine("Deflate error %d!\n", ret);
			return -EIO;
		}

		done += (todo - def.avail_out);
		if (def.avail_in == 0)
			break;

		z_buf_expansion_or_die(&def, 100);
	}

	*dst = (void *) z_buf;
	return done;
}

ssize_t z_inflate(char *src, size_t size, char **dst)
{
	int ret;
	int todo, done = 0;     

	inf.next_in = (void *) src;
	inf.avail_in = size;
	inf.next_out = (void *) z_buf;
	inf.avail_out = z_buf_size;

	for (;;) {
		todo = inf.avail_out;

		ret = inflate(&inf, Z_SYNC_FLUSH);
		if (ret != Z_OK) {
			whine("Inflate error %d!\n", ret);
			return -EIO;
		}

		done += (todo - inf.avail_out);
		if (inf.avail_in == 0)
			break;

		z_buf_expansion_or_die(&inf, 100);
	}

	*dst = (void *) z_buf;
	return done;
}

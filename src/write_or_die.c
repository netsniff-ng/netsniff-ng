/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "write_or_die.h"
#include "error_and_die.h"

void fsync_or_die(int fd, const char *msg)
{
	if (fsync(fd) < 0)
		puke_and_die(EXIT_FAILURE, "%s: fsync error", msg);
}

ssize_t write_or_die(int fd, const void *buf, size_t len)
{
	ssize_t ret = write(fd, buf, len);
	if (ret < 0) {
		if (errno == EPIPE)
			exit(EXIT_SUCCESS);
		puke_and_die(EXIT_FAILURE, "Write error");
	}

	return ret;
}

ssize_t write_or_whine_pipe(int fd, const void *buf, size_t len,
			    const char *msg)
{
	ssize_t ret = write(fd, buf, len);
	if (ret < 0) {
		if (errno == EPIPE)
			exit(0);
		whine("%s: write error (%s)!\n", msg, strerror(errno));
		return 0;
	}

	return ret;
}

ssize_t write_or_whine(int fd, const void *buf, size_t len,
		       const char *msg)
{
	ssize_t ret = write(fd, buf, len);
	if (ret < 0) {
		whine("%s: write error (%s)!\n", msg, strerror(errno));
		return 0;
	}

	return ret;
}

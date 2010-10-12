/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef WRITE_OR_DIE_H
#define WRITE_OR_DIE_H

extern void fsync_or_die(int fd, const char *msg);
extern ssize_t write_or_die(int fd, const void *buf, size_t count);
extern ssize_t write_or_whine_pipe(int fd, const void *buf, size_t len,
				   const char *msg);
extern ssize_t write_or_whine(int fd, const void *buf, size_t len,
			      const char *msg);

#endif /* WRITE_OR_DIE_H */

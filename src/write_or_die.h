/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef WRITE_OR_DIE_H
#define WRITE_OR_DIE_H

extern void fsync_or_die(int fd, const char *msg);
extern int open_or_die(const char *file, int flags);
extern int open_or_die_m(const char *file, int flags, mode_t mode);
extern int tun_open_or_die(char *name);
extern ssize_t read_or_die(int fd, void *buf, size_t count);
extern ssize_t read_exact(int fd, char *buf, size_t len);
extern ssize_t write_exact(int fd, char *buf, size_t len);
extern ssize_t write_or_die(int fd, const void *buf, size_t count);
extern ssize_t write_or_whine_pipe(int fd, const void *buf, size_t len,
				   const char *msg);
extern ssize_t write_or_whine(int fd, const void *buf, size_t len,
			      const char *msg);

#endif /* WRITE_OR_DIE_H */

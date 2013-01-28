/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef XIO_H
#define XIO_H

extern int open_or_die(const char *file, int flags);
extern int open_or_die_m(const char *file, int flags, mode_t mode);
extern void create_or_die(const char *file, mode_t mode);
extern int tun_open_or_die(char *name, int type);
extern void pipe_or_die(int pipefd[2], int flags);
extern ssize_t read_or_die(int fd, void *buf, size_t count);
extern ssize_t write_or_die(int fd, const void *buf, size_t count);
extern ssize_t read_exact(int fd, void *buf, size_t len, int mayexit);
extern ssize_t write_exact(int fd, void *buf, size_t len, int mayexit);

#endif /* XIO_H */

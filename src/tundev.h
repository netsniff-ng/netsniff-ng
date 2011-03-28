/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#ifndef TUNDEV_H
#define TUNDEV_H

#include <unistd.h>

extern int tun_open_or_die(void);
extern ssize_t tun_write(int fd, const void *buf, size_t count);
extern ssize_t tun_read(int fd, void *buf, size_t count);
extern void tun_close(int fd);

#endif /* TUNDEV_H */

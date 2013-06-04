/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010 Daniel Borkmann.
 * Copyright 2009, 2010 Emmanuel Roullit.
 * Subject to the GPL, version 2.
 */

#ifndef XSYS_H
#define XSYS_H

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/ethtool.h>
#include <linux/if.h>
#include <linux/wireless.h>
#include <poll.h>
#include <sys/poll.h>
#include <sched.h>
#include <stdbool.h>
#include <sys/resource.h>
#include <sys/time.h>

#include "built_in.h"

extern void set_epoll_descriptor(int fd_epoll, int action, int fd_toadd, int events);
extern int set_epoll_descriptor2(int fd_epoll, int action, int fd_toadd, int events);
extern void set_itimer_interval_value(struct itimerval *itimer, unsigned long sec,
				      unsigned long usec);

#endif /* XSYS_H */

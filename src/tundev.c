/*
 * netsniff-ng - the packet sniffing beast
 * Portions of this code derived and modified from:
 *  Copyright 1998-2000 Maxim Krasnyansky <max_mk@yahoo.com>
 *  VTun has been derived from VPPP package by Maxim Krasnyansky.
 *  Subject to the GPL, version 2.
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL.
 */

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "tundev.h"
#include "error_and_die.h"

static int __tun_open_or_die(void)
{
	int i, fd;
	char tunname[IFNAMSIZ];

	for (i = 0; i < 255; ++i) {
		memset(tunname, 0, sizeof(tunname));
		sprintf(tunname, "/dev/tun%d", i);

		fd = open(tunname, O_RDWR);
		if (fd > 0)
			return fd;
	}

	panic("Cannot open tunnel device!\n");
	return 0; /* never reached, but to suppress compiler warning */
}

#ifndef OTUNSETIFF
# define OTUNSETIFF (('T' << 8) | 202)
#endif

int tun_open_or_die(void)
{
	int fd, ret;
	struct ifreq ifr;

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0)
		return __tun_open_or_die();

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	ret = ioctl(fd, TUNSETIFF, &ifr);
	if (ret < 0) {
		if (errno == EBADFD) {
			ret = ioctl(fd, OTUNSETIFF, &ifr);
			if (ret < 0)
				panic("ioctl screwed up!\n");
		} else
			panic("ioctl screwed up!\n");
	}

	return fd;
}

ssize_t tun_write(int fd, const void *buf, size_t count)
{
	return write(fd, buf, count);
}

ssize_t tun_read(int fd, void *buf, size_t count)
{
	return read(fd, buf, count);
}

void tun_close(int fd)
{
	close(fd);
}


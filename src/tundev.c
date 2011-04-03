/*
 * netsniff-ng - the packet sniffing beast
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
#include "die.h"
#include "strlcpy.h"

int tun_open_or_die(char *name)
{
	int fd, ret;
	struct ifreq ifr;

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0)
		panic("Cannot open /dev/net/tun!\n");

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	if (name)
		strlcpy(ifr.ifr_name, name, IFNAMSIZ);

	ret = ioctl(fd, TUNSETIFF, &ifr);
	if (ret < 0)
		panic("ioctl screwed up!\n");

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


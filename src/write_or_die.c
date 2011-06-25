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
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "write_or_die.h"
#include "die.h"
#include "strlcpy.h"

extern sig_atomic_t sigint;

void fsync_or_die(int fd, const char *msg)
{
	if (fsync(fd) < 0)
		puke_and_die(EXIT_FAILURE, "%s: fsync error", msg);
}

int open_or_die(const char *file, int flags)
{
	int ret = open(file, flags);
	if (ret < 0)
		puke_and_die(EXIT_FAILURE, "Open error");
	return ret;
}

int open_or_die_m(const char *file, int flags, mode_t mode)
{
	int ret = open(file, flags, mode);
	if (ret < 0)
		puke_and_die(EXIT_FAILURE, "Open error");
	return ret;
}

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

	ret = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
	if (ret < 0)
		panic("fctnl screwed up!\n");

	return fd;
}

ssize_t read_or_die(int fd, void *buf, size_t len)
{
	ssize_t ret = read(fd, buf, len);
	if (ret < 0) {
		if (errno == EPIPE)
			exit(EXIT_SUCCESS);
		puke_and_die(EXIT_FAILURE, "Read error");
	}

	return ret;
}

ssize_t read_exact(int fd, void *buf, size_t len, int mayexit)
{
	register ssize_t num = 0, written;

	while (len > 0 && !sigint) {
		if ((written = read(fd, buf, len)) < 0) {
			if (errno == EAGAIN && num > 0)
				continue;
			if (mayexit)
				return -1;
			else
				continue;
		}

		if (!written)
			return 0;

		len -= written;
		buf += written;
		num += written;
	}

	return num;
}

ssize_t write_exact(int fd, void *buf, size_t len, int mayexit)
{
	register ssize_t num = 0, written;

	while (len > 0 && !sigint) {
		if ((written = write(fd, buf, len)) < 0) {
			if (errno == EAGAIN && num > 0)
				continue;
			if (mayexit)
				return -1;
			else
				continue;
		}

		if (!written)
			return 0;

		len -= written;
		buf += written;
		num += written;
	}

	return num;
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

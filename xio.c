/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "die.h"
#include "xio.h"
#include "str.h"
#include "xutils.h"

int open_or_die(const char *file, int flags)
{
	int ret = open(file, flags);
	if (ret < 0)
		panic("Cannot open file %s! %s.\n", file, strerror(errno));

	return ret;
}

int open_or_die_m(const char *file, int flags, mode_t mode)
{
	int ret = open(file, flags, mode);
	if (ret < 0)
		panic("Cannot open or create file %s! %s.", file, strerror(errno));
	return ret;
}

void create_or_die(const char *file, mode_t mode)
{
	int fd = open_or_die_m(file, O_WRONLY | O_CREAT, mode);
	close(fd);
}

void pipe_or_die(int pipefd[2], int flags)
{
	int ret = pipe2(pipefd, flags);
	if (ret < 0)
		panic("Cannot create pipe2 event fd! %s.\n", strerror(errno));
}

int tun_open_or_die(char *name, int type)
{
	int fd, ret;
	short flags;
	struct ifreq ifr;

	if (!name)
		panic("No name provided for tundev!\n");

	fd = open_or_die("/dev/net/tun", O_RDWR);

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = type;
	strlcpy(ifr.ifr_name, name, IFNAMSIZ);

	ret = ioctl(fd, TUNSETIFF, &ifr);
	if (ret < 0)
		panic("ioctl screwed up! %s.\n", strerror(errno));

	ret = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
	if (ret < 0)
		panic("fctnl screwed up! %s.\n", strerror(errno));

	flags = device_get_flags(name);
	flags |= IFF_UP | IFF_RUNNING;
	device_set_flags(name, flags);

	return fd;
}

ssize_t read_or_die(int fd, void *buf, size_t len)
{
	ssize_t ret = read(fd, buf, len);
	if (ret < 0) {
		if (errno == EPIPE)
			die();
		panic("Cannot read from descriptor! %s.\n", strerror(errno));
	}

	return ret;
}

ssize_t write_or_die(int fd, const void *buf, size_t len)
{
	ssize_t ret = write(fd, buf, len);
	if (ret < 0) {
		if (errno == EPIPE)
			die();
		panic("Cannot write to descriptor! %s.", strerror(errno));
	}

	return ret;
}

extern volatile sig_atomic_t sigint;

ssize_t read_exact(int fd, void *buf, size_t len, int mayexit)
{
	ssize_t num = 0, written;

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
	ssize_t num = 0, written;

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

static int fd_rnd = -1;

static void randombytes(unsigned char *x, unsigned long long xlen)
{
	int ret;

	if (fd_rnd == -1) {
		for (;;) {
			fd_rnd = open("/dev/urandom", O_RDONLY);
			if (fd_rnd != -1)
				break;
			sleep(1);
		}
	}

	while (xlen > 0) {
		if (xlen < 1048576)
			ret = xlen;
		else
			ret = 1048576;

		ret = read(fd_rnd, x, ret);
		if (ret < 1) {
			sleep(1);
			continue;
		}

		x += ret;
		xlen -= ret;
	}
}

/* Note: it's not really secure, but the name only suggests it's better to use
 * than rand(3) when transferring bytes over the network in non-security
 * critical structure members. secrand() is only used to fill up salts actually.
 */
int secrand(void)
{
	int ret;

	randombytes((void *) &ret, sizeof(ret));

	return ret;
}

static char const *priov[] = {
	[LOG_EMERG]	=	"EMERG:",
	[LOG_ALERT]	=	"ALERT:",
	[LOG_CRIT]	=	"CRIT:",
	[LOG_ERR]	=	"ERR:",
	[LOG_WARNING]	=	"WARNING:",
	[LOG_NOTICE]	=	"NOTICE:",
	[LOG_INFO]	=	"INFO:",
	[LOG_DEBUG]	=	"DEBUG:",
};

static ssize_t cookie_writer(void *cookie, char const *data, size_t leng)
{
	int prio = LOG_DEBUG, len;

	do {
		len = strlen(priov[prio]);
	} while (memcmp(data, priov[prio], len) && --prio >= 0);

	if (prio < 0) {
		prio = LOG_INFO;
	} else {
		data += len;
		leng -= len;
	}

	while (*data == ' ') {
		 ++data;
		--leng;
	}

	syslog(prio, "%.*s", (int) leng, data);

	return leng;
}

static cookie_io_functions_t cookie_log = {
	.write		=	cookie_writer,
};

void to_std_log(FILE **fp)
{
	setvbuf(*fp = fopencookie(NULL, "w", cookie_log), NULL, _IOLBF, 0);
}

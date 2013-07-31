#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "die.h"
#include "dev.h"
#include "ioops.h"
#include "str.h"
#include "built_in.h"

int open_or_die(const char *file, int flags)
{
	int ret = open(file, flags);
	if (unlikely(ret < 0))
		panic("Cannot open file %s! %s.\n", file, strerror(errno));
	return ret;
}

int open_or_die_m(const char *file, int flags, mode_t mode)
{
	int ret = open(file, flags, mode);
	if (unlikely(ret < 0))
		panic("Cannot open or create file %s! %s.", file, strerror(errno));
	return ret;
}

int dup_or_die(int oldfd)
{
	int newfd = dup(oldfd);
	if (unlikely(newfd < 0))
		panic("Cannot dup old file descriptor!\n");
	return newfd;
}

void dup2_or_die(int oldfd, int newfd)
{
	int ret = dup2(oldfd, newfd);
	if (unlikely(ret < 0))
		panic("Cannot dup2 old/new file descriptor!\n");
}

void create_or_die(const char *file, mode_t mode)
{
	int fd = open_or_die_m(file, O_WRONLY | O_CREAT, mode);
	close(fd);
}

void pipe_or_die(int pipefd[2], int flags)
{
	int ret = pipe2(pipefd, flags);
	if (unlikely(ret < 0))
		panic("Cannot create pipe2 event fd! %s.\n", strerror(errno));
}

int tun_open_or_die(const char *name, int type)
{
	int fd, ret;
	short flags;
	struct ifreq ifr;

	if (unlikely(!name))
		panic("No name provided for tundev!\n");

	fd = open_or_die("/dev/net/tun", O_RDWR);

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = type;
	strlcpy(ifr.ifr_name, name, IFNAMSIZ);

	ret = ioctl(fd, TUNSETIFF, &ifr);
	if (unlikely(ret < 0))
		panic("ioctl screwed up! %s.\n", strerror(errno));

	ret = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
	if (unlikely(ret < 0))
		panic("fctnl screwed up! %s.\n", strerror(errno));

	flags = device_get_flags(name);
	flags |= IFF_UP | IFF_RUNNING;
	device_set_flags(name, flags);

	return fd;
}

ssize_t read_or_die(int fd, void *buf, size_t len)
{
	ssize_t ret = read(fd, buf, len);
	if (unlikely(ret < 0)) {
		if (errno == EPIPE)
			die();
		panic("Cannot read from descriptor! %s.\n", strerror(errno));
	}

	return ret;
}

ssize_t write_or_die(int fd, const void *buf, size_t len)
{
	ssize_t ret = write(fd, buf, len);
	if (unlikely(ret < 0)) {
		if (errno == EPIPE)
			die();
		panic("Cannot write to descriptor! %s.", strerror(errno));
	}

	return ret;
}

int read_blob_or_die(const char *file, void *blob, size_t count)
{
	int fd, ret;

	fd = open_or_die(file, O_RDONLY);
	ret = read_or_die(fd, blob, count);
	close(fd);

	return ret;
}

int write_blob_or_die(const char *file, const void *blob, size_t count)
{
	int fd, ret;

	fd = open_or_die_m(file, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	ret = write_or_die(fd, blob, count);
	fdatasync(fd);
	close(fd);

	return ret;
}

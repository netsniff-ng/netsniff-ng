#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>

#include "ioexact.h"

extern volatile sig_atomic_t sigint;

ssize_t read_exact(int fd, void *buf, size_t len, bool mayexit)
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

ssize_t write_exact(int fd, void *buf, size_t len, bool mayexit)
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

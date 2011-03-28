/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef POLL_H
#define POLL_H

#define _GNU_SOURCE
#include <poll.h>
#include <errno.h>
#include <sys/poll.h>
#include <sys/socket.h>

#include "die.h"

#ifndef POLLRDNORM
# define POLLRDNORM 0x0040
#endif
#ifndef POLLWRNORM
# define POLLWRNORM 0x0100
#endif
#ifndef POLLRDHUP
# define POLLRDHUP  0x2000
#endif

#define POLL_NEXT_PKT 0
#define POLL_MOVE_OUT 1

static inline void prepare_polling(int sock, struct pollfd *pfd)
{
	memset(pfd, 0, sizeof(*pfd));

	pfd->fd = sock;
	pfd->revents = 0;
	pfd->events = POLLIN | POLLRDNORM | POLLERR;
}

static inline int poll_error_maybe_die(int sock, struct pollfd *pfd)
{
	if ((pfd->revents & (POLLHUP | POLLRDHUP | POLLERR | POLLNVAL)) == 0)
		return POLL_NEXT_PKT;

	if (pfd->revents & (POLLHUP | POLLRDHUP))
		error_and_die(EXIT_FAILURE, "Hangup on socket occured!\n");

	if (pfd->revents & POLLERR) {
		int tmp;

		errno = 0;
		/* recv is more specififc on the error */
		if (recv(sock, &tmp, sizeof(tmp), MSG_PEEK) >= 0)
			return POLL_NEXT_PKT;

		if (errno == ENETDOWN)
			error_and_die(EXIT_FAILURE, "Interface went down!\n");
		return POLL_MOVE_OUT;
	}

	if (pfd->revents & POLLNVAL) {
		whine("Invalid polling request on socket!\n");
		return POLL_MOVE_OUT;
	}

	return POLL_NEXT_PKT;
}

#endif /* POLL_H */

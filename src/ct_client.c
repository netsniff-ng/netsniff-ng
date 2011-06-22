/*
 * curvetun - the cipherspace wormhole creator
 * Part of the netsniff-ng project
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann <daniel@netsniff-ng.org>,
 * Subject to the GPL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <netinet/tcp.h>

#include "die.h"
#include "write_or_die.h"
#include "strlcpy.h"
#include "netdev.h"
#include "xmalloc.h"
#include "ct_client.h"
#include "curvetun.h"
#include "compiler.h"

/* XXX: remove */
static const char *rport = "6666";
static const char *rhost = "localhost";
static const char *scope = "eth0";

extern sig_atomic_t sigint;

static void handler_tun_to_net(int sfd, int dfd, int udp, char *buff, size_t len)
{
	ssize_t rlen, err;

	while ((rlen = read(sfd, buff, len)) > 0) {
		if (!udp) {
			err = write(dfd, &rlen, sizeof(rlen));
			err = write_exact(dfd, buff, rlen);
		} else {
			err = write(dfd, buff, rlen);
			if (err < 0)
				perror("write to network");
		}
	}
}

static void handler_net_to_tun(int sfd, int dfd, int udp, char *buff, size_t len)
{
	ssize_t rlen, err;
	struct sockaddr_storage sa;
	socklen_t sa_len;

	while (1) {
		if (!udp) {
			err = read(sfd, &rlen, sizeof(rlen));
			err = read_exact(sfd, buff, rlen);
		} else {
			sa_len = sizeof(sa);
			memset(&sa, 0, sa_len);

			rlen = recvfrom(sfd, buff, len, 0, (struct sockaddr *)
					&sa, &sa_len);
		}

		if (rlen <= 0)
			break;

		err = write(dfd, buff, rlen);
		if (err < 0)
			perror("write to tunnel");
	}
}

int client_main(int port, int udp)
{
	int fd = -1, tunfd;
	int err, ret, try = 1, i, one;
	struct addrinfo hints, *ahead, *ai;
	struct sockaddr_in6 *saddr6;
	struct pollfd fds[2];
	char *buff;
	size_t blen = 10000; //XXX

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = udp ? SOCK_DGRAM : SOCK_STREAM;
	hints.ai_protocol = udp ? IPPROTO_UDP : IPPROTO_TCP;

	ret = getaddrinfo(rhost, rport, &hints, &ahead);
	if (ret < 0)
		panic("Cannot get address info!\n");

	for (ai = ahead; ai != NULL && fd < 0; ai = ai->ai_next) {
		if (ai->ai_family == PF_INET6) {
			saddr6 = (struct sockaddr_in6 *) ai->ai_addr;
			if (saddr6->sin6_scope_id == 0) {
				saddr6->sin6_scope_id = device_ifindex(scope);
				info("Scope set to %d!\n",
				     saddr6->sin6_scope_id);
			}
		}
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0)
			continue;
		ret = connect(fd, ai->ai_addr, ai->ai_addrlen);
		if (ret < 0) {
			whine("Cannot connect to remote, try %d: %s!\n",
			      try++, strerror(errno));
			close(fd);
			fd = -1;
			continue;
		}
		one = 1;
		setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
		if (!udp) {
			one = 1;
			setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one,
				   sizeof(one));
		}
	}

	freeaddrinfo(ahead);
	if (fd < 0)
		panic("Cannot create socket!\n");

	tunfd = tun_open_or_die(DEVNAME_CLIENT);

	set_nonblocking(fd);
	set_nonblocking(tunfd);

	memset(fds, 0, sizeof(fds));
	fds[0].fd = fd;
	fds[1].fd = tunfd;
	fds[0].events = POLLIN;
	fds[1].events = POLLIN;

	buff = xmalloc(blen);

	while (likely(!sigint)) {
		poll(fds, 2, -1);
		for (i = 0; i < 2; ++i) {
			if (fds[i].fd == tunfd)
				handler_tun_to_net(tunfd, fd, udp, buff, blen);
			else
				handler_net_to_tun(fd, tunfd, udp, buff, blen);
		}
	}

	err = write(fd, EXIT_SEQ, strlen(EXIT_SEQ) + 1);
	xfree(buff);

	close(fd);
	close(tunfd);

	return 0;
}


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
#include <netinet/udp.h>

#include "die.h"
#include "write_or_die.h"
#include "strlcpy.h"
#include "deflate.h"
#include "netdev.h"
#include "xmalloc.h"
#include "curvetun.h"
#include "compiler.h"

/* XXX: remove */
static const char *rport = "6666";
static const char *rhost = "localhost";
static const char *scope = "eth0";

extern sig_atomic_t sigint;

static void handler_udp_tun_to_net(int sfd, int dfd, struct z_struct *z,
				   char *buff, size_t len)
{
	int state;
	char *pbuff;
	ssize_t rlen, err, plen;
	struct ct_proto *hdr;

	errno = 0;
	while ((rlen = read(sfd, buff + sizeof(struct ct_proto),
			    len - sizeof(struct ct_proto))) > 0) {

		hdr = (struct ct_proto *) buff;
		hdr->canary = htons(CANARY);
		hdr->flags = 0;

		plen = z_deflate(z, buff + sizeof(struct ct_proto), rlen, &pbuff);
		if (plen < 0) {
			perror("UDP tunnel deflate error");
			continue;
		}

		hdr->payload = htons((uint16_t) plen);

		state = 1;
		setsockopt(dfd, IPPROTO_UDP, UDP_CORK, &state, sizeof(state));

		err = write_exact(dfd, hdr, sizeof(struct ct_proto), 0);
		if (err < 0)
			perror("Error writing tunnel data to net");

		err = write_exact(dfd, pbuff, plen, 0);
		if (err < 0)
			perror("Error writing tunnel data to net");

		state = 0;
		setsockopt(dfd, IPPROTO_UDP, UDP_CORK, &state, sizeof(state));

		errno = 0;
	}
}

static void handler_udp_net_to_tun(int sfd, int dfd, struct z_struct *z,
				   char *buff, size_t len)
{
	char *pbuff;
	ssize_t rlen, err, plen;
	struct ct_proto *hdr;
	struct sockaddr_storage naddr;
	socklen_t nlen;

	nlen = sizeof(naddr);
	memset(&naddr, 0, sizeof(naddr));

	errno = 0;
	while ((rlen = recvfrom(sfd, buff, len, 0, (struct sockaddr *) &naddr,
				&nlen)) > 0) {
		hdr = (struct ct_proto *) buff;

		if (unlikely(rlen < sizeof(struct ct_proto)))
			goto close;
		if (unlikely(rlen - sizeof(*hdr) != ntohs(hdr->payload)))
			goto close;
		if (unlikely(ntohs(hdr->canary) != CANARY))
			goto close;
		if (unlikely(ntohs(hdr->payload) == 0))
			goto close;
		if (hdr->flags & PROTO_FLAG_EXIT)
			goto close;

		plen = z_inflate(z, buff + sizeof(struct ct_proto),
				 rlen - sizeof(struct ct_proto), &pbuff);
		if (plen < 0) {
			perror("UDP net inflate error");
			continue;
		}

		err = write(dfd, pbuff, plen);
		if (err < 0)
			perror("Error writing net data to tunnel");

		errno = 0;
	}

	return;
close:
	sigint = 1;
}

static void handler_tcp_tun_to_net(int sfd, int dfd, struct z_struct *z,
				   char *buff, size_t len)
{
	int state;
	char *pbuff;
	ssize_t rlen, err, plen;
	struct ct_proto *hdr;

	errno = 0;
	while ((rlen = read(sfd, buff + sizeof(struct ct_proto),
			    len - sizeof(struct ct_proto))) > 0) {

		hdr = (struct ct_proto *) buff;
		hdr->canary = htons(CANARY);
		hdr->flags = 0;

		plen = z_deflate(z, buff + sizeof(struct ct_proto), rlen, &pbuff);
		if (plen < 0) {
			perror("TCP tunnel deflate error");
			continue;
		}

		hdr->payload = htons((uint16_t) plen);

		state = 1;
		setsockopt(dfd, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));

		err = write_exact(dfd, hdr, sizeof(struct ct_proto), 0);
		if (err < 0)
			perror("Error writing tunnel data to net");

		err = write_exact(dfd, pbuff, plen, 0);
		if (err < 0)
			perror("Error writing tunnel data to net");

		state = 0;
		setsockopt(dfd, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));

		errno = 0;
	}
}

extern ssize_t handler_tcp_read(int fd, char *buff, size_t len);

static void handler_tcp_net_to_tun(int sfd, int dfd, struct z_struct *z,
				   char *buff, size_t len)
{
	char *pbuff;
	ssize_t rlen, err, plen;
	struct ct_proto *hdr;

	errno = 0;
	while ((rlen = handler_tcp_read(sfd, buff, len)) > 0) {
		hdr = (struct ct_proto *) buff;

		if (unlikely(rlen < sizeof(struct ct_proto)))
			goto close;
		if (unlikely(rlen - sizeof(*hdr) != ntohs(hdr->payload)))
			goto close;
		if (unlikely(ntohs(hdr->canary) != CANARY))
			goto close;
		if (unlikely(ntohs(hdr->payload) == 0))
			goto close;
		if (hdr->flags & PROTO_FLAG_EXIT)
			goto close;

		plen = z_inflate(z, buff + sizeof(struct ct_proto),
				 rlen - sizeof(struct ct_proto), &pbuff);
		if (plen < 0) {
			perror("TCP net inflate error");
			continue;
		}

		err = write(dfd, pbuff, plen);
		if (err < 0)
			perror("Error writing net data to tunnel");

		errno = 0;
	}

	return;
close:
	sigint = 1;
}

static void notify_close(int fd)
{
	ssize_t err;
	struct ct_proto hdr;

	memset(&hdr, 0, sizeof(hdr));
	hdr.flags |= PROTO_FLAG_EXIT;
	hdr.payload = 0;
	hdr.canary = htons(CANARY);

	err = write_exact(fd, &hdr, sizeof(hdr), 0);
	if (err < 0)
		perror("Error writing close");
}

int client_main(int port, int udp)
{
	int fd = -1, tunfd;
	int ret, try = 1, i, one;
	struct addrinfo hints, *ahead, *ai;
	struct sockaddr_in6 *saddr6;
	struct pollfd fds[2];
	struct z_struct *z;
	char *buff;
	size_t blen = TUNBUFF_SIZ; //FIXME

	z = xmalloc(sizeof(struct z_struct));
	ret = z_alloc_or_maybe_die(z, Z_DEFAULT_COMPRESSION);
	if (ret < 0)
		panic("Cannot init zLib!\n");

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

	info("Ready!\n");

	while (likely(!sigint)) {
		poll(fds, 2, -1);
		for (i = 0; i < 2; ++i) {
			if ((fds[i].revents & POLLIN) != POLLIN)
				continue;
			if (fds[i].fd == tunfd) {
				if (udp)
					handler_udp_tun_to_net(tunfd, fd, z,
							       buff, blen);
				else
					handler_tcp_tun_to_net(tunfd, fd, z,
							       buff, blen);
			} else if (fds[i].fd == fd) {
				if (udp)
					handler_udp_net_to_tun(fd, tunfd, z,
							       buff, blen);
				else
					handler_tcp_net_to_tun(fd, tunfd, z,
							       buff, blen);
			}
		}
	}

	info("Shutting down!\n");

	notify_close(fd);
	xfree(buff);

	close(fd);
	close(tunfd);

	z_free(z);
	xfree(z);

	return 0;
}


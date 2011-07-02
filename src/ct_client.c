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
#include "curve.h"
#include "netdev.h"
#include "xmalloc.h"
#include "curvetun.h"
#include "servmgmt.h"
#include "usermgmt.h"
#include "compiler.h"

extern sig_atomic_t sigint;

static void handler_udp_tun_to_net(int sfd, int dfd, struct z_struct *z,
				   struct curve25519_proto *p,
				   struct curve25519_struct *c,
				   char *buff, size_t len)
{
	int state;
	char *pbuff, *cbuff;
	ssize_t rlen, err, plen, clen;
	struct ct_proto *hdr;

	errno = 0;
	while ((rlen = read(sfd, buff + sizeof(struct ct_proto),
			    len - sizeof(struct ct_proto))) > 0) {

		hdr = (struct ct_proto *) buff;
		hdr->canary = htons(CANARY);
		hdr->flags = 0;

		plen = z_deflate(z, buff + sizeof(struct ct_proto), rlen, &pbuff);
		if (plen < 0)
			panic("UDP tunnel deflate error!\n");
		clen = curve25519_encode(c, p, (unsigned char *) pbuff, plen,
					 (unsigned char **) &cbuff);
		if (clen <= 0)
			panic("UDP tunnel encrypt error!\n");

		hdr->payload = htons((uint16_t) clen);

		state = 1;
		setsockopt(dfd, IPPROTO_UDP, UDP_CORK, &state, sizeof(state));

		err = write_exact(dfd, hdr, sizeof(struct ct_proto), 0);
		if (err < 0)
			perror("Error writing tunnel data to net");

		err = write_exact(dfd, cbuff, clen, 0);
		if (err < 0)
			perror("Error writing tunnel data to net");

		state = 0;
		setsockopt(dfd, IPPROTO_UDP, UDP_CORK, &state, sizeof(state));

		errno = 0;
	}
}

static void handler_udp_net_to_tun(int sfd, int dfd, struct z_struct *z,
				   struct curve25519_proto *p,
				   struct curve25519_struct *c,
				   char *buff, size_t len)
{
	char *pbuff, *cbuff;
	ssize_t rlen, err, plen, clen;
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

		clen = curve25519_decode(c, p, (unsigned char *) buff +
					 sizeof(struct ct_proto),
					 rlen - sizeof(struct ct_proto),
					 (unsigned char **) &cbuff);
		if (clen <= 0)
			panic("UDP net decrypt error!\n");
		plen = z_inflate(z, cbuff, clen, &pbuff);
		if (plen < 0)
			panic("UDP net inflate error!\n");

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
				   struct curve25519_proto *p,
				   struct curve25519_struct *c,
				   char *buff, size_t len)
{
	int state;
	char *pbuff, *cbuff;
	ssize_t rlen, err, plen, clen;
	struct ct_proto *hdr;

	errno = 0;
	while ((rlen = read(sfd, buff + sizeof(struct ct_proto),
			    len - sizeof(struct ct_proto))) > 0) {

		hdr = (struct ct_proto *) buff;
		hdr->canary = htons(CANARY);
		hdr->flags = 0;

		plen = z_deflate(z, buff + sizeof(struct ct_proto), rlen, &pbuff);
		if (plen < 0)
			panic("TCP tunnel deflate error!\n");
		clen = curve25519_encode(c, p, (unsigned char *) pbuff, plen,
					 (unsigned char **) &cbuff);
		if (clen <= 0)
			panic("TCP tunnel encrypt error!\n");

		hdr->payload = htons((uint16_t) clen);

		state = 1;
		setsockopt(dfd, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));

		err = write_exact(dfd, hdr, sizeof(struct ct_proto), 0);
		if (err < 0)
			perror("Error writing tunnel data to net");

		err = write_exact(dfd, cbuff, clen, 0);
		if (err < 0)
			perror("Error writing tunnel data to net");

		state = 0;
		setsockopt(dfd, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));

		errno = 0;
	}
}

extern ssize_t handler_tcp_read(int fd, char *buff, size_t len);

static void handler_tcp_net_to_tun(int sfd, int dfd, struct z_struct *z,
				   struct curve25519_proto *p,
				   struct curve25519_struct *c,
				   char *buff, size_t len)
{
	char *pbuff, *cbuff;
	ssize_t rlen, err, plen, clen;
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

		clen = curve25519_decode(c, p, (unsigned char *) buff +
					 sizeof(struct ct_proto),
					 rlen - sizeof(struct ct_proto),
					 (unsigned char **) &cbuff);
		if (clen <= 0)
			panic("TCP net decrypt error!\n");
		plen = z_inflate(z, cbuff, clen, &pbuff);
		if (plen < 0)
			panic("TCP net inflate error!\n");

		err = write(dfd, pbuff, plen);
		if (err < 0)
			perror("Error writing net data to tunnel");

		errno = 0;
	}

	return;
close:
	sigint = 1;
}

static void notify_init(int fd, int udp, struct curve25519_proto *p,
			struct curve25519_struct *c, char *home)
{
	int state, fd2;
	ssize_t err;
	size_t clen;
	struct ct_proto hdr;
	struct username_struct us;
	char username[256], path[512], *cbuff;

	memset(&hdr, 0, sizeof(hdr));
	hdr.flags |= PROTO_FLAG_INIT;
	hdr.canary = htons(CANARY);

	memset(path, 0, sizeof(path));
	snprintf(path, sizeof(path), "%s/%s", home, FILE_USERNAM);
	path[sizeof(path) - 1] = 0;
	memset(username, 0, sizeof(username));

	fd2 = open_or_die(path, O_RDONLY);
	err = read(fd2, username, sizeof(username));
	username[sizeof(username) - 1] = 0;
	close(fd2);

	err = username_msg(username, strlen(username) + 1,
			   (char *) &us, sizeof(us));
	if (err)
		panic("Cannot create init message!\n");
	clen = curve25519_encode(c, p, (unsigned char *) &us, sizeof(us),
				 (unsigned char **) &cbuff);
	if (clen <= 0)
		panic("Init encrypt error!\n");

	hdr.payload = htons((uint16_t) clen);

	state = 1;
	setsockopt(fd, udp ? IPPROTO_UDP : IPPROTO_TCP,
		   udp ? UDP_CORK : TCP_CORK, &state, sizeof(state));

	err = write_exact(fd, &hdr, sizeof(struct ct_proto), 0);
	if (err < 0)
		perror("Error writing init data to net");

	err = write_exact(fd, cbuff, clen, 0);
	if (err < 0)
		perror("Error writing init data to net");

	state = 0;
	setsockopt(fd, udp ? IPPROTO_UDP : IPPROTO_TCP,
		   udp ? UDP_CORK : TCP_CORK, &state, sizeof(state));
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

int client_main(char *home, char *dev, char *host, char *port, int udp)
{
	int fd = -1, tunfd;
	int ret, try = 1, i, one;
	struct addrinfo hints, *ahead, *ai;
	struct sockaddr_in6 *saddr6;
	struct pollfd fds[2];
	struct z_struct *z;
	struct curve25519_proto *p;
	struct curve25519_struct *c;
	char *buff;
	size_t blen = TUNBUFF_SIZ; //FIXME

	z = xmalloc(sizeof(struct z_struct));
	ret = z_alloc_or_maybe_die(z, Z_DEFAULT_COMPRESSION);
	if (ret < 0)
		panic("Cannot init zLib!\n");

	c = xmalloc(sizeof(struct curve25519_struct));
	ret = curve25519_alloc_or_maybe_die(c);
	if (ret < 0)
		panic("Cannot init curve!\n");

	p = get_serv_store_entry_proto_inf();
	if (!p)
		panic("Cannot proto!\n");

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = udp ? SOCK_DGRAM : SOCK_STREAM;
	hints.ai_protocol = udp ? IPPROTO_UDP : IPPROTO_TCP;

	ret = getaddrinfo(host, port, &hints, &ahead);
	if (ret < 0)
		panic("Cannot get address info!\n");

	for (ai = ahead; ai != NULL && fd < 0; ai = ai->ai_next) {
		if (ai->ai_family == PF_INET6)
			saddr6 = (struct sockaddr_in6 *) ai->ai_addr;
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

	tunfd = tun_open_or_die(dev ? dev : DEVNAME_CLIENT);

	set_nonblocking(fd);
	set_nonblocking(tunfd);

	memset(fds, 0, sizeof(fds));
	fds[0].fd = fd;
	fds[1].fd = tunfd;
	fds[0].events = POLLIN;
	fds[1].events = POLLIN;

	buff = xmalloc(blen);

	notify_init(fd, udp, p, c, home);
	info("Ready!\n");

	while (likely(!sigint)) {
		poll(fds, 2, -1);
		for (i = 0; i < 2; ++i) {
			if ((fds[i].revents & POLLIN) != POLLIN)
				continue;
			if (fds[i].fd == tunfd) {
				if (udp)
					handler_udp_tun_to_net(tunfd, fd, z, p,
							       c, buff, blen);
				else
					handler_tcp_tun_to_net(tunfd, fd, z, p,
							       c, buff, blen);
			} else if (fds[i].fd == fd) {
				if (udp)
					handler_udp_net_to_tun(fd, tunfd, z, p,
							       c, buff, blen);
				else
					handler_tcp_net_to_tun(fd, tunfd, z, p,
							       c, buff, blen);
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
	curve25519_free(c);
	xfree(c);

	return 0;
}


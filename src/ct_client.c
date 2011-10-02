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
#include <syslog.h>
#include <limits.h>
#include <assert.h>
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
#include "curve.h"
#include "mtrand.h"
#include "netdev.h"
#include "xmalloc.h"
#include "curvetun.h"
#include "servmgmt.h"
#include "usermgmt.h"
#include "compiler.h"
#include "crypto_auth_hmacsha512256.h"

extern sig_atomic_t sigint;

static void handler_udp_tun_to_net(int sfd, int dfd, struct curve25519_proto *p,
				   struct curve25519_struct *c, char *buff,
				   size_t len)
{
	int state;
	char *cbuff;
	ssize_t rlen, err, clen;
	struct ct_proto *hdr;
	size_t off = sizeof(struct ct_proto) + crypto_box_zerobytes;

	if (!buff || len <= off) {
		errno = EINVAL;
		return;
	}

	errno = 0;
	while ((rlen = read(sfd, buff + off, len - off)) > 0) {
		hdr = (struct ct_proto *) buff;
		memset(hdr, 0, sizeof(*hdr));
		hdr->flags = 0;

		clen = curve25519_encode(c, p, (unsigned char *) (buff + off -
					 crypto_box_zerobytes), (rlen +
					 crypto_box_zerobytes), (unsigned char **)
					 &cbuff);
		if (unlikely(clen <= 0)) {
			syslog(LOG_ERR, "UDP tunnel encrypt error!\n");
			goto close;
		}

		hdr->payload = htons((uint16_t) clen);

		state = 1;
		setsockopt(dfd, IPPROTO_UDP, UDP_CORK, &state, sizeof(state));

		err = write_exact(dfd, hdr, sizeof(struct ct_proto), 0);
		if (unlikely(err < 0))
			syslog(LOG_ERR, "Error writing tunnel data to net: %s\n",
			       strerror(errno));

		err = write_exact(dfd, cbuff, clen, 0);
		if (unlikely(err < 0))
			syslog(LOG_ERR, "Error writing tunnel data to net: %s\n",
			       strerror(errno));

		state = 0;
		setsockopt(dfd, IPPROTO_UDP, UDP_CORK, &state, sizeof(state));

		errno = 0;
	}

	return;
close:
	sigint = 1;
}

static void handler_udp_net_to_tun(int sfd, int dfd, struct curve25519_proto *p,
				   struct curve25519_struct *c, char *buff,
				   size_t len)
{
	char *cbuff;
	ssize_t rlen, err, clen;
	struct ct_proto *hdr;
	struct sockaddr_storage naddr;
	socklen_t nlen = sizeof(naddr);

	if (!buff || !len) {
		errno = EINVAL;
		return;
	}

	memset(&naddr, 0, sizeof(naddr));

	errno = 0;
	while ((rlen = recvfrom(sfd, buff, len, 0, (struct sockaddr *) &naddr,
				&nlen)) > 0) {
		hdr = (struct ct_proto *) buff;

		if (unlikely(rlen < sizeof(struct ct_proto)))
			goto close;
		if (unlikely(rlen - sizeof(*hdr) != ntohs(hdr->payload)))
			goto close;
		if (unlikely(ntohs(hdr->payload) == 0))
			goto close;
		if (hdr->flags & PROTO_FLAG_EXIT)
			goto close;

		clen = curve25519_decode(c, p, (unsigned char *) buff +
					 sizeof(struct ct_proto),
					 rlen - sizeof(struct ct_proto),
					 (unsigned char **) &cbuff, NULL);
		if (unlikely(clen <= 0)) {
			syslog(LOG_ERR, "UDP net decrypt error!\n");
			goto close;
		}
                cbuff += crypto_box_zerobytes;
                clen -= crypto_box_zerobytes;
		err = write(dfd, cbuff, clen);
		if (unlikely(err < 0))
			syslog(LOG_ERR, "Error writing net data to tunnel: %s\n",
			       strerror(errno));

		errno = 0;
	}

	return;
close:
	sigint = 1;
}

static void handler_tcp_tun_to_net(int sfd, int dfd, struct curve25519_proto *p,
				   struct curve25519_struct *c, char *buff,
				   size_t len)
{
	int state;
	char *cbuff;
	ssize_t rlen, err, clen;
	struct ct_proto *hdr;
	size_t off = sizeof(struct ct_proto) + crypto_box_zerobytes;

	if (!buff || len <= off) {
		errno = EINVAL;
		return;
	}

	errno = 0;
	while ((rlen = read(sfd, buff + off, len - off)) > 0) {
		hdr = (struct ct_proto *) buff;
		memset(hdr, 0, sizeof(*hdr));
		hdr->flags = 0;

		clen = curve25519_encode(c, p, (unsigned char *) (buff + off -
					 crypto_box_zerobytes), (rlen +
					 crypto_box_zerobytes), (unsigned char **)
					 &cbuff);
		if (unlikely(clen <= 0)) {
			syslog(LOG_ERR, "TCP tunnel encrypt error!\n");
			goto close;
		}

		hdr->payload = htons((uint16_t) clen);

		state = 1;
		setsockopt(dfd, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));

		err = write_exact(dfd, hdr, sizeof(struct ct_proto), 0);
		if (unlikely(err < 0))
			syslog(LOG_ERR, "Error writing tunnel data to net: %s\n",
			       strerror(errno));

		err = write_exact(dfd, cbuff, clen, 0);
		if (unlikely(err < 0))
			syslog(LOG_ERR, "Error writing tunnel data to net: %s\n",
			       strerror(errno));

		state = 0;
		setsockopt(dfd, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));

		errno = 0;
	}

	return;
close:
	sigint = 1;
}

extern ssize_t handler_tcp_read(int fd, char *buff, size_t len);

static void handler_tcp_net_to_tun(int sfd, int dfd, struct curve25519_proto *p,
				   struct curve25519_struct *c, char *buff,
				   size_t len)
{
	char *cbuff;
	ssize_t rlen, err, clen;
	struct ct_proto *hdr;

	if (!buff || !len) {
		errno = EINVAL;
		return;
	}

	errno = 0;
	while ((rlen = handler_tcp_read(sfd, buff, len)) > 0) {
		hdr = (struct ct_proto *) buff;

		if (unlikely(rlen < sizeof(struct ct_proto)))
			goto close;
		if (unlikely(rlen - sizeof(*hdr) != ntohs(hdr->payload)))
			goto close;
		if (unlikely(ntohs(hdr->payload) == 0))
			goto close;
		if (hdr->flags & PROTO_FLAG_EXIT)
			goto close;

		clen = curve25519_decode(c, p, (unsigned char *) buff +
					 sizeof(struct ct_proto),
					 rlen - sizeof(struct ct_proto),
					 (unsigned char **) &cbuff, NULL);
		if (unlikely(clen <= 0)) {
			syslog(LOG_ERR, "TCP net decrypt error!\n");
			goto close;
		}
		cbuff += crypto_box_zerobytes;
		clen -= crypto_box_zerobytes;
		err = write(dfd, cbuff, clen);
		if (unlikely(err < 0))
			syslog(LOG_ERR, "Error writing net data to tunnel: %s\n",
			       strerror(errno));

		errno = 0;
	}

	return;
close:
	sigint = 1;
}

static void notify_init(int fd, int udp, struct curve25519_proto *p,
			struct curve25519_struct *c, char *home)
{
	int state, fd2, i;
	ssize_t err, clen;
	size_t us_len, msg_len, pad;
	struct ct_proto hdr;
	char username[256], path[PATH_MAX], *us, *cbuff, *msg;
	unsigned char auth[crypto_auth_hmacsha512256_BYTES], *token;

	mt_init_by_random_device();

	memset(&hdr, 0, sizeof(hdr));
	hdr.flags |= PROTO_FLAG_INIT;

	memset(path, 0, sizeof(path));
	slprintf(path, sizeof(path), "%s/%s", home, FILE_USERNAM);
	memset(username, 0, sizeof(username));

	fd2 = open_or_die(path, O_RDONLY);
	err = read(fd2, username, sizeof(username));
	username[sizeof(username) - 1] = 0;
	close(fd2);

	token = get_serv_store_entry_auth_token();
	if (!token)
		syslog_panic("Cannot find auth token for server!\n");

	us_len = sizeof(struct username_struct) + crypto_box_zerobytes;
	us = xzmalloc(us_len);
	err = username_msg(username, strlen(username) + 1,
			   us + crypto_box_zerobytes,
			   us_len - crypto_box_zerobytes);
	if (unlikely(err))
		syslog_panic("Cannot create init message!\n");
	clen = curve25519_encode(c, p, (unsigned char *) us, us_len,
				 (unsigned char **) &cbuff);
	if (unlikely(clen <= 0))
		syslog_panic("Init encrypt error!\n");
	err = crypto_auth_hmacsha512256(auth, (unsigned char *) cbuff, clen, token);
	if (unlikely(err))
		syslog_panic("Cannot create init hmac message!\n");

	assert(132 == clen + sizeof(auth));

	pad = mt_rand_int32() % 200;
	msg_len = clen + sizeof(auth) + pad;
	msg = xzmalloc(msg_len);
	memcpy(msg, auth, sizeof(auth));
	memcpy(msg + sizeof(auth), cbuff, clen);
	for (i = sizeof(auth) + clen; i < msg_len; ++i)
		msg[i] = (uint8_t) mt_rand_int32();
	hdr.payload = htons((uint16_t) msg_len);

	state = 1;
	setsockopt(fd, udp ? IPPROTO_UDP : IPPROTO_TCP,
		   udp ? UDP_CORK : TCP_CORK, &state, sizeof(state));

	err = write_exact(fd, &hdr, sizeof(struct ct_proto), 0);
	if (unlikely(err < 0))
		syslog(LOG_ERR, "Error writing init data to net: %s\n",
		       strerror(errno));

	err = write_exact(fd, msg, msg_len, 0);
	if (unlikely(err < 0))
		syslog(LOG_ERR, "Error writing init data to net: %s\n",
		       strerror(errno));

	state = 0;
	setsockopt(fd, udp ? IPPROTO_UDP : IPPROTO_TCP,
		   udp ? UDP_CORK : TCP_CORK, &state, sizeof(state));
	xfree(msg);
	xfree(us);
}

static void notify_close(int fd)
{
	ssize_t err;
	struct ct_proto hdr;

	memset(&hdr, 0, sizeof(hdr));
	hdr.flags |= PROTO_FLAG_EXIT;
	hdr.payload = 0;

	err = write_exact(fd, &hdr, sizeof(hdr), 0);
	if (unlikely(err < 0))
		syslog(LOG_ERR, "Error writing close: %s\n",
		       strerror(errno));
}

int client_main(char *home, char *dev, char *host, char *port, int udp)
{
	int fd = -1, tunfd;
	int ret, try = 1, i, one, mtu;
	struct addrinfo hints, *ahead, *ai;
	struct sockaddr_in6 *saddr6;
	struct pollfd fds[2];
	struct curve25519_proto *p;
	struct curve25519_struct *c;
	char *buff;
	size_t blen = TUNBUFF_SIZ; //FIXME

	openlog("curvetun", LOG_PID | LOG_CONS | LOG_NDELAY, LOG_DAEMON);
	syslog(LOG_INFO, "curvetun client booting!\n");

	c = xmalloc(sizeof(struct curve25519_struct));
	ret = curve25519_alloc_or_maybe_die(c);
	if (ret < 0)
		syslog_panic("Cannot init curve!\n");

	p = get_serv_store_entry_proto_inf();
	if (!p)
		syslog_panic("Cannot proto!\n");

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = udp ? SOCK_DGRAM : SOCK_STREAM;
	hints.ai_protocol = udp ? IPPROTO_UDP : IPPROTO_TCP;
	hints.ai_flags = AI_NUMERICSERV;

	ret = getaddrinfo(host, port, &hints, &ahead);
	if (ret < 0)
		syslog_panic("Cannot get address info!\n");

	for (ai = ahead; ai != NULL && fd < 0; ai = ai->ai_next) {
		if (ai->ai_family == PF_INET6)
			saddr6 = (struct sockaddr_in6 *) ai->ai_addr;
		fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (fd < 0)
			continue;
		ret = connect(fd, ai->ai_addr, ai->ai_addrlen);
		if (ret < 0) {
			syslog(LOG_ERR, "Cannot connect to remote, try %d: %s!\n",
			       try++, strerror(errno));
			close(fd);
			fd = -1;
			continue;
		}
		one = 1;
		setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
		mtu = IP_PMTUDISC_DONT;
		setsockopt(fd, SOL_IP, IP_MTU_DISCOVER, &mtu, sizeof(mtu));
		if (!udp) {
			one = 1;
			setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one,
				   sizeof(one));
		}
	}

	freeaddrinfo(ahead);
	if (fd < 0)
		syslog_panic("Cannot create socket!\n");

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
	syslog(LOG_INFO, "curvetun client ready!\n");

	while (likely(!sigint)) {
		poll(fds, 2, -1);
		for (i = 0; i < 2; ++i) {
			if ((fds[i].revents & POLLIN) != POLLIN)
				continue;
			if (fds[i].fd == tunfd) {
				if (udp)
					handler_udp_tun_to_net(tunfd, fd, p, c,
							       buff, blen);
				else
					handler_tcp_tun_to_net(tunfd, fd, p, c,
							       buff, blen);
			} else if (fds[i].fd == fd) {
				if (udp)
					handler_udp_net_to_tun(fd, tunfd, p, c,
							       buff, blen);
				else
					handler_tcp_net_to_tun(fd, tunfd, p, c,
							       buff, blen);
			}
		}
	}

	syslog(LOG_INFO, "curvetun client prepare shut down!\n");
	notify_close(fd);

	xfree(buff);
	close(fd);
	close(tunfd);
	curve25519_free(c);
	xfree(c);

	syslog(LOG_INFO, "curvetun client shut down!\n");
	closelog();

	return 0;
}


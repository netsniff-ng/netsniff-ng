/*
 * curvetun - the cipherspace wormhole creator
 * Part of the netsniff-ng project
 * Copyright 2011 Daniel Borkmann <daniel@netsniff-ng.org>,
 * Subject to the GPL, version 2.
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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <poll.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_tun.h>

#include "built_in.h"
#include "die.h"
#include "str.h"
#include "sock.h"
#include "ioops.h"
#include "curve.h"
#include "xmalloc.h"
#include "corking.h"
#include "ioexact.h"
#include "curvetun.h"
#include "curvetun_mgmt.h"
#include "crypto.h"

extern volatile sig_atomic_t sigint;
static volatile sig_atomic_t closed_by_server = 0;

static void handler_udp_tun_to_net(int sfd, int dfd, struct curve25519_proto *p,
				   struct curve25519_struct *c, char *buff,
				   size_t len)
{
	char *cbuff;
	ssize_t rlen, clen;
	struct ct_proto *hdr;
	size_t off = sizeof(struct ct_proto) + crypto_box_zerobytes;

	if (!buff || len <= off)
		return;

	memset(buff, 0, len);
	while ((rlen = read(sfd, buff + off, len - off)) > 0) {
		hdr = (struct ct_proto *) buff;

		memset(hdr, 0, sizeof(*hdr));
		hdr->flags = 0;

		clen = curve25519_encode(c, p, (unsigned char *) (buff + off -
					 crypto_box_zerobytes), (rlen +
					 crypto_box_zerobytes), (unsigned char **)
					 &cbuff);
		if (unlikely(clen <= 0))
			goto close;

		hdr->payload = htons((uint16_t) clen);

		set_udp_cork(dfd);

		write_exact(dfd, hdr, sizeof(struct ct_proto), 0);
		write_exact(dfd, cbuff, clen, 0);

		set_udp_uncork(dfd);

		memset(buff, 0, len);
	}

	return;
close:
	closed_by_server = 1;
}

static void handler_udp_net_to_tun(int sfd, int dfd, struct curve25519_proto *p,
				   struct curve25519_struct *c, char *buff,
				   size_t len)
{
	char *cbuff;
	ssize_t rlen, clen;
	struct ct_proto *hdr;
	struct sockaddr_storage naddr;

	socklen_t nlen = sizeof(naddr);

	if (!buff || !len)
		return;

	memset(&naddr, 0, sizeof(naddr));
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
		if (unlikely(clen <= 0))
			goto close;

                cbuff += crypto_box_zerobytes;
                clen -= crypto_box_zerobytes;

		if (write(dfd, cbuff, clen)) { ; }
	}

	return;
close:
	closed_by_server = 1;
}

static void handler_tcp_tun_to_net(int sfd, int dfd, struct curve25519_proto *p,
				   struct curve25519_struct *c, char *buff,
				   size_t len)
{
	char *cbuff;
	ssize_t rlen, clen;
	struct ct_proto *hdr;
	size_t off = sizeof(struct ct_proto) + crypto_box_zerobytes;

	if (!buff || len <= off)
		return;

	memset(buff, 0, len);
	while ((rlen = read(sfd, buff + off, len - off)) > 0) {
		hdr = (struct ct_proto *) buff;

		memset(hdr, 0, sizeof(*hdr));
		hdr->flags = 0;

		clen = curve25519_encode(c, p, (unsigned char *) (buff + off -
					 crypto_box_zerobytes), (rlen +
					 crypto_box_zerobytes), (unsigned char **)
					 &cbuff);
		if (unlikely(clen <= 0))
			goto close;

		hdr->payload = htons((uint16_t) clen);

		set_tcp_cork(dfd);

		write_exact(dfd, hdr, sizeof(struct ct_proto), 0);
		write_exact(dfd, cbuff, clen, 0);

		set_tcp_uncork(dfd);

		memset(buff, 0, len);
	}

	return;
close:
	closed_by_server = 1;
}

extern ssize_t handler_tcp_read(int fd, char *buff, size_t len);

static void handler_tcp_net_to_tun(int sfd, int dfd, struct curve25519_proto *p,
				   struct curve25519_struct *c, char *buff,
				   size_t len)
{
	char *cbuff;
	ssize_t rlen, clen;
	struct ct_proto *hdr;

	if (!buff || !len)
		return;

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
		if (unlikely(clen <= 0))
			goto close;

		cbuff += crypto_box_zerobytes;
		clen -= crypto_box_zerobytes;

		if (write(dfd, cbuff, clen)) { ; }
	}

	return;
close:
	closed_by_server = 1;
}

static void notify_init(int fd, int udp, struct curve25519_proto *p,
			struct curve25519_struct *c, char *home)
{
	int fd2, i;
	ssize_t err, clen;
	size_t us_len, msg_len, pad;
	struct ct_proto hdr;
	char username[256], path[PATH_MAX], *us, *cbuff, *msg;
	unsigned char auth[crypto_auth_hmacsha512256_BYTES], *token;

	memset(&hdr, 0, sizeof(hdr));
	hdr.flags |= PROTO_FLAG_INIT;

	memset(path, 0, sizeof(path));
	slprintf(path, sizeof(path), "%s/%s", home, FILE_USERNAM);

	fd2 = open_or_die(path, O_RDONLY);

	memset(username, 0, sizeof(username));
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

	pad = ((uint32_t) secrand()) % 200;
	msg_len = clen + sizeof(auth) + pad;

	msg = xzmalloc(msg_len);
	memcpy(msg, auth, sizeof(auth));
	memcpy(msg + sizeof(auth), cbuff, clen);

	for (i = sizeof(auth) + clen; i < msg_len; ++i)
		msg[i] = (uint8_t) secrand();

	hdr.payload = htons((uint16_t) msg_len);

	set_sock_cork(fd, udp);

	write_exact(fd, &hdr, sizeof(struct ct_proto), 0);
	write_exact(fd, msg, msg_len, 0);

	set_sock_uncork(fd, udp);

	xfree(msg);
	xfree(us);
}

static void notify_close(int fd)
{
	struct ct_proto hdr;

	memset(&hdr, 0, sizeof(hdr));

	hdr.flags |= PROTO_FLAG_EXIT;
	hdr.payload = 0;

	write_exact(fd, &hdr, sizeof(hdr), 0);
}

int client_main(char *home, char *dev, char *host, char *port, int udp)
{
	int fd = -1, tunfd = 0, retry_server = 0;
	int ret, try = 1, i;
	struct addrinfo hints, *ahead, *ai;
	struct pollfd fds[2];
	struct curve25519_proto *p;
	struct curve25519_struct *c;
	char *buff;
	size_t blen = TUNBUFF_SIZ; //FIXME

retry:
	if (!retry_server) {
		openlog("curvetun", LOG_PID | LOG_CONS | LOG_NDELAY, LOG_DAEMON);
		syslog(LOG_INFO, "curvetun client booting!\n");
	}

	c = curve25519_tfm_alloc();
	p = get_serv_store_entry_proto_inf();
	if (!p)
		syslog_panic("Cannot proto!\n");

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = udp ? SOCK_DGRAM : SOCK_STREAM;
	hints.ai_protocol = udp ? IPPROTO_UDP : IPPROTO_TCP;
	hints.ai_flags = AI_NUMERICSERV;

	ret = getaddrinfo(host, port, &hints, &ahead);
	if (ret < 0) {
		syslog(LOG_ERR, "Cannot get address info! Retry!\n");
		curve25519_tfm_free(c);
		fd = -1;
		retry_server = 1;
		closed_by_server = 0;
		sleep(1);
		goto retry;
	}

	for (ai = ahead; ai != NULL && fd < 0; ai = ai->ai_next) {
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

		set_socket_keepalive(fd);
		set_mtu_disc_dont(fd);
		if (!udp)
			set_tcp_nodelay(fd);
	}

	freeaddrinfo(ahead);

	if (fd < 0) {
		syslog(LOG_ERR, "Cannot create socket! Retry!\n");
		curve25519_tfm_free(c);
		fd = -1;
		retry_server = 1;
		closed_by_server = 0;
		sleep(1);
		goto retry;
	}

	if (!retry_server)
		tunfd = tun_open_or_die(dev ? dev : DEVNAME_CLIENT,
					IFF_TUN | IFF_NO_PI);

	set_nonblocking_sloppy(fd);
	set_nonblocking_sloppy(tunfd);

	memset(fds, 0, sizeof(fds));
	fds[0].fd = fd;
	fds[1].fd = tunfd;
	fds[0].events = POLLIN;
	fds[1].events = POLLIN;

	buff = xmalloc_aligned(blen, 64);

	notify_init(fd, udp, p, c, home);

	syslog(LOG_INFO, "curvetun client ready!\n");

	while (likely(!sigint && !closed_by_server)) {
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

	if (!closed_by_server)
		notify_close(fd);

	xfree(buff);
	close(fd);
	curve25519_tfm_free(c);

	/* tundev still active */
	if (closed_by_server && !sigint) {
		syslog(LOG_ERR, "curvetun connection retry attempt!\n");
		fd = -1;
		retry_server = 1;
		closed_by_server = 0;
		sleep(1);
		goto retry;
	}

	close(tunfd);
	syslog(LOG_INFO, "curvetun client shut down!\n");
	closelog();

	return 0;
}

/*
 * curvetun - the cipherspace wormhole creator
 * Part of the netsniff-ng project
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann <daniel@netsniff-ng.org>,
 * Subject to the GPL.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <syslog.h>
#include <signal.h>
#include <netdb.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <arpa/inet.h>

#include "die.h"
#include "netdev.h"
#include "write_or_die.h"
#include "psched.h"
#include "xmalloc.h"
#include "curvetun.h"
#include "curve.h"
#include "compiler.h"
#include "usermgmt.h"
#include "deflate.h"
#include "cpusched.h"
#include "trie.h"

struct parent_info {
	int efd;
	int refd;
	int tunfd;
	int ipv4;
	int udp;
};

struct worker_struct {
	pthread_t trid;
	int efd[2];
	unsigned int cpu;
	struct parent_info parent;
	int (*handler)(int fd, const struct worker_struct *ws,
		       char *buff, size_t len);
	struct z_struct *z;
	struct curve25519_struct *c;
};

static struct worker_struct *threadpool = NULL;

extern sig_atomic_t sigint;

static int handler_udp_tun_to_net(int fd, const struct worker_struct *ws,
				  char *buff, size_t len) __pure;
static int handler_udp_net_to_tun(int fd, const struct worker_struct *ws,
				  char *buff, size_t len) __pure;
static int handler_udp(int fd, const struct worker_struct *ws,
		       char *buff, size_t len) __pure;
static int handler_tcp_tun_to_net(int fd, const struct worker_struct *ws,
				  char *buff, size_t len) __pure;
static int handler_tcp_net_to_tun(int fd, const struct worker_struct *ws,
				  char *buff, size_t len) __pure;
static int handler_tcp(int fd, const struct worker_struct *ws,
		       char *buff, size_t len) __pure;
static void *worker(void *self) __pure;

static int handler_udp_tun_to_net(int fd, const struct worker_struct *ws,
				  char *buff, size_t len)
{
	int dfd, state, keep = 1;
	char *pbuff, *cbuff;
	ssize_t rlen, err, plen, clen;
	struct ct_proto *hdr;
	struct curve25519_proto *p;
	struct sockaddr_storage naddr;
	socklen_t nlen;

	errno = 0;
	while ((rlen = read(fd, buff + sizeof(struct ct_proto),
			    len - sizeof(struct ct_proto))) > 0) {
		dfd = -1;
		nlen = 0;
		p = NULL;
		memset(&naddr, 0, sizeof(naddr));

		hdr = (struct ct_proto *) buff;
		hdr->flags = 0;

		trie_addr_lookup(buff + sizeof(struct ct_proto), rlen,
				 ws->parent.ipv4, &dfd, &naddr,
				 (size_t *) &nlen);
		if (unlikely(dfd < 0 || nlen == 0)) {
			syslog(LOG_INFO, "CPU%u: UDP tunnel lookup failed: "
			       "unknown destination\n", ws->cpu);
			continue;
		}
		err = get_user_by_sockaddr(&naddr, nlen, &p);
		if (unlikely(err || !p)) {
			syslog(LOG_ERR, "CPU%u: User protocol not in cache! "
			       "Dropping connection!\n", ws->cpu);
			continue;
		}
		plen = z_deflate(ws->z, buff + sizeof(struct ct_proto),
				 rlen, crypto_box_zerobytes, &pbuff);
		if (unlikely(plen < 0)) {
			syslog(LOG_ERR, "CPU%u: UDP tunnel deflate error: %s\n",
			       ws->cpu, strerror(errno));
			continue;
		}
		clen = curve25519_encode(ws->c, p, (unsigned char *) pbuff, plen,
					 (unsigned char **) &cbuff);
		if (unlikely(clen <= 0)) {
			syslog(LOG_ERR, "CPU%u: UDP tunnel encrypt error: %zd\n",
			       ws->cpu, clen);
			continue;
		}

		hdr->payload = htons((uint16_t) clen);

		state = 1;
		setsockopt(dfd, IPPROTO_UDP, UDP_CORK, &state, sizeof(state));

		err = sendto(dfd, hdr, sizeof(struct ct_proto), 0,
			     (struct sockaddr *) &naddr, nlen);
		if (unlikely(err < 0))
			syslog(LOG_ERR, "CPU%u: UDP tunnel write error: %s\n",
			       ws->cpu, strerror(errno));

		err = sendto(dfd, cbuff, clen, 0, (struct sockaddr *) &naddr,
			     nlen);
		if (unlikely(err < 0))
			syslog(LOG_ERR, "CPU%u: UDP tunnel write error: %s\n",
			       ws->cpu, strerror(errno));

		state = 0;
		setsockopt(dfd, IPPROTO_UDP, UDP_CORK, &state, sizeof(state));

		errno = 0;
	}

	if (unlikely(rlen < 0 && errno != EAGAIN))
		syslog(LOG_ERR, "CPU%u: UDP tunnel read error: %s\n",
		       ws->cpu, strerror(errno));

	return keep;
}

static void handler_udp_notify_close(int fd, struct sockaddr_storage *addr,
				     socklen_t len)
{
	ssize_t err;
	struct ct_proto hdr;

	memset(&hdr, 0, sizeof(hdr));
	hdr.flags |= PROTO_FLAG_EXIT;
	hdr.payload = 0;

	err = sendto(fd, &hdr, sizeof(hdr), 0, (struct sockaddr *) addr, len);
}

static int handler_udp_net_to_tun(int fd, const struct worker_struct *ws,
				  char *buff, size_t len)
{
	int keep = 1;
	char *pbuff, *cbuff;
	ssize_t rlen, err, plen, clen;
	struct ct_proto *hdr;
	struct curve25519_proto *p;
	struct sockaddr_storage naddr;
	socklen_t nlen;

	nlen = sizeof(naddr);
	memset(&naddr, 0, sizeof(naddr));

	errno = 0;
	while ((rlen = recvfrom(fd, buff, len, 0, (struct sockaddr *) &naddr,
				&nlen)) > 0) {
		p = NULL;
		hdr = (struct ct_proto *) buff;

		if (unlikely(rlen < sizeof(struct ct_proto)))
			goto close;
		if (unlikely(rlen - sizeof(*hdr) != ntohs(hdr->payload)))
			goto close;
		if (unlikely(ntohs(hdr->payload) == 0))
			goto close;
		if (hdr->flags & PROTO_FLAG_EXIT) {
close:
			remove_user_by_sockaddr(&naddr, nlen);
			trie_addr_remove_addr(&naddr, nlen);
			handler_udp_notify_close(fd, &naddr, nlen);
			nlen = sizeof(naddr);
			memset(&naddr, 0, sizeof(naddr));
			continue;
		}
		if (hdr->flags & PROTO_FLAG_INIT) {
			syslog(LOG_INFO, "Got initial userhash from remote end!\n");
			if (unlikely(rlen - sizeof(*hdr) <
				     sizeof(struct username_struct)))
				goto close;
			err = try_register_user_by_sockaddr(ws->c, buff + sizeof(struct ct_proto),
							    rlen - sizeof(struct ct_proto),
							    &naddr, nlen);
			if (unlikely(err))
				goto close;
			goto next;
		}

		err = get_user_by_sockaddr(&naddr, nlen, &p);
		if (unlikely(err || !p)) {
			syslog(LOG_ERR, "CPU%u: User protocol not in cache! "
			       "Dropping connection!\n", ws->cpu);
			goto close;
		}
		clen = curve25519_decode(ws->c, p, (unsigned char *) buff +
					 sizeof(struct ct_proto),
					 rlen - sizeof(struct ct_proto),
					 (unsigned char **) &cbuff);
                if (unlikely(clen <= 0)) {
			syslog(LOG_ERR, "CPU%u: UDP net decryption error: %zd\n",
			       ws->cpu, clen);
			goto close;
		}
		plen = z_inflate(ws->z, cbuff + crypto_box_zerobytes,
				 clen - crypto_box_zerobytes, 0, &pbuff);
		if (unlikely(plen < 0)) {
			syslog(LOG_ERR, "CPU%u: UDP net inflate error: %s\n",
			       ws->cpu, strerror(errno));
			goto close;
		}
		err = trie_addr_maybe_update(pbuff, plen, ws->parent.ipv4,
					     fd, &naddr, nlen);
		if (unlikely(err)) {
			syslog(LOG_INFO, "CPU%u: Malicious packet dropped "
			       "from id %d\n", ws->cpu, fd);
			goto next;
		}

		err = write(ws->parent.tunfd, pbuff, plen);
		if (unlikely(err < 0))
			syslog(LOG_ERR, "CPU%u: UDP net write error: %s\n",
			       ws->cpu, strerror(errno));

next:
		nlen = sizeof(naddr);
		memset(&naddr, 0, sizeof(naddr));
		errno = 0;
	}

	if (unlikely(rlen < 0 && errno != EAGAIN))
		syslog(LOG_ERR, "CPU%u: UDP net read error: %s\n",
		       ws->cpu, strerror(errno));

	return keep;
}

static int handler_udp(int fd, const struct worker_struct *ws,
		       char *buff, size_t len)
{
	int ret = 0;
	if (fd == ws->parent.tunfd)
		ret = handler_udp_tun_to_net(fd, ws, buff, len);
	else
		ret = handler_udp_net_to_tun(fd, ws, buff, len);
	return ret;
}

static int handler_tcp_tun_to_net(int fd, const struct worker_struct *ws,
				  char *buff, size_t len)
{
	int dfd, state, keep = 1;
	char *pbuff, *cbuff;
	ssize_t rlen, err, plen, clen;
	struct ct_proto *hdr;
	struct curve25519_proto *p;
	socklen_t nlen;

	errno = 0;
	while ((rlen = read(fd, buff + sizeof(struct ct_proto),
			    len - sizeof(struct ct_proto))) > 0) {
		dfd = -1;
		p = NULL;

		hdr = (struct ct_proto *) buff;
		hdr->flags = 0;

		trie_addr_lookup(buff + sizeof(struct ct_proto), rlen,
				 ws->parent.ipv4, &dfd, NULL,
				 (size_t *) &nlen);
		if (unlikely(dfd < 0)) {
			syslog(LOG_INFO, "CPU%u: TCP tunnel lookup failed: "
			       "unknown destination\n", ws->cpu);
			continue;
		}
		err = get_user_by_socket(dfd, &p);
		if (unlikely(err || !p)) {
			syslog(LOG_ERR, "CPU%u: User protocol not in cache! "
			       "Dropping connection!\n", ws->cpu);
			continue;
		}
		plen = z_deflate(ws->z, buff + sizeof(struct ct_proto),
				 rlen, crypto_box_zerobytes, &pbuff);
		if (unlikely(plen < 0)) {
			syslog(LOG_ERR, "CPU%u: TCP tunnel deflate error: %s\n",
			       ws->cpu, strerror(errno));
			continue;
		}
		clen = curve25519_encode(ws->c, p, (unsigned char *) pbuff, plen,
					 (unsigned char **) &cbuff);
		if (unlikely(clen <= 0)) {
			syslog(LOG_ERR, "CPU%u: TCP tunnel encrypt error: %zd\n",
			       ws->cpu, clen);
			continue;
		}

		hdr->payload = htons((uint16_t) clen);

		state = 1;
		setsockopt(dfd, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));

		err = write_exact(dfd, hdr, sizeof(struct ct_proto), 0);
		if (unlikely(err < 0))
			syslog(LOG_ERR, "CPU%u: TCP tunnel write error: %s\n",
			       ws->cpu, strerror(errno));

		err = write_exact(dfd, cbuff, clen, 0);
		if (unlikely(err < 0))
			syslog(LOG_ERR, "CPU%u: TCP tunnel write error: %s\n",
			       ws->cpu, strerror(errno));

		state = 0;
		setsockopt(dfd, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));

		errno = 0;
	}

	if (unlikely(rlen < 0 && errno != EAGAIN))
		syslog(LOG_ERR, "CPU%u: TCP tunnel read error: %s\n",
		       ws->cpu, strerror(errno));

	return keep;
}

ssize_t handler_tcp_read(int fd, char *buff, size_t len)
{
	ssize_t rlen;
	struct ct_proto *hdr = (struct ct_proto *) buff;

	/* May exit on EAGAIN if 0 Byte read */
	rlen = read_exact(fd, buff, sizeof(struct ct_proto), 1);
	if (rlen < 0)
		return rlen;
	if (unlikely(ntohs(hdr->payload) > len - sizeof(struct ct_proto))) {
		errno = ENOMEM;
		return 1; /* Force server to close connection */
	}
	/* May not exit on EAGAIN if 0 Byte read */
	rlen = read_exact(fd, buff + sizeof(struct ct_proto),
			  ntohs(hdr->payload), 0);
	if (rlen < 0)
		return rlen;

	return sizeof(struct ct_proto) + rlen;
}

static void handler_tcp_notify_close(int fd)
{
	ssize_t err;
	struct ct_proto hdr;

	memset(&hdr, 0, sizeof(hdr));
	hdr.flags |= PROTO_FLAG_EXIT;
	hdr.payload = 0;

	err = write(fd, &hdr, sizeof(hdr));
}

static int handler_tcp_net_to_tun(int fd, const struct worker_struct *ws,
				  char *buff, size_t len)
{
	int keep = 1, count = 0;
	char *pbuff, *cbuff;
	ssize_t rlen, err, plen, clen;
	struct ct_proto *hdr;
	struct curve25519_proto *p;

	errno = 0;
	while ((rlen = handler_tcp_read(fd, buff, len)) > 0) {
		p = NULL;
		hdr = (struct ct_proto *) buff;

		if (unlikely(rlen < sizeof(struct ct_proto)))
			goto close;
		if (unlikely(rlen - sizeof(*hdr) != ntohs(hdr->payload)))
			goto close;
		if (unlikely(ntohs(hdr->payload) == 0))
			goto close;
		if (hdr->flags & PROTO_FLAG_EXIT) {
close:
			remove_user_by_socket(fd);
			trie_addr_remove(fd);
			handler_tcp_notify_close(fd);
			rlen = write(ws->parent.efd, &fd, sizeof(fd));
			if (rlen != sizeof(fd))
				syslog(LOG_ERR, "CPU%u: TCP event write error: %s\n",
				       ws->cpu, strerror(errno));
			keep = 0;
			return keep;
		}
		if (hdr->flags & PROTO_FLAG_INIT) {
			syslog(LOG_INFO, "Got initial userhash from remote end!\n");
			if (unlikely(rlen - sizeof(*hdr) <
				     sizeof(struct username_struct)))
				goto close;
			err = try_register_user_by_socket(ws->c, buff + sizeof(struct ct_proto),
							  rlen - sizeof(struct ct_proto),
							  fd);
			if (unlikely(err))
				goto close;
			continue;
		}

		err = get_user_by_socket(fd, &p);
		if (unlikely(err || !p)) {
			syslog(LOG_ERR, "CPU%u: User protocol not in cache! "
			       "Dropping connection!\n", ws->cpu);
			goto close;
		}
		clen = curve25519_decode(ws->c, p, (unsigned char *) buff +
					 sizeof(struct ct_proto),
					 rlen - sizeof(struct ct_proto),
					 (unsigned char **) &cbuff);
                if (unlikely(clen <= 0)) {
			syslog(LOG_ERR, "CPU%u: TCP net decryption error: %zd\n",
			       ws->cpu, clen);
			goto close;
		}
		plen = z_inflate(ws->z, cbuff + crypto_box_zerobytes,
				 clen - crypto_box_zerobytes, 0, &pbuff);
		if (unlikely(plen < 0)) {
			syslog(LOG_ERR, "CPU%u: TCP net inflate error: %s\n",
			       ws->cpu, strerror(errno));
			goto close;
		}
		err = trie_addr_maybe_update(pbuff, plen, ws->parent.ipv4,
					     fd, NULL, 0);
		if (unlikely(err)) {
			syslog(LOG_INFO, "CPU%u: Malicious packet dropped "
			       "from id %d\n", ws->cpu, fd);
			continue;
		}

		err = write(ws->parent.tunfd, pbuff, plen);
		if (unlikely(err < 0))
			syslog(LOG_ERR, "CPU%u: TCP net write error: %s\n",
			       ws->cpu, strerror(errno));

		count++;
		if (count == 10) {
			err = write_exact(ws->efd[1], &fd, sizeof(fd), 1);
			if (unlikely(err != sizeof(fd)))
				syslog(LOG_ERR, "CPU%u: TCP net put fd back in "
				       "pipe error: %s\n", ws->cpu, strerror(errno));
			return keep;
		}

		errno = 0;
	}

	if (unlikely(rlen < 0 && errno != EAGAIN && errno != EBADF))
		syslog(LOG_ERR, "CPU%u: TCP net read error: %s\n",
		       ws->cpu, strerror(errno));

	return keep;
}

static int handler_tcp(int fd, const struct worker_struct *ws,
		       char *buff, size_t len)
{
	int ret = 0;
	if (fd == ws->parent.tunfd)
		ret = handler_tcp_tun_to_net(fd, ws, buff, len);
	else
		ret = handler_tcp_net_to_tun(fd, ws, buff, len);
	return ret;
}

static void *worker(void *self)
{
	int fd, old_state;
	ssize_t ret;
	size_t blen = TUNBUFF_SIZ; //FIXME
	const struct worker_struct *ws = self;
	struct pollfd fds;
	char *buff;

	fds.fd = ws->efd[0];
	fds.events = POLLIN;

	ret = z_alloc_or_maybe_die(ws->z, Z_DEFAULT_COMPRESSION);
	if (ret < 0)
		syslog_panic("Cannot init zLib!\n");

	ret = curve25519_alloc_or_maybe_die(ws->c);
	if (ret < 0)
		syslog_panic("Cannot init curve25519!\n");

	buff = xmalloc(blen);
	syslog(LOG_INFO, "curvetun thread on CPU%u up!\n", ws->cpu);
	pthread_cleanup_push(xfree, ws->c);
	pthread_cleanup_push(curve25519_free, ws->c);
	pthread_cleanup_push(xfree, ws->z);
	pthread_cleanup_push(z_free, ws->z);
	pthread_cleanup_push(xfree, buff);

	while (likely(!sigint)) {
		poll(&fds, 1, -1);
		if ((fds.revents & POLLIN) != POLLIN)
			continue;
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_state);
		while ((ret = read_exact(ws->efd[0], &fd, sizeof(fd), 1)) > 0) {
			if (ret != sizeof(fd)) {
				syslog(LOG_ERR, "CPU%u: Thread could not read "
				       "event descriptor!\n", ws->cpu);
				sched_yield();
				continue;
			}

			ret = ws->handler(fd, ws, buff, blen);
			if (ret) {
				ret = write_exact(ws->parent.refd, &fd, sizeof(fd), 1);
				if (ret != sizeof(fd))
					syslog(LOG_ERR, "CPU%u: Retriggering failed: "
					       "%s\n", ws->cpu, strerror(errno));
			}
		}
		pthread_setcancelstate(old_state, NULL);
	}

	syslog(LOG_INFO, "curvetun thread on CPU%u down!\n", ws->cpu);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_exit((void *) ((long) ws->cpu));
}

static void thread_spawn_or_panic(unsigned int cpus, int efd, int refd,
				  int tunfd, int ipv4, int udp)
{
	int i, ret;
	cpu_set_t cpuset;
	unsigned int threads;

	threads = cpus * THREADS_PER_CPU;
	for (i = 0; i < threads; ++i) {
		CPU_ZERO(&cpuset);
		threadpool[i].cpu = i % cpus;
		CPU_SET(threadpool[i].cpu, &cpuset);

		ret = pipe2(threadpool[i].efd, O_NONBLOCK);
		if (ret < 0)
			syslog_panic("Cannot create event socket!\n");

		threadpool[i].z = xmalloc(sizeof(struct z_struct));
		threadpool[i].c = xmalloc(sizeof(struct curve25519_struct));
		threadpool[i].parent.efd = efd;
		threadpool[i].parent.refd = refd;
		threadpool[i].parent.tunfd = tunfd;
		threadpool[i].parent.ipv4 = ipv4;
		threadpool[i].parent.udp = udp;
		threadpool[i].handler = udp ? handler_udp : handler_tcp;

		ret = pthread_create(&threadpool[i].trid, NULL,
				     worker, &threadpool[i]);
		if (ret < 0)
			syslog_panic("Thread creation failed!\n");

		ret = pthread_setaffinity_np(threadpool[i].trid,
					     sizeof(cpu_set_t), &cpuset);
		if (ret < 0)
			syslog_panic("Thread CPU migration failed!\n");

		pthread_detach(threadpool[i].trid);
	}

	sleep(1);
}

static void thread_finish(unsigned int cpus)
{
	int i;
	unsigned int threads;
	threads = cpus * THREADS_PER_CPU;
	for (i = 0; i < threads; ++i) {
		while (pthread_join(threadpool[i].trid, NULL) < 0)
			;
		close(threadpool[i].efd[0]);
		close(threadpool[i].efd[1]);
	}
}

int server_main(char *home, char *dev, char *port, int udp, int ipv4)
{
	int lfd = -1, kdpfd, nfds, nfd, curfds, efd[2], refd[2], tunfd, i, mtu;
	unsigned int cpus = 0, threads;
	ssize_t ret;
	struct epoll_event ev, *events;
	struct addrinfo hints, *ahead, *ai;

	openlog("curvetun", LOG_PID | LOG_CONS | LOG_NDELAY, LOG_DAEMON);
	syslog(LOG_INFO, "curvetun server booting!\n");

	parse_userfile_and_generate_user_store_or_die(home);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = udp ? SOCK_DGRAM : SOCK_STREAM;
	hints.ai_protocol = udp ? IPPROTO_UDP : IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	ret = getaddrinfo(NULL, port, &hints, &ahead);
	if (ret < 0)
		syslog_panic("Cannot get address info!\n");

	for (ai = ahead; ai != NULL && lfd < 0; ai = ai->ai_next) {
		lfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (lfd < 0)
			continue;
		if (ai->ai_family == AF_INET6) {
			int one = 1;
#ifdef IPV6_V6ONLY
			ret = setsockopt(lfd, IPPROTO_IPV6, IPV6_V6ONLY,
					 &one, sizeof(one));
			if (ret < 0) {
				close(lfd);
				lfd = -1;
				continue;
			}
#else
			close(lfd);
			lfd = -1;
			continue;
#endif /* IPV6_V6ONLY */
		}
		set_reuseaddr(lfd);
		mtu = IP_PMTUDISC_DONT;
		setsockopt(lfd, SOL_IP, IP_MTU_DISCOVER, &mtu, sizeof(mtu));
		ret = bind(lfd, ai->ai_addr, ai->ai_addrlen);
		if (ret < 0) {
			close(lfd);
			lfd = -1;
			continue;
		}
		if (!udp) {
			ret = listen(lfd, 5);
			if (ret < 0) {
				close(lfd);
				lfd = -1;
				continue;
			}
		}
		if (ipv4 == -1) {
			ipv4 = (ai->ai_family == AF_INET6 ? 0 :
				(ai->ai_family == AF_INET ? 1 : -1));
		}
		syslog(LOG_INFO, "curvetun on IPv%d via %s on port %s!\n",
		       ai->ai_family == AF_INET ? 4 : 6, udp ? "UDP" : "TCP",
		       port);
		syslog(LOG_INFO, "Allowed overlay proto is IPv%d!\n",
		       ipv4 ? 4 : 6);
	}

	freeaddrinfo(ahead);
	if (lfd < 0 || ipv4 < 0)
		syslog_panic("Cannot create socket!\n");

	tunfd = tun_open_or_die(dev ? dev : DEVNAME_SERVER);

	ret = pipe2(efd, O_NONBLOCK);
	if (ret < 0)
		syslog_panic("Cannot create parent event fd!\n");

	ret = pipe2(refd, O_NONBLOCK);
	if (ret < 0)
		syslog_panic("Cannot create parent (r)event fd!\n");

	set_nonblocking(lfd);

	events = xzmalloc(MAX_EPOLL_SIZE * sizeof(*events));
	for (i = 0; i < MAX_EPOLL_SIZE; ++i)
		events[i].data.fd = -1;

	kdpfd = epoll_create(MAX_EPOLL_SIZE);
	if (kdpfd < 0)
		syslog_panic("Cannot create socket!\n");

	memset(&ev, 0, sizeof(ev));
	ev.events = udp ? EPOLLIN | EPOLLET | EPOLLONESHOT : EPOLLIN;
	ev.data.fd = lfd;
	ret = epoll_ctl(kdpfd, EPOLL_CTL_ADD, lfd, &ev);
	if (ret < 0)
		syslog_panic("Cannot add socket for epoll!\n");

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = efd[0];
	ret = epoll_ctl(kdpfd, EPOLL_CTL_ADD, efd[0], &ev);
	if (ret < 0)
		syslog_panic("Cannot add socket for events!\n");

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = refd[0];
	ret = epoll_ctl(kdpfd, EPOLL_CTL_ADD, refd[0], &ev);
	if (ret < 0)
		syslog_panic("Cannot add socket for (r)events!\n");

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
	ev.data.fd = tunfd;
	ret = epoll_ctl(kdpfd, EPOLL_CTL_ADD, tunfd, &ev);
	if (ret < 0)
		syslog_panic("Cannot add socket for tundev!\n");

	curfds = 4;

	trie_init();

	cpus = get_number_cpus_online();
	threads = cpus * THREADS_PER_CPU;
	if (!((threads != 0) && ((threads & (threads - 1)) == 0)))
		syslog_panic("Thread number not power of two!\n");
	threadpool = xzmalloc(sizeof(*threadpool) * threads);
	thread_spawn_or_panic(cpus, efd[1], refd[1], tunfd, ipv4, udp);

	init_cpusched(threads);
	register_socket(tunfd);
	register_socket(lfd);

	syslog(LOG_INFO, "curvetun up and running!\n");

	while (likely(!sigint)) {
		nfds = epoll_wait(kdpfd, events, curfds, -1);
		if (nfds < 0) {
			syslog(LOG_ERR, "epoll_wait error: %s\n",
			       strerror(errno));
			break;
		}

		for (i = 0; i < nfds; ++i) {
			if (unlikely(events[i].data.fd < 0))
				continue;
			if (events[i].data.fd == lfd && !udp) {
				int one, ncpu;
				char hbuff[256], sbuff[256];
				struct sockaddr_storage taddr;
				socklen_t tlen;

				tlen = sizeof(taddr);
				nfd = accept(lfd, (struct sockaddr *) &taddr,
					     &tlen);
				if (nfd < 0) {
					syslog(LOG_ERR, "accept error: %s\n",
					       strerror(errno));
					continue;
				}

				if (curfds + 1 > MAX_EPOLL_SIZE) {
					close(nfd);
					continue;
				}

				curfds++;
				ncpu = register_socket(nfd);

				memset(hbuff, 0, sizeof(hbuff));
				memset(sbuff, 0, sizeof(sbuff));

				getnameinfo((struct sockaddr *) &taddr, tlen,
					    hbuff, sizeof(hbuff),
					    sbuff, sizeof(sbuff),
					    NI_NUMERICHOST | NI_NUMERICSERV);

				syslog(LOG_INFO, "New connection from %s:%s "
				       "with id %d on CPU%d, %d active!\n",
				       hbuff, sbuff, nfd, ncpu, curfds);

				set_nonblocking(nfd);

				one = 1;
				setsockopt(nfd, SOL_SOCKET, SO_KEEPALIVE,
					   &one, sizeof(one));
				one = 1;
				setsockopt(nfd, IPPROTO_TCP, TCP_NODELAY,
					   &one, sizeof(one));

				memset(&ev, 0, sizeof(ev));
				ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
				ev.data.fd = nfd;
				ret = epoll_ctl(kdpfd, EPOLL_CTL_ADD, nfd, &ev);
				if (ret < 0) {
					syslog(LOG_ERR, "Epoll ctl add error"
					       "on id %d: %s\n", nfd,
					       strerror(errno));
					close(nfd);
					curfds--;
					continue;
				}
			} else if (events[i].data.fd == refd[0]) {
				int fd_one;

				ret = read_exact(refd[0], &fd_one, sizeof(fd_one), 1);
				if (ret != sizeof(fd_one) || fd_one <= 0)
					continue;

				memset(&ev, 0, sizeof(ev));
				ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
				ev.data.fd = fd_one;
				ret = epoll_ctl(kdpfd, EPOLL_CTL_MOD, fd_one, &ev);
				if (ret < 0) {
					syslog(LOG_ERR, "Epoll ctl mod "
					       "error on id %d: %s\n",
					       fd_one, strerror(errno));
					close(fd_one);
					continue;
				}
			} else if (events[i].data.fd == efd[0]) {
				int fd_del, test;

				ret = read_exact(efd[0], &fd_del, sizeof(fd_del), 1);
				if (ret != sizeof(fd_del) || fd_del <= 0)
					continue;

				ret = read(fd_del, &test, sizeof(test));
				if (ret < 0 && errno == EBADF)
					continue;

				ret = epoll_ctl(kdpfd, EPOLL_CTL_DEL, fd_del, &ev);
				if (ret < 0) {
					syslog(LOG_ERR, "Epoll ctl del "
					       "error on id %d: %s\n",
					       fd_del, strerror(errno));
					close(fd_del);
					continue;
				}
				close(fd_del);
				curfds--;
				unregister_socket(fd_del);

				syslog(LOG_INFO, "Closed connection with "
				       "id %d, %d active!\n",
				       fd_del, curfds);
			} else {
				int cpu, fd_work = events[i].data.fd;
				cpu = socket_to_cpu(fd_work);

				ret = write_exact(threadpool[cpu].efd[1],
						  &fd_work, sizeof(fd_work), 1);
				if (ret != sizeof(fd_work))
					syslog(LOG_ERR, "Write error on event "
					       "dispatch: %s\n", strerror(errno));
			}
		}
	}

	syslog(LOG_INFO, "curvetun prepare shut down!\n");

	close(lfd);
	close(efd[0]);
	close(efd[1]);
	close(refd[0]);
	close(refd[1]);
	close(tunfd);

	thread_finish(cpus);
	xfree(threadpool);
	xfree(events);

	unregister_socket(lfd);
	unregister_socket(tunfd);
	destroy_cpusched();
	trie_cleanup();
	destroy_user_store();

	syslog(LOG_INFO, "curvetun shut down!\n");
	closelog();

	return 0;
}


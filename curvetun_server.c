/*
 * curvetun - the cipherspace wormhole creator
 * Part of the netsniff-ng project
 * Copyright 2011 Daniel Borkmann <daniel@netsniff-ng.org>,
 * Subject to the GPL, version 2.
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
#include <linux/if_tun.h>

#include "die.h"
#include "epoll2.h"
#include "ioops.h"
#include "xmalloc.h"
#include "curvetun.h"
#include "curve.h"
#include "ioexact.h"
#include "corking.h"
#include "cpus.h"
#include "sock.h"
#include "built_in.h"
#include "curvetun_mgmt.h"
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
	struct curve25519_struct *c;
};

static struct worker_struct *threadpool = NULL;

static int auth_log = 1;

extern volatile sig_atomic_t sigint;

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
ssize_t handler_tcp_read(int fd, char *buff, size_t len);
static void *worker(void *self) __pure;

static int handler_udp_tun_to_net(int fd, const struct worker_struct *ws,
				  char *buff, size_t len)
{
	int dfd, keep = 1;
	char *cbuff;
	ssize_t rlen, err, clen;
	struct ct_proto *hdr;
	struct curve25519_proto *p;
	struct sockaddr_storage naddr;
	socklen_t nlen;
	size_t off = sizeof(struct ct_proto) + crypto_box_zerobytes;

	if (!buff || len <= off)
		return 0;

	memset(buff, 0, len);
	while ((rlen = read(fd, buff + off, len - off)) > 0) {
		dfd = -1; nlen = 0; p = NULL;

		memset(&naddr, 0, sizeof(naddr));

		hdr = (struct ct_proto *) buff;
		memset(hdr, 0, sizeof(*hdr));
		hdr->flags = 0;

		trie_addr_lookup(buff + off, rlen, ws->parent.ipv4, &dfd, &naddr,
				 (size_t *) &nlen);
		if (unlikely(dfd < 0 || nlen == 0)) {
			memset(buff, 0, len);
			continue;
		}

		err = get_user_by_sockaddr(&naddr, nlen, &p);
		if (unlikely(err || !p)) {
			memset(buff, 0, len);
			continue;
		}

		clen = curve25519_encode(ws->c, p, (unsigned char *) (buff + off -
					 crypto_box_zerobytes), (rlen +
					 crypto_box_zerobytes), (unsigned char **)
					 &cbuff);
		if (unlikely(clen <= 0)) {
			memset(buff, 0, len);
			continue;
		}

		hdr->payload = htons((uint16_t) clen);

		set_udp_cork(dfd);

		sendto(dfd, hdr, sizeof(struct ct_proto), 0, (struct sockaddr *)
		       &naddr, nlen);
		sendto(dfd, cbuff, clen, 0, (struct sockaddr *) &naddr, nlen);

		set_udp_uncork(dfd);

		memset(buff, 0, len);
	}

	return keep;
}

static void handler_udp_notify_close(int fd, struct sockaddr_storage *addr)
{
	struct ct_proto hdr;

	memset(&hdr, 0, sizeof(hdr));
	hdr.flags |= PROTO_FLAG_EXIT;
	hdr.payload = 0;

	sendto(fd, &hdr, sizeof(hdr), 0, (struct sockaddr *) addr,
	       sizeof(*addr));
}

static int handler_udp_net_to_tun(int fd, const struct worker_struct *ws,
				  char *buff, size_t len)
{
	int keep = 1;
	char *cbuff;
	ssize_t rlen, err, clen;
	struct ct_proto *hdr;
	struct curve25519_proto *p;
	struct sockaddr_storage naddr;
	socklen_t nlen = sizeof(naddr);

	if (!buff || !len)
		return 0;

	memset(&naddr, 0, sizeof(naddr));
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
			handler_udp_notify_close(fd, &naddr);

			return keep;
		}
		if (hdr->flags & PROTO_FLAG_INIT) {
			syslog_maybe(auth_log, LOG_INFO, "Got initial userhash "
				     "from remote end!\n");

			if (unlikely(rlen - sizeof(*hdr) <
				     sizeof(struct username_struct)))
				goto close;

			err = try_register_user_by_sockaddr(ws->c,
					buff + sizeof(struct ct_proto),
					rlen - sizeof(struct ct_proto),
					&naddr, nlen, auth_log);
			if (unlikely(err))
				goto close;

			goto next;
		}

		err = get_user_by_sockaddr(&naddr, nlen, &p);
		if (unlikely(err || !p))
			goto close;

		clen = curve25519_decode(ws->c, p, (unsigned char *) buff +
					 sizeof(struct ct_proto),
					 rlen - sizeof(struct ct_proto),
					 (unsigned char **) &cbuff, NULL);
                if (unlikely(clen <= 0))
			goto close;

		cbuff += crypto_box_zerobytes;
		clen -= crypto_box_zerobytes;

		err = trie_addr_maybe_update(cbuff, clen, ws->parent.ipv4,
					     fd, &naddr, nlen);
		if (unlikely(err))
			goto next;

		err = write(ws->parent.tunfd, cbuff, clen);
next:
		nlen = sizeof(naddr);
		memset(&naddr, 0, sizeof(naddr));
	}

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
	int dfd, keep = 1;
	char *cbuff;
	ssize_t rlen, err, clen;
	struct ct_proto *hdr;
	struct curve25519_proto *p;
	socklen_t nlen;
	size_t off = sizeof(struct ct_proto) + crypto_box_zerobytes;

	if (!buff || len <= off)
		return 0;

	memset(buff, 0, len);
	while ((rlen = read(fd, buff + off, len - off)) > 0) {
		dfd = -1; p = NULL;

		hdr = (struct ct_proto *) buff;
		memset(hdr, 0, sizeof(*hdr));
		hdr->flags = 0;

		trie_addr_lookup(buff + off, rlen, ws->parent.ipv4, &dfd, NULL,
				 (size_t *) &nlen);
		if (unlikely(dfd < 0)) {
			memset(buff, 0, len);
			continue;
		}

		err = get_user_by_socket(dfd, &p);
		if (unlikely(err || !p)) {
			memset(buff, 0, len);
			continue;
		}

		clen = curve25519_encode(ws->c, p, (unsigned char *) (buff + off -
					 crypto_box_zerobytes), (rlen +
					 crypto_box_zerobytes), (unsigned char **)
					 &cbuff);
		if (unlikely(clen <= 0)) {
			memset(buff, 0, len);
			continue;
		}

		hdr->payload = htons((uint16_t) clen);

		set_tcp_cork(dfd);

		write_exact(dfd, hdr, sizeof(struct ct_proto), 0);
		write_exact(dfd, cbuff, clen, 0);

		set_tcp_uncork(dfd);

		memset(buff, 0, len);
	}

	return keep;
}

ssize_t handler_tcp_read(int fd, char *buff, size_t len)
{
	ssize_t rlen;
	struct ct_proto *hdr = (struct ct_proto *) buff;

	if (!buff || !len)
		return 0;

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
	struct ct_proto hdr;

	memset(&hdr, 0, sizeof(hdr));
	hdr.flags |= PROTO_FLAG_EXIT;
	hdr.payload = 0;

	if (write(fd, &hdr, sizeof(hdr))) { ; }
}

static int handler_tcp_net_to_tun(int fd, const struct worker_struct *ws,
				  char *buff, size_t len)
{
	int keep = 1, count = 0;
	char *cbuff;
	ssize_t rlen, err, clen;
	struct ct_proto *hdr;
	struct curve25519_proto *p;

	if (!buff || !len)
		return 0;

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

			keep = 0;
			return keep;
		}
		if (hdr->flags & PROTO_FLAG_INIT) {
			syslog_maybe(auth_log, LOG_INFO, "Got initial userhash "
				     "from remote end!\n");

			if (unlikely(rlen - sizeof(*hdr) <
				     sizeof(struct username_struct)))
				goto close;

			err = try_register_user_by_socket(ws->c,
					buff + sizeof(struct ct_proto),
					rlen - sizeof(struct ct_proto),
					fd, auth_log);
			if (unlikely(err))
				goto close;

			continue;
		}

		err = get_user_by_socket(fd, &p);
		if (unlikely(err || !p))
			continue;

		clen = curve25519_decode(ws->c, p, (unsigned char *) buff +
					 sizeof(struct ct_proto),
					 rlen - sizeof(struct ct_proto),
					 (unsigned char **) &cbuff, NULL);
                if (unlikely(clen <= 0))
			continue;

		cbuff += crypto_box_zerobytes;
		clen -= crypto_box_zerobytes;

		err = trie_addr_maybe_update(cbuff, clen, ws->parent.ipv4,
					     fd, NULL, 0);
		if (unlikely(err))
			continue;

		err = write(ws->parent.tunfd, cbuff, clen);

		count++;
		if (count == 10) {
			write_exact(ws->efd[1], &fd, sizeof(fd), 1);
			/* Read later next data and let others process */
			return keep;
		}
	}

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
	struct worker_struct *ws = self;
	struct pollfd fds;
	char *buff;

	fds.fd = ws->efd[0];
	fds.events = POLLIN;

	ws->c = curve25519_tfm_alloc();
	buff = xmalloc_aligned(blen, 64);

	syslog(LOG_INFO, "curvetun thread on CPU%u up!\n", ws->cpu);

	pthread_cleanup_push(curve25519_tfm_free_void, ws->c);
	pthread_cleanup_push(xfree_func, buff);

	while (likely(!sigint)) {
		poll(&fds, 1, -1);
		if ((fds.revents & POLLIN) != POLLIN)
			continue;

		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old_state);

		while ((ret = read_exact(ws->efd[0], &fd, sizeof(fd), 1)) > 0) {
			if (ret != sizeof(fd)) {
				sched_yield();
				continue;
			}

			ret = ws->handler(fd, ws, buff, blen);
			if (ret)
				write_exact(ws->parent.refd, &fd, sizeof(fd), 1);
		}

		pthread_setcancelstate(old_state, NULL);
	}

	syslog(LOG_INFO, "curvetun thread on CPU%u down!\n", ws->cpu);

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

		threadpool[i].c = xmalloc_aligned(sizeof(*threadpool[i].c), 64);
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
					     sizeof(cpuset), &cpuset);
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

int server_main(char *home, char *dev, char *port, int udp, int ipv4, int log)
{
	int lfd = -1, kdpfd, nfds, nfd, curfds, efd[2], refd[2], tunfd, i;
	unsigned int cpus = 0, threads, udp_cpu = 0;
	ssize_t ret;
	struct epoll_event *events;
	struct addrinfo hints, *ahead, *ai;

	auth_log = !!log;
	openlog("curvetun", LOG_PID | LOG_CONS | LOG_NDELAY, LOG_DAEMON);

	syslog(LOG_INFO, "curvetun server booting!\n");
	syslog_maybe(!auth_log, LOG_INFO, "curvetun user logging disabled!\n");

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
#ifdef IPV6_V6ONLY
			ret = set_ipv6_only(lfd);
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
		set_mtu_disc_dont(lfd);

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

		syslog_maybe(auth_log, LOG_INFO, "curvetun on IPv%d via %s "
			     "on port %s!\n", ai->ai_family == AF_INET ? 4 : 6,
			     udp ? "UDP" : "TCP", port);
		syslog_maybe(auth_log, LOG_INFO, "Allowed overlay proto is "
			     "IPv%d!\n", ipv4 ? 4 : 6);
	}

	freeaddrinfo(ahead);

	if (lfd < 0 || ipv4 < 0)
		syslog_panic("Cannot create socket!\n");

	tunfd = tun_open_or_die(dev ? dev : DEVNAME_SERVER, IFF_TUN | IFF_NO_PI);

	pipe_or_die(efd, O_NONBLOCK);
	pipe_or_die(refd, O_NONBLOCK);

	set_nonblocking(lfd);

	events = xzmalloc(MAX_EPOLL_SIZE * sizeof(*events));
	for (i = 0; i < MAX_EPOLL_SIZE; ++i)
		events[i].data.fd = -1;

	kdpfd = epoll_create(MAX_EPOLL_SIZE);
	if (kdpfd < 0)
		syslog_panic("Cannot create socket!\n");

	set_epoll_descriptor(kdpfd, EPOLL_CTL_ADD, lfd,
			     udp ? EPOLLIN | EPOLLET | EPOLLONESHOT : EPOLLIN);
	set_epoll_descriptor(kdpfd, EPOLL_CTL_ADD, efd[0], EPOLLIN);
	set_epoll_descriptor(kdpfd, EPOLL_CTL_ADD, refd[0], EPOLLIN);
	set_epoll_descriptor(kdpfd, EPOLL_CTL_ADD, tunfd,
			     EPOLLIN | EPOLLET | EPOLLONESHOT);
	curfds = 4;

	trie_init();

	cpus = get_number_cpus_online();
	threads = cpus * THREADS_PER_CPU;
	if (!ispow2(threads))
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
				int ncpu;
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

				syslog_maybe(auth_log, LOG_INFO, "New connection "
					     "from %s:%s (%d active client connections) -  id %d on CPU%d",
					     hbuff, sbuff, curfds-4, nfd, ncpu);

				set_nonblocking(nfd);
				set_socket_keepalive(nfd);
				set_tcp_nodelay(nfd);
				ret = set_epoll_descriptor2(kdpfd, EPOLL_CTL_ADD,
						nfd, EPOLLIN | EPOLLET | EPOLLONESHOT);
				if (ret < 0) {
					close(nfd);
					curfds--;
					continue;
				}
			} else if (events[i].data.fd == refd[0]) {
				int fd_one;

				ret = read_exact(refd[0], &fd_one,
						 sizeof(fd_one), 1);
				if (ret != sizeof(fd_one) || fd_one <= 0)
					continue;

				ret = set_epoll_descriptor2(kdpfd, EPOLL_CTL_MOD,
						fd_one, EPOLLIN | EPOLLET | EPOLLONESHOT);
				if (ret < 0) {
					close(fd_one);
					continue;
				}
			} else if (events[i].data.fd == efd[0]) {
				int fd_del, test;

				ret = read_exact(efd[0], &fd_del,
						 sizeof(fd_del), 1);
				if (ret != sizeof(fd_del) || fd_del <= 0)
					continue;

				ret = read(fd_del, &test, sizeof(test));
				if (ret < 0 && errno == EBADF)
					continue;

				ret = set_epoll_descriptor2(kdpfd, EPOLL_CTL_DEL,
						fd_del, 0);
				if (ret < 0) {
					close(fd_del);
					continue;
				}

				close(fd_del);
				curfds--;
				unregister_socket(fd_del);

				syslog_maybe(auth_log, LOG_INFO, "Closed connection "
					     "with id %d (%d active client connections remain)\n", fd_del,
					     curfds-4);
			} else {
				int cpu, fd_work = events[i].data.fd;

				if (!udp)
					cpu = socket_to_cpu(fd_work);
				else
					udp_cpu = (udp_cpu + 1) & (threads - 1);

				write_exact(threadpool[udp ? udp_cpu : cpu].efd[1],
					    &fd_work, sizeof(fd_work), 1);
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

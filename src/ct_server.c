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
#include <limits.h>
#include <netdb.h>
#include <sched.h>
#include <ctype.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <arpa/inet.h>

#include "die.h"
#include "netdev.h"
#include "write_or_die.h"
#include "psched.h"
#include "xmalloc.h"
#include "ct_server.h"
#include "curvetun.h"
#include "compiler.h"
#include "trie.h"

struct parent_info {
	int efd;
	int tunfd;
	int ipv4;
	int udp;
};

struct worker_struct {
	int efd;
	unsigned int cpu;
	pthread_t thread;
	struct parent_info parent;
	void (*handler)(int fd, const struct worker_struct *ws,
			char *buff, size_t len);
};

static struct worker_struct *threadpool = NULL;

extern sig_atomic_t sigint;

static void handler_udp_tun_to_net(int fd, const struct worker_struct *ws,
				   char *buff, size_t len)
{
	int dfd;
	ssize_t rlen, err;
	struct sockaddr_storage naddr;
	socklen_t nlen;

	while ((rlen = read(fd, buff, len)) > 0) {
		nlen = 0;
		memset(&naddr, 0, sizeof(naddr));

		trie_addr_lookup(buff, rlen, ws->parent.ipv4, &dfd, &naddr,
				 (size_t *) &nlen);
		if (dfd < 0 || nlen == 0)
			/* We have no destination for this, drop! */
			continue;

		err = sendto(dfd, buff, rlen, 0, (struct sockaddr *) &naddr,
			     nlen);
	}
}

static void handler_udp_net_to_tun(int fd, const struct worker_struct *ws,
				   char *buff, size_t len)
{
	size_t elen;
	ssize_t rlen, err;
	struct sockaddr_storage naddr;
	socklen_t nlen;

	elen = strlen("\r\r\r") + 1;
	nlen = sizeof(naddr);
	memset(&naddr, 0, sizeof(naddr));

	while ((rlen = recvfrom(fd, buff, len, 0, (struct sockaddr *) &naddr,
				&nlen)) > 0) {
		trie_addr_maybe_update(buff, rlen, ws->parent.ipv4, fd,
				       &naddr, nlen);
		if (unlikely(rlen < elen))
			continue;
		if (!strncmp(buff, "\r\r\r", elen))
			trie_addr_remove_addr(&naddr, nlen);
		else
			err = write(ws->parent.tunfd, buff, rlen);

		nlen = sizeof(naddr);
		memset(&naddr, 0, sizeof(naddr));
	}
}

static void handler_udp(int fd, const struct worker_struct *ws,
		        char *buff, size_t len)
{
	if (fd == ws->parent.tunfd)
		handler_udp_tun_to_net(fd, ws, buff, len);
	else
		handler_udp_net_to_tun(fd, ws, buff, len);
}

static void handler_tcp_tun_to_net(int fd, const struct worker_struct *ws,
				   char *buff, size_t len)
{
	int dfd;
	ssize_t rlen, err;
	socklen_t nlen;

	while ((rlen = read(fd, buff, len)) > 0) {
		trie_addr_lookup(buff, rlen, ws->parent.ipv4, &dfd, NULL,
				 (size_t *) &nlen);
		if (dfd < 0)
			continue;

		err = write(dfd, buff, rlen);
	}
}

static void handler_tcp_net_to_tun(int fd, const struct worker_struct *ws,
				   char *buff, size_t len)
{
	ssize_t rlen, err;

	while ((rlen = read(fd, buff, len)) > 0) {
		trie_addr_maybe_update(buff, rlen, ws->parent.ipv4, fd, NULL, 0);
		err = write(ws->parent.tunfd, buff, rlen);
	}

	if (rlen < 1 && errno != EAGAIN) {
		uint64_t fd64 = fd;
		rlen = write(ws->parent.efd, &fd64, sizeof(fd64));
		if (rlen != sizeof(fd64))
			whine("Event write error from thread!\n");
		trie_addr_remove(fd);
	}
}

static void handler_tcp(int fd, const struct worker_struct *ws,
		        char *buff, size_t len)
{
	if (fd == ws->parent.tunfd)
		handler_tcp_tun_to_net(fd, ws, buff, len);
	else
		handler_tcp_net_to_tun(fd, ws, buff, len);
}

static void *worker(void *self)
{
	uint64_t fd64;
	ssize_t ret;
	size_t blen = 10000; //XXX
	const struct worker_struct *ws = self;
	struct pollfd fds;
	char *buff;

	fds.fd = ws->efd;
	fds.events = POLLIN;

	buff = xmalloc(blen);

	syslog(LOG_INFO, "curvetun thread %p/CPU%u up!\n", ws, ws->cpu);

	while (likely(!sigint)) {
		poll(&fds, 1, -1);
		while ((ret = read(ws->efd, &fd64, sizeof(fd64))) > 0) {
			if (ret != sizeof(fd64)) {
				sched_yield();
				continue;
			}
			ws->handler((int) fd64, ws, buff, blen);
		}
	}

	xfree(buff);

	syslog(LOG_INFO, "curvetun thread %p/CPU%u down!\n", ws, ws->cpu);
	pthread_exit(0);
}

static void thread_spawn_or_panic(unsigned int cpus, int efd, int tunfd,
				  int ipv4, int udp)
{
	int i, ret;
	cpu_set_t cpuset;

	for (i = 0; i < cpus * THREADS_PER_CPU; ++i) {
		CPU_ZERO(&cpuset);
		threadpool[i].cpu = i % cpus;
		CPU_SET(threadpool[i].cpu, &cpuset);

		threadpool[i].efd = eventfd(0, 0);
		if (threadpool[i].efd < 0)
			panic("Cannot create event socket!\n");

		set_nonblocking(threadpool[i].efd);

		threadpool[i].parent.efd = efd;
		threadpool[i].parent.tunfd = tunfd;
		threadpool[i].parent.ipv4 = ipv4;
		threadpool[i].parent.udp = udp;
		threadpool[i].handler = udp ? handler_udp : handler_tcp;

		ret = pthread_create(&(threadpool[i].thread), NULL,
				     worker, &threadpool[i]);
		if (ret < 0)
			panic("Thread creation failed!\n");

		ret = pthread_setaffinity_np(threadpool[i].thread,
					     sizeof(cpu_set_t), &cpuset);
		if (ret < 0)
			panic("Thread CPU migration failed!\n");

		pthread_detach(threadpool[i].thread);
	}
}

static void thread_finish(unsigned int cpus)
{
	int i;
	for (i = 0; i < cpus * THREADS_PER_CPU; ++i) {
		close(threadpool[i].efd);
		pthread_join(threadpool[i].thread, NULL);
	}
}

int server_main(int port, int udp, int lnum)
{
	int lfd = -1, kdpfd, nfds, nfd, curfds, efd, tunfd;
	int ipv4 = 0, thread_it = 0, i;
	unsigned int cpus = 0;
	ssize_t ret;
	struct epoll_event lev, eev, tev, nev;
	struct epoll_event events[MAX_EPOLL_SIZE];
	struct addrinfo hints, *ahead, *ai;

	openlog("curvetun", LOG_PID | LOG_CONS | LOG_NDELAY, LOG_DAEMON);
	syslog(LOG_INFO, "curvetun server booting!\n");

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = udp ? SOCK_DGRAM : SOCK_STREAM;
	hints.ai_protocol = udp ? IPPROTO_UDP : IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	ret = getaddrinfo(NULL, "6666", &hints, &ahead);
	if (ret < 0)
		panic("Cannot get address info!\n");

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
		ipv4 = (ai->ai_family == AF_INET6 ? 0 :
			(ai->ai_family == AF_INET ? 1 : -1));
		syslog(LOG_INFO, "curvetun on IPv%d via %s!\n",
		       ipv4 ? 4 : 6, udp ? "UDP" : "TCP");
	}

	freeaddrinfo(ahead);
	if (lfd < 0 || ipv4 < 0)
		panic("Cannot create socket!\n");

	tunfd = tun_open_or_die(DEVNAME_SERVER);

	efd = eventfd(0, 0);
	if (efd < 0)
		panic("Cannot create parent event fd!\n");

	set_nonblocking(lfd);
	set_nonblocking(efd);
	set_nonblocking(tunfd);

	kdpfd = epoll_create(MAX_EPOLL_SIZE);
	if (kdpfd < 0)
		panic("Cannot create socket!\n");

	memset(&lev, 0, sizeof(lev));
	lev.events = EPOLLIN | EPOLLET;
	lev.data.fd = lfd;
	memset(&eev, 0, sizeof(lev));
	eev.events = EPOLLIN | EPOLLET;
	eev.data.fd = efd;
	memset(&tev, 0, sizeof(tev));
	tev.events = EPOLLIN | EPOLLET;
	tev.data.fd = tunfd;
	curfds = 3;

	ret = epoll_ctl(kdpfd, EPOLL_CTL_ADD, lfd, &lev);
	if (ret < 0)
		panic("Cannot add socket for epoll!\n");
	ret = epoll_ctl(kdpfd, EPOLL_CTL_ADD, efd, &eev);
	if (ret < 0)
		panic("Cannot add socket for events!\n");
	ret = epoll_ctl(kdpfd, EPOLL_CTL_ADD, tunfd, &tev);
	if (ret < 0)
		panic("Cannot add socket for tundev!\n");

	trie_init();

	cpus = get_number_cpus_online();
	threadpool = xzmalloc(sizeof(*threadpool) * cpus * THREADS_PER_CPU);
	thread_spawn_or_panic(cpus, efd, tunfd, ipv4, udp);

	syslog(LOG_INFO, "curvetun up and running!\n");

	while (likely(!sigint)) {
		nfds = epoll_wait(kdpfd, events, curfds, -1);
		if (nfds < 0) {
			syslog(LOG_ERR, "epoll_wait error: %s\n",
			       strerror(errno));
			break;
		}

		for (i = 0; i < nfds; ++i) {
			if (events[i].data.fd == lfd && !udp) {
				int one;
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

				memset(hbuff, 0, sizeof(hbuff));
				memset(sbuff, 0, sizeof(sbuff));

				getnameinfo((struct sockaddr *) &taddr, tlen,
					    hbuff, sizeof(hbuff),
					    sbuff, sizeof(sbuff),
					    NI_NUMERICHOST | NI_NUMERICSERV);

				syslog(LOG_INFO, "New connection from %s:%s with id %d\n",
				       hbuff, sbuff, nfd);

				set_nonblocking(nfd);

				one = 1;
				setsockopt(nfd, SOL_SOCKET, SO_KEEPALIVE,
					   &one, sizeof(one));
				one = 1;
				setsockopt(nfd, IPPROTO_TCP, TCP_NODELAY,
					   &one, sizeof(one));

				memset(&nev, 0, sizeof(nev));
				nev.events = EPOLLIN | EPOLLET;
				nev.data.fd = nfd;

				ret = epoll_ctl(kdpfd, EPOLL_CTL_ADD, nfd, &nev);
				if (ret < 0)
					panic("Epoll ctl error!\n");

				curfds++;
			} else if (events[i].data.fd == efd) {
				uint64_t fd64_del;

				while ((ret = read(efd, &fd64_del,
						   sizeof(fd64_del))) > 0) {
					if (ret != sizeof(fd64_del))
						continue;

					epoll_ctl(kdpfd, EPOLL_CTL_DEL, (int)
						  fd64_del, &nev);
					curfds--;

					syslog(LOG_INFO, "Closed connection with id %d\n",
					       (int) fd64_del);
				}
			} else {
				uint64_t fd64 = events[i].data.fd;

				ret = write(threadpool[thread_it].efd,
					    &fd64, sizeof(fd64));
				if (ret != sizeof(fd64))
					syslog(LOG_ERR, "Write error on event dispatch!\n");

				thread_it = (thread_it + 1) % cpus;
			}
		}
	}

	syslog(LOG_INFO, "curvetun prepare shut down!\n");

	close(lfd);
	close(efd);
	close(tunfd);

	thread_finish(cpus);
	xfree(threadpool);

	trie_cleanup();

	syslog(LOG_INFO, "curvetun shut down!\n");
	closelog();

	return 0;
}


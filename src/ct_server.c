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
#include "compiler.h"
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
};

static struct worker_struct *threadpool = NULL;

extern sig_atomic_t sigint;

static int handler_udp_tun_to_net(int fd, const struct worker_struct *ws,
				  char *buff, size_t len)
{
	int dfd, keep = 1;
	ssize_t rlen, err;
	struct ct_proto *hdr;
	struct sockaddr_storage naddr;
	socklen_t nlen;

	while ((rlen = read(fd, buff + sizeof(struct ct_proto),
			    len - sizeof(struct ct_proto))) > 0) {
		nlen = 0;
		memset(&naddr, 0, sizeof(naddr));

		hdr = (struct ct_proto *) buff;
		hdr->payload = htons((uint16_t) rlen);
		hdr->flags = 0;

		trie_addr_lookup(buff + sizeof(struct ct_proto),
				 rlen - sizeof(struct ct_proto),
				 ws->parent.ipv4, &dfd, &naddr,
				 (size_t *) &nlen);

		if (dfd < 0 || nlen == 0) {
			syslog(LOG_INFO, "TCP tunnel lookup failed: "
			       "unknown destination\n");
			continue;
		}

		err = sendto(dfd, buff, rlen + sizeof(struct ct_proto), 0,
			     (struct sockaddr *) &naddr, nlen);
		if (err < 0)
			syslog(LOG_ERR, "UDP tunnel write error: %s\n",
			       strerror(errno));
	}

	if (rlen < 0 && errno != EAGAIN)
		syslog(LOG_ERR, "UDP tunnel read error: %s\n", strerror(errno));

	return keep;
}

static int handler_udp_net_to_tun(int fd, const struct worker_struct *ws,
				  char *buff, size_t len)
{
	int keep = 1;
	ssize_t rlen, err;
	struct ct_proto *hdr;
	struct sockaddr_storage naddr;
	socklen_t nlen;

	nlen = sizeof(naddr);
	memset(&naddr, 0, sizeof(naddr));

	while ((rlen = recvfrom(fd, buff, len, 0, (struct sockaddr *) &naddr,
				&nlen)) > 0) {
		if (rlen < sizeof(struct ct_proto)) {
			nlen = sizeof(naddr);
			memset(&naddr, 0, sizeof(naddr));
			continue;
		}
		hdr = (struct ct_proto *) buff;
		if (hdr->flags & PROTO_FLAG_EXIT) {
			trie_addr_remove_addr(&naddr, nlen);
			nlen = sizeof(naddr);
			memset(&naddr, 0, sizeof(naddr));
			syslog(LOG_INFO, "Remote UDP connection closed!\n");
			continue;
		}

		trie_addr_maybe_update(buff + sizeof(struct ct_proto),
				       rlen - sizeof(struct ct_proto),
				       ws->parent.ipv4, fd,
				       &naddr, nlen);

		err = write(ws->parent.tunfd,
			    buff + sizeof(struct ct_proto),
			    rlen - sizeof(struct ct_proto));
		if (err < 0)
			syslog(LOG_ERR, "UDP net write error: %s\n",
			       strerror(errno));

		nlen = sizeof(naddr);
		memset(&naddr, 0, sizeof(naddr));
	}

	if (rlen < 0 && errno != EAGAIN)
		syslog(LOG_ERR, "UDP net read error: %s\n", strerror(errno));

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
	ssize_t rlen, err;
	struct ct_proto *hdr;
	socklen_t nlen;

	while ((rlen = read(fd, buff + sizeof(struct ct_proto),
			    len - sizeof(struct ct_proto))) > 0) {
		hdr = (struct ct_proto *) buff;
		hdr->payload = htons((uint16_t) rlen);

		trie_addr_lookup(buff + sizeof(struct ct_proto),
				 rlen - sizeof(struct ct_proto),
				 ws->parent.ipv4, &dfd, NULL,
				 (size_t *) &nlen);

		if (dfd < 0) {
			syslog(LOG_INFO, "TCP tunnel lookup failed: "
			       "unknown destination\n");
			continue;
		}

		err = write(dfd, buff, rlen + sizeof(struct ct_proto));
		if (err < 0)
			syslog(LOG_ERR, "TCP tunnel write error: %s\n",
			       strerror(errno));
	}

	if (rlen < 0 && errno != EAGAIN)
		syslog(LOG_ERR, "TCP tunnel read error: %s\n", strerror(errno));

	return keep;
}

static int handler_tcp_net_to_tun(int fd, const struct worker_struct *ws,
				  char *buff, size_t len)
{
	int keep = 1;
	ssize_t rlen, err;
	struct ct_proto hdr;

	while (1) {
		rlen = read_exact(fd, &hdr, sizeof(hdr));
		if (rlen < 0 || len < ntohs(hdr.payload))
			break;
		rlen = read_exact(fd, buff, ntohs(hdr.payload));
		if (rlen < 0)
			break;
		if (hdr.flags & PROTO_FLAG_EXIT) {
			uint64_t fd64 = fd;

			rlen = write(ws->parent.efd, &fd64, sizeof(fd64));
			if (rlen != sizeof(fd64))
				syslog(LOG_ERR, "TCP event write error: %s\n",
				       strerror(errno));

			trie_addr_remove(fd);
			keep = 0;
			continue;
		}

		trie_addr_maybe_update(buff, rlen, ws->parent.ipv4, fd, NULL, 0);

		err = write(ws->parent.tunfd, buff, ntohs(hdr.payload));
		if (err < 0)
			syslog(LOG_ERR, "TCP net write error: %s\n",
			       strerror(errno));
	}

	if (rlen < 0 && errno != EAGAIN)
		syslog(LOG_ERR, "TCP net read error: %s\n", strerror(errno));

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
	int fd;
	ssize_t ret;
	size_t blen = 10000; //XXX
	const struct worker_struct *ws = self;
	struct pollfd fds;
	char *buff;

	fds.fd = ws->efd[0];
	fds.events = POLLIN;

	buff = xmalloc(blen);
	syslog(LOG_INFO, "curvetun thread on CPU%u up!\n", ws->cpu);

	while (likely(!sigint)) {
		poll(&fds, 1, -1);
		if ((fds.revents & POLLIN) != POLLIN)
			continue;
		while ((ret = read_exact(ws->efd[0], &fd, sizeof(fd))) > 0) {
			if (ret != sizeof(fd)) {
				syslog(LOG_ERR, "Thread could not read event "
				       "descriptor!\n");
				sched_yield();
				continue;
			}
			ret = ws->handler(fd, ws, buff, blen);
			if (ret) {
				ret = write_exact(ws->parent.refd, &fd, sizeof(fd));
				if (ret != sizeof(fd))
					syslog(LOG_ERR, "Retriggering failed: "
					       "%s\n", strerror(errno));
			}
		}
	}

	syslog(LOG_INFO, "curvetun thread on CPU%u down!\n", ws->cpu);
	xfree(buff);

	pthread_exit(0);
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
			panic("Cannot create event socket!\n");

		threadpool[i].parent.efd = efd;
		threadpool[i].parent.refd = refd;
		threadpool[i].parent.tunfd = tunfd;
		threadpool[i].parent.ipv4 = ipv4;
		threadpool[i].parent.udp = udp;
		threadpool[i].handler = udp ? handler_udp : handler_tcp;

		ret = pthread_create(&threadpool[i].trid, NULL,
				     worker, &threadpool[i]);
		if (ret < 0)
			panic("Thread creation failed!\n");

		ret = pthread_setaffinity_np(threadpool[i].trid,
					     sizeof(cpu_set_t), &cpuset);
		if (ret < 0)
			panic("Thread CPU migration failed!\n");

		pthread_detach(threadpool[i].trid);
	}
}

static void thread_finish(unsigned int cpus)
{
	int i, ret;
	unsigned int threads;

	threads = cpus * THREADS_PER_CPU;
	for (i = 0; i < threads; ++i) {
		ret = pthread_join(threadpool[i].trid, NULL);
		if (ret < 0)
			continue;
		close(threadpool[i].efd[0]);
		close(threadpool[i].efd[1]);
	}
}

int server_main(int port, int udp, int lnum)
{
	int lfd = -1, kdpfd, nfds, nfd, curfds, efd[2], refd[2], tunfd;
	int ipv4 = 0, thread_it = 0, i;
	unsigned int cpus = 0, threads;
	ssize_t ret;
	struct epoll_event ev, *events;
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

	ret = pipe2(efd, O_NONBLOCK);
	if (ret < 0)
		panic("Cannot create parent event fd!\n");

	ret = pipe2(refd, O_NONBLOCK);
	if (ret < 0)
		panic("Cannot create parent (r)event fd!\n");

	set_nonblocking(lfd);
	set_nonblocking(tunfd);

	events = xzmalloc(MAX_EPOLL_SIZE * sizeof(*events));
	for (i = 0; i < MAX_EPOLL_SIZE; ++i)
		events[i].data.fd = -1;

	kdpfd = epoll_create(MAX_EPOLL_SIZE);
	if (kdpfd < 0)
		panic("Cannot create socket!\n");

	memset(&ev, 0, sizeof(ev));
	ev.events = udp ? EPOLLIN | EPOLLET | EPOLLONESHOT : EPOLLIN;
	ev.data.fd = lfd;
	ret = epoll_ctl(kdpfd, EPOLL_CTL_ADD, lfd, &ev);
	if (ret < 0)
		panic("Cannot add socket for epoll!\n");

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = efd[0];
	ret = epoll_ctl(kdpfd, EPOLL_CTL_ADD, efd[0], &ev);
	if (ret < 0)
		panic("Cannot add socket for events!\n");

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.fd = refd[0];
	ret = epoll_ctl(kdpfd, EPOLL_CTL_ADD, refd[0], &ev);
	if (ret < 0)
		panic("Cannot add socket for (r)events!\n");

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
	ev.data.fd = tunfd;
	ret = epoll_ctl(kdpfd, EPOLL_CTL_ADD, tunfd, &ev);
	if (ret < 0)
		panic("Cannot add socket for tundev!\n");

	curfds = 4;

	trie_init();

	cpus = get_number_cpus_online();
	threads = cpus * THREADS_PER_CPU;
	threadpool = xzmalloc(sizeof(*threadpool) * threads);
	thread_spawn_or_panic(cpus, efd[1], refd[1], tunfd, ipv4, udp);

	syslog(LOG_INFO, "tunnel id: %d, listener id: %d\n", tunfd, lfd);
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

				if (curfds + 1 > MAX_EPOLL_SIZE) {
					close(nfd);
					continue;
				}

				curfds++;

				memset(hbuff, 0, sizeof(hbuff));
				memset(sbuff, 0, sizeof(sbuff));

				getnameinfo((struct sockaddr *) &taddr, tlen,
					    hbuff, sizeof(hbuff),
					    sbuff, sizeof(sbuff),
					    NI_NUMERICHOST | NI_NUMERICSERV);

				syslog(LOG_INFO, "New connection from %s:%s "
				       "with id %d, %d active!\n",
				       hbuff, sbuff, nfd, curfds);

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

				ret = read_exact(refd[0], &fd_one, sizeof(fd_one));
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
				int fd_del;

				ret = read_exact(efd[0], &fd_del, sizeof(fd_del));
				if (ret != sizeof(fd_del) || fd_del <= 0)
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

				syslog(LOG_INFO, "Closed connection with "
				       "id %d, %d active!\n",
				       fd_del, curfds);
			} else {
				int fd_work = events[i].data.fd;

				ret = write_exact(threadpool[thread_it].efd[1],
						  &fd_work, sizeof(fd_work));
				if (ret != sizeof(fd_work))
					syslog(LOG_ERR, "Write error on event "
					       "dispatch: %s\n", strerror(errno));

				thread_it = (thread_it + 1) % threads;
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

	trie_cleanup();

	syslog(LOG_INFO, "curvetun shut down!\n");
	closelog();

	return 0;
}


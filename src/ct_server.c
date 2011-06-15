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
#include "locking.h"
#include "tlsf.h"
#include "netdev.h"
#include "write_or_die.h"
#include "psched.h"
#include "xmalloc.h"
#include "ct_server.h"
#include "curvetun.h"
#include "compiler.h"
#include "patricia.h"

struct worker_struct {
	int efd;
	unsigned int cpu;
	pthread_t thread;
	void *mmap_mempool_raw;
	void *mmap_mempool;
	size_t mmap_size;
};

static struct worker_struct *threadpool = NULL;

static unsigned int cpus = 0;

extern sig_atomic_t sigint;

static int efd_parent, fd_tun;

static struct patricia_node *tree = NULL;

static struct spinlock tree_lock;

static void *worker(void *self)
{
	uint64_t fd64;
	ssize_t ret, len, err;
	const struct worker_struct *ws = self;
	char buff[1600]; //XXX
	struct pollfd fds;

	init_memory_pool(ws->mmap_size - 2 * getpagesize(),
			 ws->mmap_mempool);

	fds.fd = ws->efd;
	fds.events = POLLIN;

	syslog(LOG_INFO, "curvetun thread %p/CPU%u up!\n", ws, ws->cpu);
	while (likely(!sigint)) {
		poll(&fds, 1, -1);
		ret = read(ws->efd, &fd64, sizeof(fd64));
		if (ret != sizeof(fd64)) {
			cpu_relax();
			sched_yield();
			continue;
		}
		if (fd64 == fd_tun) {
			printf("FROM TUNNEL\n");
			len = read(fd_tun, buff, sizeof(buff));
			if (len > 0) {
				/* todo: lookup right socket */
				err = write(0, buff, len);
			}
		} else {
			len = read((int) fd64, buff, sizeof(buff));
			if (len > 0) {
				err = write(fd_tun, buff, len);
			} else {
				if (len < 1 && errno != 11) {
					len = write(efd_parent, &fd64, sizeof(fd64));
					if (len != sizeof(fd64))
						whine("Event write error from thread!\n");
				}
			}
		}
	}

	destroy_memory_pool(ws->mmap_mempool);
	pthread_exit(0);
}

static void tspawn_or_panic(void)
{
	int i, ret, fd;
	cpu_set_t cpuset;

	fd = open_or_die("/dev/null", O_RDWR);

	for (i = 0; i < cpus * THREADS_PER_CPU; ++i) {
		CPU_ZERO(&cpuset);
		threadpool[i].cpu = i % cpus;
		CPU_SET(threadpool[i].cpu, &cpuset);

		threadpool[i].efd = eventfd(0, 0);
		if (threadpool[i].efd < 0)
			panic("Cannot create event socket!\n");

		threadpool[i].mmap_size = getpagesize() * (1 << 5);
		threadpool[i].mmap_mempool_raw = mmap(0, threadpool[i].mmap_size,
						      PROT_READ | PROT_WRITE,
						      MAP_PRIVATE | MAP_ANONYMOUS,
						      fd, 0);
		if (threadpool[i].mmap_mempool_raw == MAP_FAILED)
			panic("Cannot mmap memory!\n");
		ret = mprotect(threadpool[i].mmap_mempool_raw, getpagesize(),
			       PROT_NONE);
		if (ret < 0) {
			perror("");
			panic("Cannot protect pool start!\n");
		}
		ret = mprotect(threadpool[i].mmap_mempool_raw + (unsigned long)
			       threadpool[i].mmap_size - getpagesize(),
			       getpagesize(), PROT_NONE);
		if (ret < 0)
			panic("Cannot protect pool end!\n");
		threadpool[i].mmap_mempool = threadpool[i].mmap_mempool_raw +
					     getpagesize();

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

	close(fd);
}

static void tfinish(void)
{
	int i;
	for (i = 0; i < cpus * THREADS_PER_CPU; ++i) {
		close(threadpool[i].efd);
		pthread_cancel(threadpool[i].thread);
		munmap(threadpool[i].mmap_mempool_raw, threadpool[i].mmap_size);
	}
}

int server_main(int set_rlim, int port, int lnum)
{
	int lfd = -1, kdpfd, nfds, nfd, ret, curfds, i, trit;
	struct epoll_event lev, eev, tev, nev;
	struct epoll_event events[MAX_EPOLL_SIZE];
	struct rlimit rt;
	struct addrinfo hints, *ahead, *ai;
	struct sockaddr_storage taddr;
	socklen_t tlen;

	openlog("curvetun", LOG_PID | LOG_CONS | LOG_NDELAY, LOG_DAEMON);
	syslog(LOG_INFO, "curvetun server booting!\n");

	cpus = get_number_cpus_online();
	threadpool = xzmalloc(sizeof(*threadpool) * cpus * THREADS_PER_CPU);

	if (set_rlim) {
		rt.rlim_max = rt.rlim_cur = MAX_EPOLL_SIZE;
		ret = setrlimit(RLIMIT_NOFILE, &rt);
		if (ret < 0)
			whine("Cannot set rlimit!\n");
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = IPPROTO_TCP;

	fd_tun = tun_open_or_die(DEVNAME_SERVER);

	ret = getaddrinfo(NULL, "6666", &hints, &ahead);
	if (ret < 0)
		panic("Cannot get address info!\n");

	for (ai = ahead; ai != NULL && lfd < 0; ai = ai->ai_next) {
		lfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (lfd < 0)
			continue;

		set_nonblocking(lfd);
		set_reuseaddr(lfd);

		ret = bind(lfd, ai->ai_addr, ai->ai_addrlen);
		if (ret < 0) {
			close(lfd);
			lfd = -1;
			continue;
		}
		syslog(LOG_INFO, "curvetun bound!\n");

		ret = listen(lfd, 5);
		if (ret < 0) {
			close(lfd);
			lfd = -1;
			continue;
		}
		syslog(LOG_INFO, "curvetun listening!\n");
	}

	freeaddrinfo(ahead);
	if (lfd < 0)
		panic("Cannot create socket!\n");

	tspawn_or_panic();

	efd_parent = eventfd(0, 0);
	if (efd_parent < 0)
		panic("Cannot create parent event fd!\n");

	set_nonblocking(efd_parent);
	set_nonblocking(fd_tun);

	kdpfd = epoll_create(MAX_EPOLL_SIZE);
	if (kdpfd < 0)
		panic("Cannot create socket!\n");

	memset(&lev, 0, sizeof(lev));
	lev.events = EPOLLIN | EPOLLET;
	lev.data.fd = lfd;

	memset(&eev, 0, sizeof(lev));
	eev.events = EPOLLIN | EPOLLET;
	eev.data.fd = efd_parent;

	memset(&tev, 0, sizeof(tev));
	tev.events = EPOLLIN | EPOLLET;
	tev.data.fd = fd_tun;

	ret = epoll_ctl(kdpfd, EPOLL_CTL_ADD, lfd, &lev);
	if (ret < 0)
		panic("Cannot add socket for epoll!\n");

	ret = epoll_ctl(kdpfd, EPOLL_CTL_ADD, efd_parent, &eev);
	if (ret < 0)
		panic("Cannot add socket for events!\n");

	ret = epoll_ctl(kdpfd, EPOLL_CTL_ADD, fd_tun, &tev);
	if (ret < 0)
		panic("Cannot add socket for tundev!\n");

	trit = 0;
	curfds = 3;
	tlen = sizeof(taddr);

	syslog(LOG_INFO, "curvetun up and running!\n");

	while (likely(!sigint)) {
		nfds = epoll_wait(kdpfd, events, curfds, -1);
		if (nfds < 0) {
			break;
		}

		for (i = 0; i < nfds; ++i) {
			if (events[i].data.fd == lfd) {
				int one;
				char hbuff[256], sbuff[256];

				nfd = accept(lfd, (struct sockaddr *) &taddr, &tlen);
				if (nfd < 0) {
					perror("accept");
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
			} else if (events[i].data.fd == efd_parent) {
				uint64_t fd64_del;
				ret = read(efd_parent, &fd64_del, sizeof(fd64_del));
				if (ret != sizeof(fd64_del))
					continue;
				epoll_ctl(kdpfd, EPOLL_CTL_DEL, (int) fd64_del, &nev);
				curfds--;

				syslog(LOG_INFO, "Closed connection with id %d\n",
				       (int) fd64_del);
			} else {
				uint64_t fd64 = events[i].data.fd;
				ret = write(threadpool[trit].efd, &fd64,
					    sizeof(fd64));
				if (ret != sizeof(fd64))
					whine("Write error on event dispatch!\n");
				trit = (trit + 1) % cpus;
			}
		}
	}

	close(lfd);
	close(efd_parent);
	close(fd_tun);

	syslog(LOG_INFO, "curvetun shut down!\n");
	closelog();

	tfinish();
	xfree(threadpool);

	return 0;
}


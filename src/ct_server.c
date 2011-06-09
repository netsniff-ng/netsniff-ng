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
#include <numa.h>
#include <pthread.h>
#include <syslog.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <limits.h>

#include "die.h"
#include "locking.h"
#include "tlsf.h"
#include "netdev.h"
#include "psched.h"

#define MAX_THREADS	16
#define MAX_BUF		1024
#define MAX_EPOLL_SIZE	10000

struct worker_struct {
	unsigned int cpu;
	pthread_t thread;
	pthread_attr_t tattr;
	void *mempool;
	size_t spool;
	void *stack;
	size_t sstack;
};

static struct worker_struct threadpool[MAX_THREADS];

extern sig_atomic_t sigint;

int handle_frame(int new_fd)
{
	int len;
	char buf[MAX_BUF + 1];

	bzero(buf, MAX_BUF + 1);
	len = recv(new_fd, buf, MAX_BUF, 0);
	if (len > 0)
		printf("fd: %d: '%s'，len %d\n", new_fd, buf, len);
	else {
		if (len < 0)
			printf("err %d，'%s'\n", errno, strerror(errno));
		close(new_fd);
		return -1;
	}
	return len;
}

static void *worker(void *self)
{
	while (likely(!sigint)) {
		sleep(1);
	}
	pthread_exit(0);
}

static void tspawn_or_panic(void)
{
	int i, ret;
	unsigned int cpus = get_number_cpus_online();
	cpu_set_t cpuset;

	for (i = 0; i < MAX_THREADS; ++i) {
		CPU_ZERO(&cpuset);

		threadpool[i].cpu = i % cpus;
		threadpool[i].sstack = PTHREAD_STACK_MIN + 0x4000;
		threadpool[i].stack = numa_alloc_onnode(threadpool[i].sstack,
							0); /* FIXME */
		if (!threadpool[i].stack)
			panic("No mem left on node!\n");

		threadpool[i].spool = 4096;
		threadpool[i].mempool = numa_alloc_onnode(threadpool[i].spool,
							  0); /* FIXME */
		if (!threadpool[i].mempool)
			panic("No mem left on node!\n");

		CPU_SET(threadpool[i].cpu, &cpuset);

		ret = pthread_attr_init(&(threadpool[i].tattr));
		if (ret < 0)
			panic("Thread attribute init failed!\n");
		ret = pthread_attr_setinheritsched(&(threadpool[i].tattr),
						   PTHREAD_EXPLICIT_SCHED);
		if (ret < 0)
			panic("Thread attribute set failed!\n");
		ret = pthread_attr_setstack(&(threadpool[i].tattr),
					    threadpool[i].stack,
					    threadpool[i].sstack);
		if (ret < 0)
			panic("Thread attribute set failed!\n");

		ret = pthread_create(&(threadpool[i].thread),
				     &(threadpool[i].tattr), worker,
				     &threadpool[i]);
		if (ret < 0)
			panic("Thread creation failed!\n");

		ret = pthread_setaffinity_np(threadpool[i].thread,
					     sizeof(cpu_set_t), &cpuset);
		if (ret < 0)
			panic("Thread CPU migration failed!\n");

		pthread_detach(threadpool[i].thread);
	}
}

static void tfinish(void)
{
	int i;
	for (i = 0; i < MAX_THREADS; ++i) {
		pthread_cancel(threadpool[i].thread);

//		numa_free(threadpool[i].stack, threadpool[i].sstack);
//		numa_free(threadpool[i].mempool, threadpool[i].spool);

		pthread_attr_destroy(&(threadpool[i].tattr));
	}
}

int server_main(int set_rlim, int port, int lnum)
{
	int lfd, kdpfd, nfds, nfd, ret, curfds, i;
	struct sockaddr_in maddr, taddr;
	struct epoll_event lev;
	struct epoll_event events[MAX_EPOLL_SIZE];
	struct rlimit rt;
	socklen_t len;

	openlog("curvetun", LOG_PID | LOG_CONS | LOG_NDELAY, LOG_DAEMON);
	syslog(LOG_INFO, "curvetun server booting!\n");

	if (set_rlim) {
		rt.rlim_max = rt.rlim_cur = MAX_EPOLL_SIZE;
		ret = setrlimit(RLIMIT_NOFILE, &rt);
		if (ret < 0)
			whine("Cannot set rlimit!\n");
	}

	tspawn_or_panic();

	lfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (lfd < 0)
		panic("Cannot create socket!\n");

	set_nonblocking(lfd);
	set_reuseaddr(lfd);

	memset(&events, 0, sizeof(events));
	memset(&maddr, 0, sizeof(maddr));
	maddr.sin_family = PF_INET;
	maddr.sin_port = htons(port);
	maddr.sin_addr.s_addr = INADDR_ANY;

	ret = bind(lfd, (struct sockaddr *) &maddr, sizeof(struct sockaddr));
	if (ret < 0)
		panic("Cannot bind sock to address!\n");
	syslog(LOG_INFO, "curvetun bound to port %d!\n", port);

	ret = listen(lfd, lnum);
	if (ret < 0)
		panic("Cannot listen on socket!\n");
	syslog(LOG_INFO, "curvetun listening on port %d!\n", port);

	kdpfd = epoll_create(MAX_EPOLL_SIZE);
	if (kdpfd < 0)
		panic("Cannot create socket!\n");

	memset(&lev, 0, sizeof(lev));
	lev.events = EPOLLIN | EPOLLET;
	lev.data.fd = lfd;

	ret = epoll_ctl(kdpfd, EPOLL_CTL_ADD, lfd, &lev);
	if (ret < 0)
		panic("Cannot add socket for epoll!\n");

	curfds = 1;
	len = sizeof(struct sockaddr);

	while (likely(!sigint)) {
		nfds = epoll_wait(kdpfd, events, curfds, -1);
		if (nfds < 0) {
			break;
		}

		for (i = 0; i < nfds; ++i) {
			if (events[i].data.fd == lfd) {
				nfd = accept(lfd, (struct sockaddr *) &taddr, &len);
				if (nfd < 0) {
					continue;
				}

				syslog(LOG_INFO, "New connection from: %s:%d\n",
				       inet_ntoa(taddr.sin_addr),
				       ntohs(taddr.sin_port));

				set_nonblocking(nfd);

				lev.events = EPOLLIN | EPOLLET;
				lev.data.fd = nfd;

				ret = epoll_ctl(kdpfd, EPOLL_CTL_ADD, nfd, &lev);
				if (ret < 0)
					panic("Epoll ctl error!\n");
				curfds++;
			} else {
				ret = handle_frame(events[i].data.fd);
				if (ret < 1 && errno != 11) {
					epoll_ctl(kdpfd, EPOLL_CTL_DEL,
						  events[i].data.fd, &lev);
					curfds--;
				}
			}
		}
	}

	close(lfd);
	syslog(LOG_INFO, "curvetun shut down!\n");
	closelog();
	tfinish();

	return 0;
}


/*
 * curvetun - the cipherspace wormhole creator
 * Part of the netsniff-ng project
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann <daniel@netsniff-ng.org>,
 * Subject to the GPL.
 */

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

#include "die.h"
#include "locking.h"
#include "tlsf.h"
#include "netdev.h"

#define MAX_THREADS	16
#define MAX_BUF		1024
#define MAX_EPOLL_SIZE	10000

struct worker_struct {
	pthread_t thread;
	unsigned int cpu;
	void *mempool;
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

void *worker(void *init)
{
	while (likely(!sigint)) {
		sleep(0);
	}
	pthread_exit(0);
}

void spawn_or_panic(void)
{
	int i, ret;
	for (i = 0; i < MAX_THREADS; ++i) {
		ret = pthread_create(&(threadpool[i].thread), 0, worker, NULL);
		if (ret)
			panic("Thread creation failed!\n");
		pthread_detach(threadpool[i].thread);
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
			whine("epoll wait error: %d!\n", errno);
			break;
		}

		for (i = 0; i < nfds; ++i) {
			if (events[i].data.fd == lfd) {
				nfd = accept(lfd, (struct sockaddr *) &taddr, &len);
				if (nfd < 0) {
					whine("accept error: %d!\n", errno);
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

	return 0;
}


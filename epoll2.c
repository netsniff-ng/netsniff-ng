#include <sys/epoll.h>
#include <string.h>

#include "epoll2.h"
#include "die.h"

void set_epoll_descriptor(int fd_epoll, int action, int fd_toadd, int events)
{
	int ret;
	struct epoll_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.events = events;
	ev.data.fd = fd_toadd;

	ret = epoll_ctl(fd_epoll, action, fd_toadd, &ev);
	if (ret < 0)
		panic("Cannot add socket for epoll!\n");
}

int set_epoll_descriptor2(int fd_epoll, int action, int fd_toadd, int events)
{
	struct epoll_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.events = events;
	ev.data.fd = fd_toadd;

	return epoll_ctl(fd_epoll, action, fd_toadd, &ev);
}

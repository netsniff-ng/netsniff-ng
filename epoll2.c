/*
 * epoll2.c - kqueue implementation of epoll2 API
 */
#include <sys/event.h>
#include <sys/time.h>
#include <stdio.h>
#include "epoll2.h"
#include "die.h"

void set_epoll_descriptor(int fd_epoll, int action, int fd_toadd, int events)
{
    struct kevent ev;
    int filter = (events == EVFILT_WRITE) ? EVFILT_WRITE : EVFILT_READ;
    int flags  = (action == EV_DELETE) ? EV_DELETE : (EV_ADD | EV_ENABLE);

    EV_SET(&ev, fd_toadd, filter, flags, 0, 0, NULL);

    if (kevent(fd_epoll, &ev, 1, NULL, 0, NULL) < 0)
        panic("Cannot add descriptor to kqueue!\n");
}

int set_epoll_descriptor2(int fd_epoll, int action, int fd_toadd, int events)
{
    struct kevent ev;
    int filter = (events == EVFILT_WRITE) ? EVFILT_WRITE : EVFILT_READ;
    int flags  = (action == EV_DELETE) ? EV_DELETE : (EV_ADD | EV_ENABLE);

    EV_SET(&ev, fd_toadd, filter, flags, 0, 0, NULL);

    return kevent(fd_epoll, &ev, 1, NULL, 0, NULL);
}

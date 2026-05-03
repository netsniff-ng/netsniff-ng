/*
 * epoll2.h - kqueue drop-in for macOS BPF port
 */
#ifndef EPOLL2_H
#define EPOLL2_H

#include <sys/event.h>

/* Mirror the original epoll2 API exactly so callers don't change */
extern void set_epoll_descriptor(int fd_epoll, int action, int fd_toadd, int events);
extern int  set_epoll_descriptor2(int fd_epoll, int action, int fd_toadd, int events);

/* Map epoll constants to kqueue equivalents */
#ifndef EPOLLIN
# define EPOLLIN  EVFILT_READ
#endif
#ifndef EPOLLOUT
# define EPOLLOUT EVFILT_WRITE
#endif
#ifndef EPOLL_CTL_ADD
# define EPOLL_CTL_ADD EV_ADD
#endif
#ifndef EPOLL_CTL_MOD
# define EPOLL_CTL_MOD EV_ADD  /* kqueue: re-add with new flags = modify */
#endif
#ifndef EPOLL_CTL_DEL
# define EPOLL_CTL_DEL EV_DELETE
#endif

/* epoll_create → kqueue */
#ifndef epoll_create
# define epoll_create(n) kqueue()
#endif

/* epoll_wait → kevent */
#ifndef epoll_wait
# define epoll_wait(kq, events, n, ms) \
    kevent((kq), NULL, 0, (struct kevent *)(events), (n), NULL)
#endif

/* epoll_event → kevent */
#ifndef epoll_event
# define epoll_event kevent
#endif

#endif /* EPOLL2_H */

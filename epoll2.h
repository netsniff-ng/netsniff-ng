#ifndef __EPOLL_H
#define __EPOLL_H

extern void set_epoll_descriptor(int fd_epoll, int action, int fd_toadd, int events);
extern int set_epoll_descriptor2(int fd_epoll, int action, int fd_toadd, int events);

#endif /* __EPOLL_H */

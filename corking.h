#ifndef CORKING_H
#define CORKING_H

extern void set_tcp_cork(int fd);
extern void set_tcp_uncork(int fd);
extern void set_udp_cork(int fd);
extern void set_udp_uncork(int fd);
extern void set_sock_cork(int fd, int udp);
extern void set_sock_uncork(int fd, int udp);

#endif /* CORKING_H */

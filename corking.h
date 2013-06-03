#ifndef CORKING_H
#define CORKING_H

#include <stdbool.h>

extern void set_tcp_cork(int fd);
extern void set_tcp_uncork(int fd);
extern void set_udp_cork(int fd);
extern void set_udp_uncork(int fd);
extern void set_sock_cork(int fd, bool is_udp);
extern void set_sock_uncork(int fd, bool is_udp);

#endif /* CORKING_H */

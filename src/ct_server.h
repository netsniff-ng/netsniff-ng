/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef CT_SERVER_H
#define CT_SERVER_H

#define THREADS_PER_CPU 2
#define MAX_EPOLL_SIZE  10000

extern int server_main(int port, int lnum);

#define DEVNAME_SERVER "curves"

#endif /* CT_SERVER_H */


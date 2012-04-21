/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef CT_CPUSCHED_H
#define CT_CPUSCHED_H

extern void init_cpusched(unsigned int cpus);
extern unsigned int socket_to_cpu(int fd);
extern unsigned int register_socket(int fd);
extern void unregister_socket(int fd);
extern void destroy_cpusched(void);

#endif /* CT_CPUSCHED_H */

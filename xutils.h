/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010 Daniel Borkmann.
 * Copyright 2009, 2010 Emmanuel Roullit.
 * Subject to the GPL, version 2.
 */

#ifndef XSYS_H
#define XSYS_H

#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/ethtool.h>
#include <linux/if.h>
#include <linux/wireless.h>
#include <poll.h>
#include <sys/poll.h>
#include <sched.h>
#include <stdbool.h>
#include <sys/resource.h>
#include <sys/time.h>

#include "built_in.h"

extern int af_socket(int af);
extern int pf_socket(void);
extern int wireless_sigqual(const char *ifname, struct iw_statistics *stats);
extern int wireless_rangemax_sigqual(const char *ifname);
extern u32 wireless_bitrate(const char *ifname);
extern u32 ethtool_bitrate(const char *ifname);
extern int ethtool_drvinf(const char *ifname, struct ethtool_drvinfo *drvinf);
extern int ethtool_link(const char *ifname);
extern void drop_privileges(bool enforce, uid_t uid, gid_t gid);
extern void set_nonblocking(int fd);
extern int set_nonblocking_sloppy(int fd);
extern int set_reuseaddr(int fd);
extern void set_sock_prio(int fd, int prio);
extern void set_tcp_nodelay(int fd);
extern void set_socket_keepalive(int fd);
extern int set_ipv6_only(int fd);
extern void set_mtu_disc_dont(int fd);
extern int get_system_socket_mem(int which);
extern void set_system_socket_mem(int which, int val);
extern void register_signal(int signal, void (*handler)(int));
extern void register_signal_f(int signal, void (*handler)(int), int flags);
extern void set_epoll_descriptor(int fd_epoll, int action, int fd_toadd, int events);
extern int set_epoll_descriptor2(int fd_epoll, int action, int fd_toadd, int events);
extern void cpu_affinity(int cpu);
extern int set_proc_prio(int prio);
extern int set_sched_status(int policy, int priority);
extern int get_default_sched_policy(void);
extern int get_default_sched_prio(void);
extern int get_default_proc_prio(void);
extern void set_system_socket_memory(int *vals, size_t len);
extern void reset_system_socket_memory(int *vals, size_t len);
extern void set_itimer_interval_value(struct itimerval *itimer, unsigned long sec,
				      unsigned long usec);

#endif /* XSYS_H */

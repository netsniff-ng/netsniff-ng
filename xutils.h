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
extern u32 device_bitrate(const char *ifname);
extern int ethtool_drvinf(const char *ifname, struct ethtool_drvinfo *drvinf);
extern int ethtool_link(const char *ifname);
extern int device_mtu(const char *ifname);
extern int device_address(const char *ifname, int af, struct sockaddr_storage *ss);
extern void sock_print_net_stats(int sock);
extern int device_ifindex(const char *ifname);
extern short device_get_flags(const char *ifname);
extern void device_set_flags(const char *ifname, const short flags);
extern void drop_privileges(bool enforce, uid_t uid, gid_t gid);
extern void xlockme(void);
extern void xunlockme(void);
extern void set_nonblocking(int fd);
extern int set_nonblocking_sloppy(int fd);
extern int set_reuseaddr(int fd);
extern void set_sock_prio(int fd, int prio);
extern void set_tcp_cork(int fd);
extern void set_tcp_uncork(int fd);
extern void set_udp_cork(int fd);
extern void set_udp_uncork(int fd);
extern void set_sock_cork(int fd, int udp);
extern void set_sock_uncork(int fd, int udp);
extern void set_tcp_nodelay(int fd);
extern void set_socket_keepalive(int fd);
extern int set_ipv6_only(int fd);
extern void set_mtu_disc_dont(int fd);
extern int get_system_socket_mem(int which);
extern void set_system_socket_mem(int which, int val);
extern void register_signal(int signal, void (*handler)(int));
extern void register_signal_f(int signal, void (*handler)(int), int flags);
extern short enter_promiscuous_mode(char *ifname);
extern void leave_promiscuous_mode(char *ifname, short oldflags);
extern int device_up_and_running(char *ifname);
extern void set_epoll_descriptor(int fd_epoll, int action, int fd_toadd, int events);
extern int set_epoll_descriptor2(int fd_epoll, int action, int fd_toadd, int events);
extern void cpu_affinity(int cpu);
extern int set_cpu_affinity(char *str, int inverted);
extern int set_proc_prio(int prio);
extern int set_sched_status(int policy, int priority);
extern void ioprio_print(void);
extern void set_ioprio_rt(void);
extern void set_ioprio_be(void);
extern size_t strlcpy(char *dest, const char *src, size_t size);
extern int slprintf(char *dst, size_t size, const char *fmt, ...)  __check_format_printf(3, 4);
extern int slprintf_nocheck(char *dst, size_t size, const char *fmt, ...);
extern noinline void *xmemset(void *s, int c, size_t n);
extern char *strtrim_right(char *p, char c);
extern int get_default_sched_policy(void);
extern int get_default_sched_prio(void);
extern int get_number_cpus(void);
extern int get_number_cpus_online(void);
extern int get_default_proc_prio(void);
extern void set_system_socket_memory(int *vals, size_t len);
extern void reset_system_socket_memory(int *vals, size_t len);
extern void set_itimer_interval_value(struct itimerval *itimer, unsigned long sec,
				      unsigned long usec);

#endif /* XSYS_H */

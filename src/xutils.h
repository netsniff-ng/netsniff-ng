/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
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
#include <sys/resource.h>
#include <sys/time.h>

#include "die.h"
#include "built_in.h"

extern int af_socket(int af);
extern int pf_socket(void);
extern int wireless_bitrate(const char *ifname);
extern int adjust_dbm_level(int in_dbm, int dbm_val);
extern int wireless_sigqual(const char *ifname, struct iw_statistics *stats);
extern int wireless_rangemax_sigqual(const char *ifname);
extern int ethtool_bitrate(const char *ifname);
extern int ethtool_drvinf(const char *ifname, struct ethtool_drvinfo *drvinf);
extern int device_bitrate(const char *ifname);
extern int device_mtu(const char *ifname);
extern int device_address(const char *ifname, int af,
			  struct sockaddr_storage *ss);
extern int device_irq_number(const char *ifname);
extern int device_bind_irq_to_cpu(int irq, int cpu);
extern void sock_print_net_stats(int sock, unsigned long skipped);
extern int device_ifindex(const char *ifname);
extern short device_get_flags(const char *ifname);
extern void device_set_flags(const char *ifname, const short flags);
extern int set_nonblocking(int fd);
extern int set_nonblocking_sloppy(int fd);
extern int set_reuseaddr(int fd);
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
extern void register_signal(int signal, void (*handler)(int));
extern void register_signal_f(int signal, void (*handler)(int), int flags);
extern int get_tty_size(void);
extern void check_for_root_maybe_die(void);
extern short enter_promiscuous_mode(char *ifname);
extern void leave_promiscuous_mode(char *ifname, short oldflags);
extern int device_up(char *ifname);
extern int device_running(char *ifname);
extern int device_up_and_running(char *ifname);
extern int poll_error_maybe_die(int sock, struct pollfd *pfd);
extern void set_epoll_descriptor(int fd_epoll, int action,
				 int fd_toadd, int events);
extern int set_epoll_descriptor2(int fd_epoll, int action,
				 int fd_toadd, int events);
extern int set_cpu_affinity(char *str, int inverted);
extern int set_proc_prio(int prio);
extern int set_sched_status(int policy, int priority);
extern void ioprio_print(void);
extern void set_ioprio_rt(void);
extern void set_ioprio_be(void);
extern void xusleep(const struct timespec *ts_delay);
extern void xusleep2(long usecs);
extern int xnanosleep(double seconds);
extern int set_timeout(struct timeval *timeval, unsigned int msec);
extern size_t strlcpy(char *dest, const char *src, size_t size);
extern int slprintf(char *dst, size_t size, const char *fmt, ...);
extern noinline void *xmemset(void *s, int c, size_t n);
extern char *getuint(char *in, uint32_t *out);
extern char *strtrim_right(register char *p, register char c);
extern char *strtrim_left(register char *p, register char c);

static inline int get_default_sched_policy(void)
{
	return SCHED_FIFO;
}

static inline int get_default_sched_prio(void)
{
	return sched_get_priority_max(get_default_sched_policy());
}

static inline int get_number_cpus(void)
{
	return sysconf(_SC_NPROCESSORS_CONF);
}

static inline int get_number_cpus_online(void)
{
	return sysconf(_SC_NPROCESSORS_ONLN);
}

static inline int get_default_proc_prio(void)
{
	return -20;
}

static inline struct timeval tv_subtract(struct timeval time1,
					 struct timeval time2)
{
	/* time1 - time2 */
	struct timeval result;

	if ((time1.tv_sec < time2.tv_sec) || ((time1.tv_sec == time2.tv_sec) &&
	    (time1.tv_usec <= time2.tv_usec))) {
		result.tv_sec = result.tv_usec = 0;
	} else {
		result.tv_sec = time1.tv_sec - time2.tv_sec;
		if (time1.tv_usec < time2.tv_usec) {
			result.tv_usec = time1.tv_usec + 1000000L -
					 time2.tv_usec;
			result.tv_sec--;
		} else {
			result.tv_usec = time1.tv_usec - time2.tv_usec;
		}
	}

	return result;
}

static inline char *skips(char *p)
{
	return strtrim_left(p, ' ');
}

static inline char *skipchar(char *in, char c)
{
	if (*in != c)
		panic("Syntax error!\n");
	return ++in;
}

#endif /* XSYS_H */

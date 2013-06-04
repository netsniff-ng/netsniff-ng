/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010 Daniel Borkmann.
 * Copyright 2009, 2010 Emmanuel Roullit.
 * Subject to the GPL, version 2.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <ctype.h>
#include <signal.h>
#include <arpa/inet.h>
#include <time.h>
#include <sched.h>
#include <limits.h>
#include <stdbool.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <asm/unistd.h>
#include <linux/if.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "die.h"
#include "str.h"
#include "xutils.h"
#include "ring.h"
#include "built_in.h"

enum {
	sock_rmem_max = 0,
	sock_rmem_def,
	sock_wmem_max,
	sock_wmem_def,
};

#define SMEM_SUG_MAX	104857600
#define SMEM_SUG_DEF	4194304

static const char *const to_prio[] = {
	"none",
	"realtime",
	"best-effort",
	"idle",
};

static const char *const sock_mem[] = {
	"/proc/sys/net/core/rmem_max",
	"/proc/sys/net/core/rmem_default",
	"/proc/sys/net/core/wmem_max",
	"/proc/sys/net/core/wmem_default",
};

int af_socket(int af)
{
	int sock;

	if (unlikely(af != AF_INET && af != AF_INET6))
		panic("Wrong AF socket type!\n");

	sock = socket(af, SOCK_DGRAM, 0);
	if (unlikely(sock < 0))
		panic("Creation AF socket failed!\n");

	return sock;
}

int pf_socket(void)
{
	int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (unlikely(sock < 0))
		panic("Creation of PF socket failed!\n");

	return sock;
}

void set_sock_prio(int fd, int prio)
{
	int ret, val = prio;

	ret = setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &val, sizeof(val));
	if (unlikely(ret))
		panic("Cannot set socket priority!\n");
}

void set_nonblocking(int fd)
{
	int ret = fcntl(fd, F_SETFL, fcntl(fd, F_GETFD, 0) | O_NONBLOCK);
	if (unlikely(ret < 0))
		panic("Cannot fcntl!\n");
}

int set_nonblocking_sloppy(int fd)
{
	return fcntl(fd, F_SETFL, fcntl(fd, F_GETFD, 0) | O_NONBLOCK);
}

void set_socket_keepalive(int fd)
{
	int ret, one = 1;

	ret = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
	if (unlikely(ret))
		panic("Cannot set TCP keepalive!\n");
}

void set_tcp_nodelay(int fd)
{
	int one = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

int set_ipv6_only(int fd)
{
	int one = 1;
	return setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
}

int set_reuseaddr(int fd)
{
	int ret, one = 1;

	ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (unlikely(ret < 0))
		panic("Cannot reuse addr!\n");

	return 0;
}

void set_mtu_disc_dont(int fd)
{
	int mtu = IP_PMTUDISC_DONT, ret;

	ret = setsockopt(fd, SOL_IP, IP_MTU_DISCOVER, &mtu, sizeof(mtu));
	if (unlikely(ret))
		panic("Cannot set MTU discovery options!\n");
}

void set_epoll_descriptor(int fd_epoll, int action, int fd_toadd, int events)
{
	int ret;
	struct epoll_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.events = events;
	ev.data.fd = fd_toadd;

	ret = epoll_ctl(fd_epoll, action, fd_toadd, &ev);
	if (ret < 0)
		panic("Cannot add socket for epoll!\n");
}

int set_epoll_descriptor2(int fd_epoll, int action, int fd_toadd, int events)
{
	struct epoll_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.events = events;
	ev.data.fd = fd_toadd;

	return epoll_ctl(fd_epoll, action, fd_toadd, &ev);
}

u32 wireless_bitrate(const char *ifname)
{
	int sock, ret, rate_in_mbit;
	struct iwreq iwr;

	sock = af_socket(AF_INET);

	memset(&iwr, 0, sizeof(iwr));
	strlcpy(iwr.ifr_name, ifname, IFNAMSIZ);

	ret = ioctl(sock, SIOCGIWRATE, &iwr);
	if (!ret)
		rate_in_mbit = iwr.u.bitrate.value / 1000000;
	else
		rate_in_mbit = 0;

	close(sock);

	return rate_in_mbit;
}

int get_system_socket_mem(int which)
{
	int fd, val = -1;
	ssize_t ret;
	const char *file = sock_mem[which];
	char buff[64];

	fd = open(file, O_RDONLY);
	if (fd < 0)
		return val;

	ret = read(fd, buff, sizeof(buff));
	if (ret > 0)
		val = atoi(buff);

	close(fd);
	return val;
}

void set_system_socket_mem(int which, int val)
{
	int fd;
	const char *file = sock_mem[which];
	ssize_t ret;
	char buff[64];

	fd = open(file, O_WRONLY);
	if (fd < 0)
		return;

	memset(buff, 0, sizeof(buff));
	slprintf(buff, sizeof(buff), "%d", val);

	ret = write(fd, buff, strlen(buff));
	ret = ret;

	close(fd);
}

int wireless_sigqual(const char *ifname, struct iw_statistics *stats)
{
	int ret, sock;
	struct iwreq iwr;

	sock = af_socket(AF_INET);

	memset(&iwr, 0, sizeof(iwr));
	strlcpy(iwr.ifr_name, ifname, IFNAMSIZ);

	iwr.u.data.pointer = (caddr_t) stats;
	iwr.u.data.length = sizeof(*stats);
	iwr.u.data.flags = 1;

	ret = ioctl(sock, SIOCGIWSTATS, &iwr);

	close(sock);

	return ret;
}

int wireless_rangemax_sigqual(const char *ifname)
{
	int ret, sock, sigqual;
	struct iwreq iwr;
	struct iw_range iwrange;

	sock = af_socket(AF_INET);

	memset(&iwrange, 0, sizeof(iwrange));

	memset(&iwr, 0, sizeof(iwr));
	strlcpy(iwr.ifr_name, ifname, IFNAMSIZ);

	iwr.u.data.pointer = (caddr_t) &iwrange;
	iwr.u.data.length = sizeof(iwrange);
	iwr.u.data.flags = 0;

	ret = ioctl(sock, SIOCGIWRANGE, &iwr);
	if (!ret)
		sigqual = iwrange.max_qual.qual;
	else
		sigqual = 0;

	close(sock);

	return sigqual;
}

u32 ethtool_bitrate(const char *ifname)
{
	int ret, sock, bitrate;
	struct ifreq ifr;
	struct ethtool_cmd ecmd;

	sock = af_socket(AF_INET);

	memset(&ecmd, 0, sizeof(ecmd));

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	ecmd.cmd = ETHTOOL_GSET;
	ifr.ifr_data = (char *) &ecmd;

	ret = ioctl(sock, SIOCETHTOOL, &ifr);
	if (ret) {
		bitrate = 0;
		goto out;
	}

	switch (ecmd.speed) {
	case SPEED_10:
	case SPEED_100:
	case SPEED_1000:
	case SPEED_2500:
	case SPEED_10000:
		bitrate = ecmd.speed;
		break;
	default:
		bitrate = 0;
		break;
	};
out:
	close(sock);

	return bitrate;
}

int ethtool_link(const char *ifname)
{
	int ret, sock;
	struct ifreq ifr;
	struct ethtool_value ecmd;

	sock = af_socket(AF_INET);

	memset(&ecmd, 0, sizeof(ecmd));

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	ecmd.cmd = ETHTOOL_GLINK;
	ifr.ifr_data = (char *) &ecmd;

	ret = ioctl(sock, SIOCETHTOOL, &ifr);
	if (ret)
		ret = -EINVAL;
	else
		ret = !!ecmd.data;

	close(sock);
	return ret;
}

int ethtool_drvinf(const char *ifname, struct ethtool_drvinfo *drvinf)
{
	int ret, sock;
	struct ifreq ifr;

	sock = af_socket(AF_INET);

	memset(drvinf, 0, sizeof(*drvinf));

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	drvinf->cmd = ETHTOOL_GDRVINFO;
	ifr.ifr_data = (char *) drvinf;

	ret = ioctl(sock, SIOCETHTOOL, &ifr);

	close(sock);

	return ret;
}

void register_signal(int signal, void (*handler)(int))
{
	sigset_t block_mask;
	struct sigaction saction;

	sigfillset(&block_mask);

	saction.sa_handler = handler;
	saction.sa_mask = block_mask;
	saction.sa_flags = SA_RESTART;

	sigaction(signal, &saction, NULL);
}

void register_signal_f(int signal, void (*handler)(int), int flags)
{
	sigset_t block_mask;
	struct sigaction saction;

	sigfillset(&block_mask);

	saction.sa_handler = handler;
	saction.sa_mask = block_mask;
	saction.sa_flags = flags;

	sigaction(signal, &saction, NULL);
}

void cpu_affinity(int cpu)
{
	int ret;
	cpu_set_t cpu_bitmask;

	CPU_ZERO(&cpu_bitmask);
	CPU_SET(cpu, &cpu_bitmask);

	ret = sched_setaffinity(getpid(), sizeof(cpu_bitmask),
				&cpu_bitmask);
	if (ret)
		panic("Can't set this cpu affinity!\n");
}

int set_proc_prio(int priority)
{
	int ret = setpriority(PRIO_PROCESS, getpid(), priority);
	if (ret)
		panic("Can't set nice val to %i!\n", priority);

	return 0;
}

int set_sched_status(int policy, int priority)
{
	int ret, min_prio, max_prio;
	struct sched_param sp;

	max_prio = sched_get_priority_max(policy);
	min_prio = sched_get_priority_min(policy);

	if (max_prio == -1 || min_prio == -1)
		printf("Cannot determine scheduler prio limits!\n");
	else if (priority < min_prio)
		priority = min_prio;
	else if (priority > max_prio)
		priority = max_prio;

	memset(&sp, 0, sizeof(sp));
	sp.sched_priority = priority;

	ret = sched_setscheduler(getpid(), policy, &sp);
	if (ret) {
		printf("Cannot set scheduler policy!\n");
		return -EINVAL;
	}

	ret = sched_setparam(getpid(), &sp);
	if (ret) {
		printf("Cannot set scheduler prio!\n");
		return -EINVAL;
	}

	return 0;
}

int get_default_sched_policy(void)
{
	return SCHED_FIFO;
}

int get_default_sched_prio(void)
{
	return sched_get_priority_max(get_default_sched_policy());
}

int get_default_proc_prio(void)
{
	return -20;
}

void set_system_socket_memory(int *vals, size_t len)
{
	bug_on(len != 4);

	if ((vals[0] = get_system_socket_mem(sock_rmem_max)) < SMEM_SUG_MAX)
		set_system_socket_mem(sock_rmem_max, SMEM_SUG_MAX);
	if ((vals[1] = get_system_socket_mem(sock_rmem_def)) < SMEM_SUG_DEF)
		set_system_socket_mem(sock_rmem_def, SMEM_SUG_DEF);
	if ((vals[2] = get_system_socket_mem(sock_wmem_max)) < SMEM_SUG_MAX)
		set_system_socket_mem(sock_wmem_max, SMEM_SUG_MAX);
	if ((vals[3] = get_system_socket_mem(sock_wmem_def)) < SMEM_SUG_DEF)
		set_system_socket_mem(sock_wmem_def, SMEM_SUG_DEF);
}

void reset_system_socket_memory(int *vals, size_t len)
{
	bug_on(len != 4);

	set_system_socket_mem(sock_rmem_max, vals[0]);
	set_system_socket_mem(sock_rmem_def, vals[1]);
	set_system_socket_mem(sock_wmem_max, vals[2]);
	set_system_socket_mem(sock_wmem_def, vals[3]);
}

void set_itimer_interval_value(struct itimerval *itimer, unsigned long sec,
			       unsigned long usec)
{
	itimer->it_interval.tv_sec = sec;
	itimer->it_interval.tv_usec = usec;

	itimer->it_value.tv_sec = sec;
	itimer->it_value.tv_usec = usec;
}

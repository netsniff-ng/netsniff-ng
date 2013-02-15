/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Copyright 2009, 2010 Emmanuel Roullit.
 * Copyright 2010 Marek Polacek.
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
#include "xutils.h"
#include "ring.h"
#include "built_in.h"

#define IOPRIO_CLASS_SHIFT      13

enum {
	ioprio_class_none,
	ioprio_class_rt,
	ioprio_class_be,
	ioprio_class_idle,
};

enum {
	ioprio_who_process = 1,
	ioprio_who_pgrp,
	ioprio_who_user,
};

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
	int val = prio;
	setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &val, sizeof(val));
}

void set_udp_cork(int fd)
{
	int state = 1;
	setsockopt(fd, IPPROTO_UDP, UDP_CORK, &state, sizeof(state));
}

void set_udp_uncork(int fd)
{
	int state = 0;
	setsockopt(fd, IPPROTO_UDP, UDP_CORK, &state, sizeof(state));
}

void set_tcp_cork(int fd)
{
	int state = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));
}

void set_tcp_uncork(int fd)
{
	int state = 0;
	setsockopt(fd, IPPROTO_TCP, TCP_CORK, &state, sizeof(state));
}

void set_sock_cork(int fd, int udp)
{
	if (!!udp)
		set_udp_cork(fd);
	else
		set_tcp_cork(fd);
}

void set_sock_uncork(int fd, int udp)
{
	if (!!udp)
		set_udp_uncork(fd);
	else
		set_tcp_uncork(fd);
}

int set_nonblocking(int fd)
{
	int ret = fcntl(fd, F_SETFL, fcntl(fd, F_GETFD, 0) | O_NONBLOCK);
	if (unlikely(ret < 0))
		panic("Cannot fcntl!\n");

	return 0;
}

int set_nonblocking_sloppy(int fd)
{
	return fcntl(fd, F_SETFL, fcntl(fd, F_GETFD, 0) | O_NONBLOCK);
}

void set_socket_keepalive(int fd)
{
	int one = 1;
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
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
	int mtu = IP_PMTUDISC_DONT;
	setsockopt(fd, SOL_IP, IP_MTU_DISCOVER, &mtu, sizeof(mtu));
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

void drop_privileges(bool enforce, uid_t uid, gid_t gid)
{
	if (enforce) {
		if (uid == getuid())
			panic("Uid cannot be the same as the current user!\n");
		if (gid == getgid())
			panic("Gid cannot be the same as the current user!\n");
	}
	if (setgid(gid) != 0)
		panic("Unable to drop group privileges: %s!\n", strerror(errno));
	if (setuid(uid) != 0)
		panic("Unable to drop user privileges: %s!\n", strerror(errno));
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

u32 device_bitrate(const char *ifname)
{
	u32 speed_c, speed_w;

	speed_c = ethtool_bitrate(ifname);
	speed_w = wireless_bitrate(ifname);

	return (speed_c == 0 ? speed_w : speed_c);
}

int device_ifindex(const char *ifname)
{
	int ret, sock, index;
	struct ifreq ifr;

	if (!strncmp("any", ifname, strlen("any")))
		return 0;

	sock = af_socket(AF_INET);

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	ret = ioctl(sock, SIOCGIFINDEX, &ifr);
	if (!ret)
		index = ifr.ifr_ifindex;
	else
		index = -1;

	close(sock);

	return index;
}

static int __device_address6(const char *ifname, struct sockaddr_storage *ss)
{
	int ret, family, found = -EINVAL;
	struct ifaddrs *ifaddr, *ifa;

	ret = getifaddrs(&ifaddr);
	if (ret < 0)
		panic("Cannot get device addresses for IPv6!\n");

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		family = ifa->ifa_addr->sa_family;
		if (family != AF_INET6)
			continue;
		if (strcmp(ifa->ifa_name, ifname))
			continue;

		memcpy(ss, ifa->ifa_addr, sizeof(*ss));
		found = 0;
		break;
	}

	freeifaddrs(ifaddr);
	return found;
}

int device_address(const char *ifname, int af, struct sockaddr_storage *ss)
{
	int ret, sock;
	struct ifreq ifr;

	if (!ss)
		return -EINVAL;
	if (!strncmp("any", ifname, strlen("any")))
		return -EINVAL;
	if (af == AF_INET6)
		return __device_address6(ifname, ss);

	sock = af_socket(af);

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	ifr.ifr_addr.sa_family = af;

	ret = ioctl(sock, SIOCGIFADDR, &ifr);
	if (!ret)
		memcpy(ss, &ifr.ifr_addr, sizeof(ifr.ifr_addr));

	close(sock);

	return ret;
}

int device_mtu(const char *ifname)
{
	int ret, sock, mtu;
	struct ifreq ifr;

	sock = af_socket(AF_INET);

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	ret = ioctl(sock, SIOCGIFMTU, &ifr);
	if (!ret)
		mtu = ifr.ifr_mtu;
	else
		mtu = 0;

	close(sock);

	return mtu;
}

short device_get_flags(const char *ifname)
{
	/* Really, it's short! Look at struct ifreq */
	short flags;
	int ret, sock;
	struct ifreq ifr;

	sock = af_socket(AF_INET);

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	ret = ioctl(sock, SIOCGIFFLAGS, &ifr);
	if (!ret)
		flags = ifr.ifr_flags;
	else
		flags = 0;

	close(sock);

	return flags;
}

void device_set_flags(const char *ifname, const short flags)
{
	int ret, sock;
	struct ifreq ifr;

	sock = af_socket(AF_INET);

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	ifr.ifr_flags = flags;

	ret = ioctl(sock, SIOCSIFFLAGS, &ifr);
	if (ret < 0)
		panic("Cannot set NIC flags!\n");

	close(sock);
}

int device_irq_number(const char *ifname)
{
	/*
	 * Since fetching IRQ numbers from SIOCGIFMAP is deprecated and not
	 * supported anymore, we need to grab them from procfs
	 */
	int irq = 0;
	char *buffp;
	char buff[512];
	char sysname[512];
	FILE *fp;

	if (!strncmp("lo", ifname, strlen("lo")))
		return 0;

	fp = fopen("/proc/interrupts", "r");
	if (!fp)
		panic("Cannot open /proc/interrupts!\n");

	memset(buff, 0, sizeof(buff));
	while (fgets(buff, sizeof(buff), fp) != NULL) {
		buff[sizeof(buff) - 1] = 0;

		if (strstr(buff, ifname) == NULL)
			continue;

		buffp = buff;
		while (*buffp != ':')
			buffp++;
		*buffp = 0;
		irq = atoi(buff);

		memset(buff, 0, sizeof(buff));
	}

	fclose(fp);

	if (irq != 0)
		return irq;
	/* 
	 * Try sysfs as fallback. Probably wireless devices will be found
	 * here. We return silently if it fails ...
	 */
	slprintf(sysname, sizeof(sysname), "/sys/class/net/%s/device/irq",
		 ifname);

	fp = fopen(sysname, "r");
	if (!fp)
		return -ENOENT;

	memset(buff, 0, sizeof(buff));
	if(fgets(buff, sizeof(buff), fp) != NULL) {
		buff[sizeof(buff) - 1] = 0;
		irq = atoi(buff);
	}

	fclose(fp);

	return irq;
}

int device_set_irq_affinity_list(int irq, unsigned long from, unsigned long to)
{
	int ret, fd;
	char file[256], list[64];

	slprintf(file, sizeof(file), "/proc/irq/%d/smp_affinity_list", irq);
	slprintf(list, sizeof(list), "%lu-%lu\n", from, to);

	fd = open(file, O_WRONLY);
	if (fd < 0)
		return -ENOENT;

	ret = write(fd, list, strlen(list));

	close(fd);
	return ret;
}

int device_bind_irq_to_cpu(int irq, int cpu)
{
	int ret;
	char buff[256];
	char file[256];
	FILE *fp;

	/* Note: first CPU begins with CPU 0 */
	if (irq < 0 || cpu < 0)
		return -EINVAL;

	memset(file, 0, sizeof(file));
	memset(buff, 0, sizeof(buff));

	/* smp_affinity starts counting with CPU 1, 2, ... */
	cpu = cpu + 1;
	sprintf(file, "/proc/irq/%d/smp_affinity", irq);

	fp = fopen(file, "w");
	if (!fp)
		return -ENOENT;

	sprintf(buff, "%d", cpu);
	ret = fwrite(buff, sizeof(buff), 1, fp);

	fclose(fp);
	return (ret > 0 ? 0 : ret);
}

void sock_print_net_stats(int sock, unsigned long skipped)
{
	int ret;
	struct tpacket_stats kstats;

	socklen_t slen = sizeof(kstats);

	memset(&kstats, 0, sizeof(kstats));
	ret = getsockopt(sock, SOL_PACKET, PACKET_STATISTICS, &kstats, &slen);
	if (ret > -1) {
		uint64_t packets = kstats.tp_packets;
		uint64_t drops = kstats.tp_drops;

		printf("\r%12ld  packets incoming\n", packets);
		printf("\r%12ld  packets passed filter\n", packets - drops - skipped);
		printf("\r%12ld  packets failed filter (out of space)\n", drops + skipped);
		if (kstats.tp_packets > 0)
			printf("\r%12.4lf%\% packet droprate\n", (1.0 * drops / packets) * 100.0);
	}
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

short enter_promiscuous_mode(char *ifname)
{
	short ifflags;

	if (!strncmp("any", ifname, strlen("any")))
		return 0;

	ifflags = device_get_flags(ifname);
	device_set_flags(ifname, ifflags | IFF_PROMISC);

	return ifflags;
}

void leave_promiscuous_mode(char *ifname, short oldflags)
{
	if (!strncmp("any", ifname, strlen("any")))
		return;

	device_set_flags(ifname, oldflags);
}

int device_up_and_running(char *ifname)
{
	if (!ifname)
		return -EINVAL;
	if (!strncmp("any", ifname, strlen("any")))
		return 1;

	return (device_get_flags(ifname) & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING);
}

int poll_error_maybe_die(int sock, struct pollfd *pfd)
{
	if ((pfd->revents & (POLLHUP | POLLRDHUP | POLLERR | POLLNVAL)) == 0)
		return POLL_NEXT_PKT;
	if (pfd->revents & (POLLHUP | POLLRDHUP))
		panic("Hangup on socket occured!\n");
	if (pfd->revents & POLLERR) {
		int tmp;

		errno = 0;
		if (recv(sock, &tmp, sizeof(tmp), MSG_PEEK) >= 0)
			return POLL_NEXT_PKT;
		if (errno == ENETDOWN)
			panic("Interface went down!\n");

		return POLL_MOVE_OUT;
	}
	if (pfd->revents & POLLNVAL) {
		printf("Invalid polling request on socket!\n");

		return POLL_MOVE_OUT;
	}

	return POLL_NEXT_PKT;
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

static inline int ioprio_set(int which, int who, int ioprio)
{
	return syscall(SYS_ioprio_set, which, who, ioprio);
}

static inline int ioprio_get(int which, int who)
{
	return syscall(SYS_ioprio_get, which, who);
}

static void ioprio_setpid(pid_t pid, int ioprio, int ioclass)
{
	int ret = ioprio_set(ioprio_who_process, pid,
			     ioprio | ioclass << IOPRIO_CLASS_SHIFT);
	if (ret < 0)
		panic("Failed to set io prio for pid!\n");
}

void ioprio_print(void)
{
	int ioprio = ioprio_get(ioprio_who_process, getpid());
	if (ioprio < 0)
		panic("Failed to fetch io prio for pid!\n");
	else {
		int ioclass = ioprio >> IOPRIO_CLASS_SHIFT;
		if (ioclass != ioprio_class_idle) {
			ioprio &= 0xff;
			printf("%s: prio %d\n", to_prio[ioclass], ioprio);
		} else
			printf("%s\n", to_prio[ioclass]);
	}
}

void set_ioprio_rt(void)
{
	ioprio_setpid(getpid(), 4, ioprio_class_rt);
}

void set_ioprio_be(void)
{
	ioprio_setpid(getpid(), 4, ioprio_class_be);
}

void xlockme(void)
{
	if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0)
		panic("Cannot lock pages!\n");
}

void xunlockme(void)
{
	munlockall();
}

size_t strlcpy(char *dest, const char *src, size_t size)
{
	size_t ret = strlen(src);

	if (size) {
		size_t len = (ret >= size) ? size - 1 : ret;

		memcpy(dest, src, len);
		dest[len] = '\0';
	}

	return ret;
}

static inline int vslprintf(char *dst, size_t size, const char *fmt, va_list ap)
{
	int ret;

	ret = vsnprintf(dst, size, fmt, ap);
	dst[size - 1] = '\0';

	return ret;
}

int slprintf(char *dst, size_t size, const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vslprintf(dst, size, fmt, ap);
	va_end(ap);

	return ret;
}

int slprintf_nocheck(char *dst, size_t size, const char *fmt, ...)
{
	int ret;
	va_list ap;

	va_start(ap, fmt);
	ret = vslprintf(dst, size, fmt, ap);
	va_end(ap);

	return ret;
}

noinline void *xmemset(void *s, int c, size_t n)
{
	size_t i;
	uint8_t *ptr = s;

	for (i = 0; i < n; ++i)
		ptr[i] = (uint8_t) c;

	return ptr;
}

char *strtrim_right(register char *p, register char c)
{
	register char *end;
	register int len;

	len = strlen(p);
	while (*p && len) {
		end = p + len - 1;
		if (c == *end)
			*end = 0;
		else
			break;
		len = strlen(p);
	}

	return p;
}

static char *strtrim_left(register char *p, register char c)
{
	register int len;

	len = strlen(p);
	while (*p && len--) {
		if (c == *p)
			p++;
		else
			break;
	}

	return p;
}

char *skips(char *p)
{
	return strtrim_left(p, ' ');
}

int get_default_sched_policy(void)
{
	return SCHED_FIFO;
}

int get_default_sched_prio(void)
{
	return sched_get_priority_max(get_default_sched_policy());
}

int get_number_cpus(void)
{
	return sysconf(_SC_NPROCESSORS_CONF);
}

int get_number_cpus_online(void)
{
	return sysconf(_SC_NPROCESSORS_ONLN);
}

int get_default_proc_prio(void)
{
	return -20;
}

struct timeval tv_subtract(struct timeval time1, struct timeval time2)
{
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

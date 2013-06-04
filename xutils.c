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
#include "sock.h"
#include "built_in.h"

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

void set_itimer_interval_value(struct itimerval *itimer, unsigned long sec,
			       unsigned long usec)
{
	itimer->it_interval.tv_sec = sec;
	itimer->it_interval.tv_usec = usec;

	itimer->it_value.tv_sec = sec;
	itimer->it_value.tv_usec = usec;
}

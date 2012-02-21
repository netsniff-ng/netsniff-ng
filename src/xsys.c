/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
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
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
/* Kernel < 2.6.26 */
#include <linux/if.h>
#include <linux/socket.h>
#include <linux/types.h>
/* Kernel < 2.6.26 */
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <sched.h>
#include <sys/resource.h>

#include "die.h"
#include "xsys.h"
#include "strlcpy.h"

int af_socket(int af)
{
	int sock;
	if (af != AF_INET && af != AF_INET6) {
		whine("Wrong AF socket type! Falling back to AF_INET\n");
		af = AF_INET;
	}
	sock = socket(af, SOCK_DGRAM, 0);
	if (sock < 0)
		panic("Creation AF socket failed!\n");
	return sock;
}

int af_raw_socket(int af, int proto)
{
	int sock;
	if (af != AF_INET && af != AF_INET6) {
		whine("Wrong AF socket type! Falling back to AF_INET\n");
		af = AF_INET;
	}
	sock = socket(af, SOCK_RAW, proto);
	if (sock < 0)
		panic("Creation AF socket failed!\n");
	return sock;
}

int pf_socket(void)
{
	int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0)
		panic("Creation of PF socket failed!\n");
	return sock;
}

int set_nonblocking(int fd)
{
	int ret = fcntl(fd, F_SETFL, fcntl(fd, F_GETFD, 0) | O_NONBLOCK);
	if (ret < 0)
		panic("Cannot fcntl!\n");
	return 0;
}

int set_nonblocking_sloppy(int fd)
{
	return fcntl(fd, F_SETFL, fcntl(fd, F_GETFD, 0) | O_NONBLOCK);
}

int set_reuseaddr(int fd)
{
	int one = 1;
	int ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof (one));
	if (ret < 0)
		panic("Cannot reuse addr!\n");
	return 0;
}

int wireless_bitrate(const char *ifname)
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

int wireless_essid(const char *ifname, char *essid)
{
	int ret, sock, essid_len;
	struct iwreq iwr;
	sock = af_socket(AF_INET);
	memset(&iwr, 0, sizeof(iwr));
	strlcpy(iwr.ifr_name, ifname, IFNAMSIZ);
	iwr.u.essid.pointer = essid;
	iwr.u.essid.length = IW_ESSID_MAX_SIZE;
	ret = ioctl(sock, SIOCGIWESSID, &iwr);
	if (!ret)
		essid_len = iwr.u.essid.length;
	else
		essid_len = 0;
	close(sock);
	return essid_len;
}

int adjust_dbm_level(int dbm_val)
{
	if (dbm_val >= 64)
		dbm_val -= 0x100;
	return dbm_val;
}

int dbm_to_mwatt(const int in)
{
	/* From Jean Tourrilhes <jt@hpl.hp.com> (iwlib.c) */
	int ip = in / 10;
	int fp = in % 10;
	int k;
	double res = 1.0;
	for (k = 0; k < ip; k++)
		res *= 10;
	for (k = 0; k < fp; k++)
		res *= 1.25892541179; /* LOG10_MAGIC */
	return (int) res;
}

int wireless_tx_power(const char *ifname)
{
	int ret, sock, tx_power;
	struct iwreq iwr;

	sock = af_socket(AF_INET);

	memset(&iwr, 0, sizeof(iwr));
	strlcpy(iwr.ifr_name, ifname, IFNAMSIZ);

	ret = ioctl(sock, SIOCGIWTXPOW, &iwr);
	if (!ret)
		tx_power = iwr.u.txpower.value;
	else 
		tx_power = 0;

	close(sock);
	return ret;
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

int ethtool_bitrate(const char *ifname)
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

int device_bitrate(const char *ifname)
{
	int speed_c, speed_w;
	/* Probe for speed rates */
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

int device_address(const char *ifname, int af, struct sockaddr_storage *ss)
{
	int ret, sock;
	struct ifreq ifr;
	if (!ss)
		return -EINVAL;
	if (!strncmp("any", ifname, strlen("any")))
		return -EINVAL;
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
	if (!strncmp("lo", ifname, strlen("lo")))
		return 0;
	FILE *fp = fopen("/proc/interrupts", "r");
	if (!fp) {
		whine("Cannot open /proc/interrupts!\n");
		return -ENOENT;
	}
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

int device_bind_irq_to_cpu(int irq, int cpu)
{
	int ret;
	char buff[256];
	char file[256];
	/* Note: first CPU begins with CPU 0 */
	if (irq < 0 || cpu < 0)
		return -EINVAL;
	memset(file, 0, sizeof(file));
	memset(buff, 0, sizeof(buff));
	/* smp_affinity starts counting with CPU 1, 2, ... */
	cpu = cpu + 1;
	sprintf(file, "/proc/irq/%d/smp_affinity", irq);
	FILE *fp = fopen(file, "w");
	if (!fp) {
		whine("Cannot open file %s!\n", file);
		return -ENOENT;
	}
	sprintf(buff, "%d", cpu);
	ret = fwrite(buff, sizeof(buff), 1, fp);
	fclose(fp);
	return (ret > 0 ? 0 : ret);
}

void sock_print_net_stats(int sock)
{
	int ret;
	struct tpacket_stats kstats;
	socklen_t slen = sizeof(kstats);
	memset(&kstats, 0, sizeof(kstats));
	ret = getsockopt(sock, SOL_PACKET, PACKET_STATISTICS, &kstats, &slen);
	if (ret > -1) {
		printf("\r%12d  frames incoming\n",
		       kstats.tp_packets);
		printf("\r%12d  frames passed filter\n", 
		       kstats.tp_packets - kstats.tp_drops);
		printf("\r%12d  frames failed filter (out of space)\n",
		       kstats.tp_drops);
		if (kstats.tp_packets > 0)
			printf("\r%12.4f%% frame droprate\n", 1.f *
			       kstats.tp_drops / kstats.tp_packets * 100.f);
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

int get_tty_size(void)
{
#ifdef TIOCGSIZE
	struct ttysize ts = {0};
	int ret = ioctl(0, TIOCGSIZE, &ts);
	return (ret == 0 ? ts.ts_cols : DEFAULT_TTY_SIZE);
#elif defined(TIOCGWINSZ)
	struct winsize ts;
	memset(&ts, 0, sizeof(ts));
	int ret = ioctl(0, TIOCGWINSZ, &ts);
	return (ret == 0 ? ts.ws_col : DEFAULT_TTY_SIZE);
#else
	return DEFAULT_TTY_SIZE;
#endif
}

void check_for_root_maybe_die(void)
{
	if (geteuid() != 0 || geteuid() != getuid())
		panic("Uhhuh, not root?!\n");
}

short enter_promiscuous_mode(char *ifname)
{
	if (!strncmp("any", ifname, strlen("any")))
		return 0;
	short ifflags = device_get_flags(ifname);
	device_set_flags(ifname, ifflags | IFF_PROMISC);
	return ifflags;
}

void leave_promiscuous_mode(char *ifname, short oldflags)
{
	if (!strncmp("any", ifname, strlen("any")))
		return;
	device_set_flags(ifname, oldflags);
}

int device_up(char *ifname)
{
	if (!ifname)
		return -EINVAL;
	if (!strncmp("any", ifname, strlen("any")))
		return 1;
	return (device_get_flags(ifname) & IFF_UP) == IFF_UP;
}

int device_running(char *ifname)
{
	if (!ifname)
		return -EINVAL;
	if (!strncmp("any", ifname, strlen("any")))
		return 1;
	return (device_get_flags(ifname) & IFF_RUNNING) == IFF_RUNNING;
}

int device_up_and_running(char *ifname)
{
	if (!ifname)
		return -EINVAL;
	if (!strncmp("any", ifname, strlen("any")))
		return 1;
	return (device_get_flags(ifname) & (IFF_UP | IFF_RUNNING)) ==
	       (IFF_UP | IFF_RUNNING);
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
		/* recv is more specififc on the error */
		if (recv(sock, &tmp, sizeof(tmp), MSG_PEEK) >= 0)
			return POLL_NEXT_PKT;
		if (errno == ENETDOWN)
			panic("Interface went down!\n");
		return POLL_MOVE_OUT;
	}
	if (pfd->revents & POLLNVAL) {
		whine("Invalid polling request on socket!\n");
		return POLL_MOVE_OUT;
	}
	return POLL_NEXT_PKT;
}

static inline const char *next_token(const char *q, int sep)
{
	if (q)
		q = strchr(q, sep);
	if (q)
		q++;
	return (q);
}

int set_cpu_affinity(const char *str, int inverted)
{
	int ret, i, cpus;
	const char *p, *q;
	cpu_set_t cpu_bitmask;
	q = str;
	cpus = get_number_cpus();
	CPU_ZERO(&cpu_bitmask);
	for (i = 0; inverted && i < cpus; ++i)
		CPU_SET(i, &cpu_bitmask);
	while (p = q, q = next_token(q, ','), p) {
		unsigned int a;	 /* Beginning of range */
		unsigned int b;	 /* End of range */
		unsigned int s;	 /* Stride */
		const char *c1, *c2;
		if (sscanf(p, "%u", &a) < 1)
			return -EINVAL;
		b = a;
		s = 1;
		c1 = next_token(p, '-');
		c2 = next_token(p, ',');
		if (c1 != NULL && (c2 == NULL || c1 < c2)) {
			if (sscanf(c1, "%u", &b) < 1)
				return -EINVAL;
			c1 = next_token(c1, ':');
			if (c1 != NULL && (c2 == NULL || c1 < c2))
				if (sscanf(c1, "%u", &s) < 1)
					return -EINVAL;
		}
		if (!(a <= b))
			return -EINVAL;
		while (a <= b) {
			if (inverted)
				CPU_CLR(a, &cpu_bitmask);
			else
				CPU_SET(a, &cpu_bitmask);
			a += s;
		}
	}
	ret = sched_setaffinity(getpid(), sizeof(cpu_bitmask),
				&cpu_bitmask);
	if (ret)
		panic("Can't set this cpu affinity!\n");
	return 0;
}

char *get_cpu_affinity(char *cpu_string, size_t len)
{
	int ret, i, cpu;
	cpu_set_t cpu_bitmask;
	if (len != get_number_cpus() + 1)
		return NULL;
	CPU_ZERO(&cpu_bitmask);
	ret = sched_getaffinity(getpid(), sizeof(cpu_bitmask),
				&cpu_bitmask);
	if (ret) {
		whine("Can't fetch cpu affinity!\n");
		return NULL;
	}
	for (i = 0, cpu_string[len - 1] = 0; i < len - 1; ++i) {
		cpu = CPU_ISSET(i, &cpu_bitmask);
		cpu_string[i] = (cpu ? '1' : '0');
	}
	return cpu_string;
}

int set_proc_prio(int priority)
{
	/*
	 * setpriority() is clever, even if you put a nice value which 
	 * is out of range it corrects it to the closest valid nice value
	 */
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
		whine("Cannot determine scheduler prio limits!\n");
	else if (priority < min_prio)
		priority = min_prio;
	else if (priority > max_prio)
		priority = max_prio;
	memset(&sp, 0, sizeof(sp));
	sp.sched_priority = priority;
	ret = sched_setscheduler(getpid(), policy, &sp);
	if (ret) {
		whine("Cannot set scheduler policy!\n");
		return -EINVAL;
	}
	ret = sched_setparam(getpid(), &sp);
	if (ret) {
		whine("Cannot set scheduler prio!\n");
		return -EINVAL;
	}
	return 0;
}

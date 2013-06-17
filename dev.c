#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <ifaddrs.h>

#include "dev.h"
#include "str.h"
#include "sock.h"
#include "die.h"
#include "link.h"
#include "built_in.h"

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
	if (unlikely(ret))
		panic("Cannot get ifindex from device!\n");

	index = ifr.ifr_ifindex;
	close(sock);

	return index;
}

static int __device_address6(const char *ifname, struct sockaddr_storage *ss)
{
	int ret, family, found = -EINVAL;
	struct ifaddrs *ifaddr, *ifa;

	ret = getifaddrs(&ifaddr);
	if (unlikely(ret < 0))
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

	if (unlikely(!ss))
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
	int ret, sock, mtu = 0;
	struct ifreq ifr;

	sock = af_socket(AF_INET);

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	ret = ioctl(sock, SIOCGIFMTU, &ifr);
	if (!ret)
		mtu = ifr.ifr_mtu;

	close(sock);
	return mtu;
}

short device_get_flags(const char *ifname)
{
	short flags = 0;
	int ret, sock;
	struct ifreq ifr;

	sock = af_socket(AF_INET);

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	ret = ioctl(sock, SIOCGIFFLAGS, &ifr);
	if (!ret)
		flags = ifr.ifr_flags;

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

int device_up_and_running(char *ifname)
{
	if (!ifname)
		return -EINVAL;
	if (!strncmp("any", ifname, strlen("any")))
		return 1;

	return (device_get_flags(ifname) &
		(IFF_UP | IFF_RUNNING)) ==
		(IFF_UP | IFF_RUNNING);
}

u32 device_bitrate(const char *ifname)
{
	u32 scopper, swireless;

	scopper   = ethtool_bitrate(ifname);
	swireless = wireless_bitrate(ifname);

	return scopper ? : swireless;
}

#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_arp.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

#include "dev.h"
#include "str.h"
#include "sock.h"
#include "die.h"
#include "link.h"
#include "built_in.h"

int __device_ifindex(const char *ifname)
{
	int ret, sock, index;
	struct ifreq ifr;

	if (!strncmp("any", ifname, strlen("any")))
		return 0;

	sock = af_socket(AF_INET);

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	ret = ioctl(sock, SIOCGIFINDEX, &ifr);
	if (ret)
		index = -1;
	else
		index = ifr.ifr_ifindex;

	close(sock);

	return index;
}

int device_ifindex(const char *ifname)
{
	int index = __device_ifindex(ifname);

	if (unlikely(index < 0))
		panic("Cannot get ifindex from device!\n");

	return index;
}

int device_type(const char *ifname)
{
	int ret, sock, type;
	struct ifreq ifr;

	if (!strncmp("any", ifname, strlen("any")))
		return ARPHRD_ETHER;

	sock = af_socket(AF_INET);

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	ret = ioctl(sock, SIOCGIFHWADDR, &ifr);
	if (unlikely(ret))
		panic("Cannot get iftype from device!\n");

	/* dev->type */
	type = ifr.ifr_hwaddr.sa_family;
	close(sock);

	return type;
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
	if (likely(!ret))
		memcpy(ss, &ifr.ifr_addr, sizeof(ifr.ifr_addr));

	close(sock);
	return ret;
}

int device_hw_address(const char *ifname, uint8_t *addr, size_t len)
{
	int ret, sock;
	struct ifreq ifr;

	if (!addr)
		return -EINVAL;
	if (len < IFHWADDRLEN)
		return -ENOSPC;
	if (!strncmp("any", ifname, strlen("any")))
		return -EINVAL;

	sock = af_socket(AF_INET);

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	ret = ioctl(sock, SIOCGIFHWADDR, &ifr);
	if (!ret)
		memcpy(addr, &ifr.ifr_hwaddr.sa_data[0], IFHWADDRLEN);

	close(sock);
	return ret;
}

size_t device_mtu(const char *ifname)
{
	size_t mtu = 0;
	int ret, sock;
	struct ifreq ifr;

	sock = af_socket(AF_INET);

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

	ret = ioctl(sock, SIOCGIFMTU, &ifr);
	if (likely(!ret))
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
	if (likely(!ret))
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
	if (unlikely(ret < 0))
		panic("Cannot set NIC flags (%s)!\n", strerror(errno));

	close(sock);
}

int device_up_and_running(const char *ifname)
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

short device_enter_promiscuous_mode(const char *ifname)
{
	short ifflags;

	if (!strncmp("any", ifname, strlen("any")))
		return 0;

	ifflags = device_get_flags(ifname);
	device_set_flags(ifname, ifflags | IFF_PROMISC);

	return ifflags;
}

void device_leave_promiscuous_mode(const char *ifname, short oldflags)
{
	if (!strncmp("any", ifname, strlen("any")))
		return;

	device_set_flags(ifname, oldflags);
}

const char *device_type2str(uint16_t type)
{
	switch (type) {
	case ARPHRD_ETHER:
		return "ether";
	case ARPHRD_EETHER:
		return "eether";
	case ARPHRD_AX25:
		return "ax25";
	case ARPHRD_PRONET:
		return "pronet";
	case ARPHRD_CHAOS:
		return "chaos";
	case ARPHRD_IEEE802:
		return "ieee802";
	case ARPHRD_ARCNET:
		return "arcnet";
	case ARPHRD_APPLETLK:
		return "appletlk";
	case ARPHRD_DLCI:
		return "dlci";
	case ARPHRD_ATM:
		return "atm";
	case ARPHRD_METRICOM:
		return "metricom";
	case ARPHRD_IEEE1394:
		return "ieee1394";
	case ARPHRD_INFINIBAND:
		return "infiniband";
	case ARPHRD_SLIP:
		return "slip";
	case ARPHRD_CSLIP:
		return "cslip";
	case ARPHRD_SLIP6:
		return "slip6";
	case ARPHRD_CSLIP6:
		return "cslip6";
	case ARPHRD_RSRVD:
		return "RSRVD";
	case ARPHRD_ADAPT:
		return "adapt";
	case ARPHRD_ROSE:
		return "rose";
	case ARPHRD_X25:
		return "x25";
	case ARPHRD_HWX25:
		return "hwx25";
	case ARPHRD_CAN:
		return "can";
	case ARPHRD_PPP:
		return "ppp";
	case ARPHRD_HDLC:
		return "hdlc";
	case ARPHRD_LAPB:
		return "lapb";
	case ARPHRD_DDCMP:
		return "ddcmp";
	case ARPHRD_RAWHDLC:
		return "rawhdlc";
	case ARPHRD_TUNNEL:
		return "tunnel";
	case ARPHRD_TUNNEL6:
		return "tunnel6";
	case ARPHRD_FRAD:
		return "frad";
	case ARPHRD_SKIP:
		return "skip";
	case ARPHRD_LOOPBACK:
		return "loopback";
	case ARPHRD_LOCALTLK:
		return "localtlk";
	case ARPHRD_FDDI:
		return "fddi";
	case ARPHRD_BIF:
		return "bif";
	case ARPHRD_SIT:
		return "sit";
	case ARPHRD_IPDDP:
		return "ipddp";
	case ARPHRD_IPGRE:
		return "ipgre";
	case ARPHRD_PIMREG:
		return "pimreg";
	case ARPHRD_HIPPI:
		return "hippi";
	case ARPHRD_ASH:
		return "ash";
	case ARPHRD_ECONET:
		return "econet";
	case ARPHRD_IRDA:
		return "irda";
	case ARPHRD_FCPP:
		return "fcpp";
	case ARPHRD_FCAL:
		return "fcal";
	case ARPHRD_FCPL:
		return "fcpl";
	case ARPHRD_FCFABRIC:
		return "fcfb0";
	case ARPHRD_FCFABRIC + 1:
		return "fcfb1";
	case ARPHRD_FCFABRIC + 2:
		return "fcfb2";
	case ARPHRD_FCFABRIC + 3:
		return "fcfb3";
	case ARPHRD_FCFABRIC + 4:
		return "fcfb4";
	case ARPHRD_FCFABRIC + 5:
		return "fcfb5";
	case ARPHRD_FCFABRIC + 6:
		return "fcfb6";
	case ARPHRD_FCFABRIC + 7:
		return "fcfb7";
	case ARPHRD_FCFABRIC + 8:
		return "fcfb8";
	case ARPHRD_FCFABRIC + 9:
		return "fcfb9";
	case ARPHRD_FCFABRIC + 10:
		return "fcfb10";
	case ARPHRD_FCFABRIC + 11:
		return "fcfb11";
	case ARPHRD_FCFABRIC + 12:
		return "fcfb12";
	case ARPHRD_IEEE802_TR:
		return "ieee802_tr";
	case ARPHRD_IEEE80211:
		return "ieee80211";
	case ARPHRD_IEEE80211_PRISM:
		return "ieee80211_prism";
	case ARPHRD_IEEE80211_RADIOTAP:
		return "ieee80211_radiotap";
	case ARPHRD_IEEE802154:
		return "ieee802154";
	case ARPHRD_PHONET:
		return "phonet";
	case ARPHRD_PHONET_PIPE:
		return "phonet_pipe";
	case ARPHRD_CAIF:
		return "caif";
	case ARPHRD_IP6GRE:
		return "ip6gre";
	case ARPHRD_NETLINK:
		return "netlink";
	case ARPHRD_NONE:
		return "none";
	case ARPHRD_VOID:
		return "void";
	default:
		return "Unknown";
	}
}

/* Taken from iproute2 ll_addr_n2a func */
const char *device_addr2str(const unsigned char *addr, int alen, int type,
			    char *buf, int blen)
{
	int i, l;

	if (alen == 4 &&
	    (type == ARPHRD_TUNNEL || type == ARPHRD_SIT ||
	     type == ARPHRD_IPGRE))
		return inet_ntop(AF_INET, addr, buf, blen);

	if (alen == 16 && type == ARPHRD_TUNNEL6)
		return inet_ntop(AF_INET6, addr, buf, blen);

	for (l = 0, i = 0; i < alen; i++) {
		if (i == 0) {
			snprintf(buf + l, blen, "%02x", addr[i]);
			blen -= 2;
			l += 2;
		} else {
			snprintf(buf + l, blen, ":%02x", addr[i]);
			blen -= 3;
			l += 3;
		}
	}

	return buf;
}

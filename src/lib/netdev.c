/* XXX: Coding Style - use the tool indent with the following (Linux kernel
 *                     code indents)
 *
 * indent -nbad -bap -nbc -bbo -hnl -br -brs -c33 -cd33 -ncdb -ce -ci4   \
 *        -cli0 -d0 -di1 -nfc1 -i8 -ip0 -l120 -lp -npcs -nprs -npsl -sai \
 *        -saf -saw -ncs -nsc -sob -nfca -cp33 -ss -ts8 -il1
 *
 *
 * netsniff-ng
 *
 * High performance network sniffer for packet inspection
 *
 * Copyright (C) 2009, 2010  Daniel Borkmann <danborkmann@googlemail.com> and 
 *                           Emmanuel Roullit <emmanuel.roullit@googlemail.com>
 *
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation; either version 2 of the License, or (at 
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License 
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
 *
 * Note: Your kernel has to be compiled with CONFIG_PACKET_MMAP=y option in 
 *       order to use this.
 */

/*
 * Contains: 
 *    Networking stuff that doesn't belong to tx or rx_ring
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

#include <sys/ioctl.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <linux/wireless.h>

#include <netsniff-ng/macros.h>
#include <netsniff-ng/netdev.h>

static inline void assert_dev_name(const char *dev)
{
	assert(dev);
	assert(strnlen(dev, IFNAMSIZ));
}

int get_af_socket(int af)
{
	int sock;

	assert(af == AF_INET || af == AF_INET6);

	sock = socket(af, SOCK_DGRAM, 0);

	if (sock < 0) {
		perr("socket");
		exit(EXIT_FAILURE);
	}

	return (sock);
}

/**
 * get_pf_socket - Allocates a raw PF_PACKET socket
 */
int get_pf_socket(void)
{
	int sock = socket(PF_PACKET, SOCK_RAW, 0);
	if (sock < 0) {
		perr("alloc pf socket");
		exit(EXIT_FAILURE);
	}

	return (sock);
}

/**
 * get_wireless_bitrate - Returns wireless bitrate in Mb/s
 * @ifname:              device name
 */
int get_wireless_bitrate(const char *ifname)
{
	int sock, ret;
	struct iwreq iwr;

	assert_dev_name(ifname);

	memset(&iwr, 0, sizeof(iwr));
	strncpy(iwr.ifr_name, ifname, IFNAMSIZ);

	sock = get_af_socket(AF_INET);

	ret = ioctl(sock, SIOCGIWRATE, &iwr);
	if (ret) {
		close(sock);
		return 0;
	}

	close(sock);
	return (iwr.u.bitrate.value / 1000000);
}

/**
 * get_ethtool_bitrate - Returns non-wireless bitrate in Mb/s (via ethtool)
 * @ifname:             device name
 */
int get_ethtool_bitrate(const char *ifname)
{
	int sock, ret;
	struct ifreq ifr;
	struct ethtool_cmd ecmd;

	assert_dev_name(ifname);

	memset(&ifr, 0, sizeof(ifr));
	ecmd.cmd = ETHTOOL_GSET;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	sock = get_af_socket(AF_INET);

	ifr.ifr_data = (char *)&ecmd;

	ret = ioctl(sock, SIOCETHTOOL, &ifr);
	if (ret) {
		close(sock);
		return 0;
	}

	switch (ecmd.speed) {
	case SPEED_10:
		ret = 10;
		break;
	case SPEED_100:
		ret = 100;
		break;
	case SPEED_1000:
		ret = 1000;
		break;
	case SPEED_2500:
		ret = 2500;
		break;
	case SPEED_10000:
		ret = 10000;
		break;
	default:
		ret = 0;
		break;
	};

	close(sock);
	return ret;
}

/**
 * get_device_bitrate_generic - Returns bitrate in Mb/s
 * @ifname:                    device name
 */
int get_device_bitrate_generic(const char *ifname)
{
	int speed_c, speed_w;

	/* Probe for speed rates */
	speed_c = get_ethtool_bitrate(ifname);
	speed_w = get_wireless_bitrate(ifname);

	return (speed_c == 0 ? speed_w : speed_c);
}

/**
 * get_mtu - 	Get MTU of a device
 * @sock:                      socket descriptor
 * @ifname:                    device name
 */

int get_mtu(const char *dev)
{
	int sock;
	struct ifreq ifr;

	assert_dev_name(dev);

	sock = get_af_socket(AF_INET);

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if (ioctl(sock, SIOCGIFMTU, &ifr) < 0) {
		perror("iotcl(SIOCGIFMTU)");
		return 0;
	}

	close(sock);
	return (ifr.ifr_mtu);
}

/**
 * get_nic_flags - Fetches device flags
 * @sock:             socket
 * @dev:              device name
 */
short get_nic_flags(const char *dev)
{
	int ret;
	int sock;
	struct ifreq ethreq;

	assert_dev_name(dev);

	sock = get_af_socket(AF_INET);

	memset(&ethreq, 0, sizeof(ethreq));
	strncpy(ethreq.ifr_name, dev, IFNAMSIZ);

	ret = ioctl(sock, SIOCGIFFLAGS, &ethreq);
	if (ret < 0) {
		perr("ioctl: cannot determine dev number for %s: %d - ", ethreq.ifr_name, errno);
		close(sock);
		exit(EXIT_FAILURE);
	}

	close(sock);

	return (ethreq.ifr_flags);
}

/**
 * get_nic_mac - Fetches device MAC address
 * @dev:              device name
 * @mac:              Output buffer
 */
int get_nic_mac(const char *dev, uint8_t * mac)
{
	int ret;
	int sock;
	struct ifreq ifr;

	assert_dev_name(dev);
	assert(mac);

	sock = get_af_socket(AF_INET);

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	ret = ioctl(sock, SIOCGIFHWADDR, &ifr);
	if (ret) {
		perror("ioctl(SIOCGIFHWADDR) ");
		return (EINVAL);
	}

	close(sock);
	memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	return (0);
}

char *get_nic_mac_str(const char *dev)
{
	uint8_t mac[ETH_ALEN] = { 0 };
	get_nic_mac(dev, mac);
	return (ether_ntoa((const struct ether_addr *)mac));
}

int get_interface_conf(struct ifconf *ifconf)
{
	int sock;

	assert(ifconf);
	assert(ifconf->ifc_buf);
	assert(ifconf->ifc_len);

	sock = get_af_socket(AF_INET);

	if (ioctl(sock, SIOCGIFCONF, ifconf) < 0) {
		perr("ioctl(SIOCGIFCONF) ");
		exit(EXIT_FAILURE);
	}

	close(sock);

	return (0);
}

int get_interface_address(const char *dev, struct in_addr *in, struct in6_addr *in6)
{
	int sock;
	struct ifreq ifr;
	struct in_addr *tmp_in;
	struct sockaddr *sa;
	struct sockaddr_in6 *sa6;

	assert_dev_name(dev);
	assert(in);
	assert(in6);

	memset(in, 0, sizeof(in));
	memset(in6, 0, sizeof(in6));

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	sock = get_af_socket(AF_INET);

	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
		perr("ioctl(SIOCGIFADDR) ");
		close(sock);
		return (0);
	}

	sa = (struct sockaddr *)&ifr.ifr_addr;

	switch (sa->sa_family) {
	case AF_INET:
		tmp_in = &(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
		memcpy(in, tmp_in, sizeof(in));
		break;

	case AF_INET6:
		sa6 = (struct sockaddr_in6 *)&ifr.ifr_addr;
		memcpy(in6, &sa6->sin6_addr, sizeof(in6));
		break;
	}

	return (sa->sa_family);
}

void print_device_info(void)
{
	int i, speed;
	//int ret, i, speed;
	short nic_flags = 0;
	struct ifconf ifc;
	struct ifreq *ifr_elem = NULL;
	struct ifreq *ifr_buffer = NULL;
	size_t if_buffer_len = sizeof(*ifr_buffer) * MAX_NUMBER_OF_NICS;
	struct in_addr ipv4 = { 0 };
	struct in6_addr ipv6;
	char tmp_ip[INET6_ADDRSTRLEN] = { 0 };

	if ((ifr_buffer = malloc(if_buffer_len)) == NULL) {
		perr("Out of memory");
		exit(EXIT_FAILURE);
	}

	memset(&ipv6, 0, sizeof(ipv6));
	memset(&ifc, 0, sizeof(ifc));
	memset(ifr_buffer, 0, if_buffer_len);

	ifc.ifc_len = if_buffer_len;
	ifc.ifc_req = ifr_buffer;

	get_interface_conf(&ifc);

	info("Networking devs\n");
	for (i = 0; i < (ifc.ifc_len / sizeof(*ifr_buffer)); i++) {
		ifr_elem = &ifc.ifc_req[i];
		switch (get_interface_address(ifr_elem->ifr_name, &ipv4, &ipv6)) {
		case AF_INET:
			inet_ntop(AF_INET, (const void *)&ipv4, tmp_ip, INET_ADDRSTRLEN);
			break;
		case AF_INET6:
			inet_ntop(AF_INET6, (const void *)&ipv6, tmp_ip, INET6_ADDRSTRLEN);
			break;
		}
		info(" %s => %s\n", ifr_elem->ifr_name, tmp_ip);
		info("   HW: %s\n", get_nic_mac_str(ifr_elem->ifr_name));

		nic_flags = get_nic_flags(ifr_elem->ifr_name);
		info("   Stat:%s%s%s%s\n",
		     (((nic_flags & IFF_UP) == IFF_UP) ? " up" : " not up"),
		     (((nic_flags & IFF_RUNNING) == IFF_RUNNING) ? " running" : ""),
		     (((nic_flags & IFF_LOOPBACK) == IFF_LOOPBACK) ? ", loops back" : ""),
		     (((nic_flags & IFF_POINTOPOINT) == IFF_POINTOPOINT) ? ", point-to-point link" : ""));

		info("   MTU: %d Byte\n", get_mtu(ifr_elem->ifr_name));

		speed = get_device_bitrate_generic(ifr_elem->ifr_name);
		if (speed) {
			info("   Bitrate: %d Mb/s\n", speed);
		}
	}

	free(ifr_buffer);
}

/**
 * put_dev_into_promisc_mode - Puts network device into promiscuous mode
 * @sock:                     socket
 * @ifindex:                  device number
 */
void put_dev_into_promisc_mode(const char *dev)
{
	int ret;
	int sock;
	struct packet_mreq mr;

	assert(dev);

	sock = get_pf_socket();

	memset(&mr, 0, sizeof(mr));
	mr.mr_ifindex = ethdev_to_ifindex(dev);
	mr.mr_type = PACKET_MR_PROMISC;

	/* This is better than ioctl(), because the kernel now manages the 
	   promisc flag for itself via internal counters. If the socket will 
	   be closed the kernel decrements the counters automatically which 
	   will not work with ioctl(). There, you have to manage things 
	   manually ... */

	ret = setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));
	if (ret < 0) {
		perr("setsockopt: cannot set dev %s to promisc mode: ", dev);

		close(sock);
		exit(EXIT_FAILURE);
	}

	close(sock);
}

/**
 * inject_kernel_bpf - Binds filter code to socket
 * @sock:             socket
 * @bpf:              Berkeley Packet Filter code
 * @len:              length of bpf
 */
void inject_kernel_bpf(int sock, struct sock_filter *bpf, int len)
{
	int ret;
	struct sock_fprog filter;

	assert(bpf);
	assert(len > 0 && (len % sizeof(*bpf) == 0));

	memset(&filter, 0, sizeof(filter));

	filter.len = len / sizeof(*bpf);
	filter.filter = bpf;

	ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter));
	if (ret < 0) {
		perr("setsockopt: filter cannot be injected: %d - ", errno);

		close(sock);
		exit(EXIT_FAILURE);
	}
}

/**
 * reset_kernel_bpf - Resets filter code from socket
 * @sock:            socket
 */
void reset_kernel_bpf(int sock)
{
	int ret;
	int foo = 0;

	ret = setsockopt(sock, SOL_SOCKET, SO_DETACH_FILTER, &foo, sizeof(foo));
	if (ret < 0) {
		perr("setsockopt: cannot reset filter: %d - ", errno);

		close(sock);
		exit(EXIT_FAILURE);
	}
}

/**
 * ethdev_to_ifindex - Translates device name into device number
 * @dev:              device name
 */
int ethdev_to_ifindex(const char *dev)
{
	int ret;
	int sock;
	struct ifreq ethreq;

	assert(dev);

	sock = get_af_socket(AF_INET);

	memset(&ethreq, 0, sizeof(ethreq));
	strncpy(ethreq.ifr_name, dev, IFNAMSIZ);

	ret = ioctl(sock, SIOCGIFINDEX, &ethreq);
	if (ret < 0) {
		perr("ioctl: cannot determine dev number for %s: %d - ", ethreq.ifr_name, errno);

		close(sock);
		exit(EXIT_FAILURE);
	}

	close(sock);
	return (ethreq.ifr_ifindex);
}

/**
 * net_stat - Grabs and prints current socket statistics
 * @sock:    socket
 */
void net_stat(int sock)
{
	int ret;
	struct tpacket_stats kstats;
	socklen_t slen = sizeof(kstats);

	memset(&kstats, 0, sizeof(kstats));

	ret = getsockopt(sock, SOL_PACKET, PACKET_STATISTICS, &kstats, &slen);
	if (ret > -1) {
		info("%d frames incoming\n", kstats.tp_packets);
		info("%d frames passed filter\n", kstats.tp_packets - kstats.tp_drops);
		info("%d frames failed filter (due to out of space)\n", kstats.tp_drops);
	}
}


/**
 * parse_rules - Parses a BPF rulefile
 * @rulefile:   path to rulefile
 * @bpf:        sock filter
 * @len:        len of bpf
 */
void parse_rules(char *rulefile, struct sock_filter **bpf, int *len)
{
	int ret;
	char buff[128] = { 0 };

	struct sock_filter sf_single;

	assert(bpf);
	assert(len);
	assert(rulefile);

	FILE *fp = fopen(rulefile, "r");
	if (!fp) {
		perr("cannot read rulefile - ");
		exit(EXIT_FAILURE);
	}

	memset(buff, 0, sizeof(buff));

	info("Parsing rulefile %s\n", rulefile);

	while (fgets(buff, sizeof(buff), fp) != NULL) {
		/* We're using evil sscanf, so we have to assure
		   that we don't get into a buffer overflow ... */
		buff[sizeof(buff) - 1] = 0;

		memset(&sf_single, 0, sizeof(sf_single));

		ret = sscanf(buff, "{ 0x%x, %d, %d, 0x%08x },",
			     (unsigned int *)((void *)&(sf_single.code)),
			     (int *)((void *)&(sf_single.jt)), (int *)((void *)&(sf_single.jf)), &(sf_single.k));
		if (ret != 4) {
			/* No valid bpf opcode format, might be a comment or 
			   a syntax error */
			continue;
		}

		*len += 1;
		*bpf = (struct sock_filter *)realloc(*bpf, *len * sizeof(sf_single));

		memcpy(&((*bpf)[*len - 1]), &sf_single, sizeof(sf_single));
		memset(buff, 0, sizeof(buff));
	}

	fclose(fp);
}

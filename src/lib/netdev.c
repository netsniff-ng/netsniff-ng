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
 * Copyright (C) 2009, 2010  Daniel Borkmann <danborkmann@googlemail.com>
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

/**
 * get_wireless_bitrate - Returns wireless bitrate in Mb/s
 * @ifname:              device name
 */
int get_wireless_bitrate(char *ifname)
{
	int sock, ret;
	struct iwreq iwr;

	assert(ifname);

	memset(&iwr, 0, sizeof(iwr));

	strncpy(iwr.ifr_name, ifname, IFNAMSIZ);

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

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
int get_ethtool_bitrate(char *ifname)
{
	int sock, ret;
	struct ifreq ifr;
	struct ethtool_cmd ecmd;

	assert(ifname);

	memset(&ifr, 0, sizeof(ifr));
	ecmd.cmd = ETHTOOL_GSET;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

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

	return ret;
}

/**
 * get_device_bitrate_generic - Returns bitrate in Mb/s
 * @ifname:                    device name
 */
int get_device_bitrate_generic(char *ifname)
{
	int speed_c, speed_w;

	/* Probe for speed rates */
	speed_c = get_ethtool_bitrate(ifname);
	speed_w = get_wireless_bitrate(ifname);

	return (speed_c == 0 ? speed_w : speed_c);
}

/**
 * print_device_info - Prints some device specific info
 */
void print_device_info(void)
{
	int ret, i, stmp, speed;
	char dev_buff[1024];

	struct ifconf ifc;
	struct ifreq *ifr;
	struct ifreq *ifr_elem;

	stmp = socket(AF_INET, SOCK_DGRAM, 0);
	if (stmp < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	ifc.ifc_len = sizeof(dev_buff);
	ifc.ifc_buf = dev_buff;

	ret = ioctl(stmp, SIOCGIFCONF, &ifc);
	if (ret < 0) {
		perror("ioctl(SIOCGIFCONF)");
		exit(EXIT_FAILURE);
	}

	ifr = ifc.ifc_req;

	info("networking devs\n");
	for (i = 0; i < ifc.ifc_len / sizeof(struct ifreq); ++i) {
		ifr_elem = &ifr[i];

		info("  %s => %s ", ifr_elem->ifr_name,
		     inet_ntoa(((struct sockaddr_in *)&ifr_elem->ifr_addr)->sin_addr));

		ret = ioctl(stmp, SIOCGIFHWADDR, ifr_elem);
		if (ret) {
			perror("ioctl(SIOCGIFHWADDR)");
			exit(EXIT_FAILURE);
		}

		ret = ioctl(stmp, SIOCGIFFLAGS, ifr_elem);
		if (ret) {
			perror("ioctl(SIOCGIFFLAGS)");
			exit(EXIT_FAILURE);
		}

		info("(%s), %s %s ", ether_ntoa((struct ether_addr *)ifr_elem->ifr_hwaddr.sa_data),
		     ((ifr_elem->ifr_flags & IFF_UP) ? "up" : "not up"),
		     ((ifr_elem->ifr_flags & IFF_RUNNING) ? "running" : ""));

		speed = get_device_bitrate_generic(ifr_elem->ifr_name);
		if (speed) {
			info("(bitrate: %d Mb/s)\n", speed);
		} else {
			info("\n");
		}
	}

	close(stmp);
}

/**
 * put_dev_into_promisc_mode - Puts network device into promiscuous mode
 * @sock:                     socket
 * @ifindex:                  device number
 */
void put_dev_into_promisc_mode(int sock, int ifindex)
{
	int ret;
	struct packet_mreq mr;

	memset(&mr, 0, sizeof(mr));

	mr.mr_ifindex = ifindex;
	mr.mr_type = PACKET_MR_PROMISC;

	/* This is better than ioctl(), because the kernel now manages the 
	   promisc flag for itself via internal counters. If the socket will 
	   be closed the kernel decrements the counters automatically which 
	   will not work with ioctl(). There, you have to manage things 
	   manually ... */

	ret = setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));
	if (ret < 0) {
		perr("setsockopt: cannot set dev %d to promisc mode: %d - ", ifindex, errno);

		close(sock);
		exit(EXIT_FAILURE);
	}
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
 * @sock:             socket
 * @dev:              device name
 */
int ethdev_to_ifindex(int sock, char *dev)
{
	int ret;
	struct ifreq ethreq;

	assert(dev);

	memset(&ethreq, 0, sizeof(ethreq));
	strncpy(ethreq.ifr_name, dev, IFNAMSIZ);

	ret = ioctl(sock, SIOCGIFINDEX, &ethreq);
	if (ret < 0) {
		perr("ioctl: cannot determine dev number for %s: %d - ", ethreq.ifr_name, errno);

		close(sock);
		exit(EXIT_FAILURE);
	}

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
 * alloc_pf_sock - Allocates a raw PF_PACKET socket
 */
int alloc_pf_sock(void)
{
	int sock = socket(PF_PACKET, SOCK_RAW, 0);
	if (sock < 0) {
		perr("alloc pf socket");
		exit(EXIT_FAILURE);
	}

	return (sock);
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
	uint32_t count = 0;
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

		info(" line %d: { 0x%x, %d, %d, 0x%08x }\n", count++,
		     (*bpf)[*len - 1].code, (*bpf)[*len - 1].jt, (*bpf)[*len - 1].jf, (*bpf)[*len - 1].k);
	}

	info("\n");
	fclose(fp);
}

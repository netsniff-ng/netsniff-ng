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

#ifndef _NET_NETDEV_H_
#define _NET_NETDEV_H_

#include <linux/filter.h>
#include <linux/if_packet.h>

#define FAILSAFE_BITRATE	100000000	/* 100 Mbits (Chosen arbitrary) */

/* Function signatures */

extern int get_device_bitrate_generic(char *ifname);
extern int get_wireless_bitrate(char *ifname);
extern int get_ethtool_bitrate(char *ifname);
extern short get_nic_flags(int sock, const char *dev);
extern int change_mtu(char *ifname, int mtu);
extern void print_device_info(void);
extern void put_dev_into_promisc_mode(int sock, int ifindex);
extern void inject_kernel_bpf(int sock, struct sock_filter *bpf, int len);
extern void reset_kernel_bpf(int sock);
extern int ethdev_to_ifindex(int sock, char *dev);
extern void net_stat(int sock);
extern int alloc_pf_sock(void);
extern void parse_rules(char *rulefile, struct sock_filter **bpf, int *len);

/* Inline stuff */

/**
 * get_device_bitrate_generic_fallback - Returns bitrate of device
 * @ifname:                             interface name
 */
static inline int get_device_bitrate_generic_fallback(char *ifname)
{
	int speed = get_device_bitrate_generic(ifname);
	/* If speed is 0 interface could be down or user has choosen a loopback device?! */
	return (speed > 0 ? speed : FAILSAFE_BITRATE);
}

#endif				/* _NET_NETDEV_H_ */

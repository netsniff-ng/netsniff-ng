/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Copyright 2009, 2010 Emmanuel Roullit.
 * Subject to the GPL.
 */

#ifndef NETDEV_H
#define NETDEV_H

#include <linux/ethtool.h>
#include <linux/if.h>
#include <linux/wireless.h>

extern int af_socket(int af);
extern int pf_socket(void);
extern int wireless_bitrate(const char *ifname);
extern int wireless_essid(const char *ifname, char *essid);
extern int adjust_dbm_level(int dbm_val);
extern int dbm_to_mwatt(const int in);
extern int wireless_tx_power(const char *ifname);
extern int wireless_sigqual(const char *ifname, struct iw_statistics *stats);
extern int wireless_rangemax_sigqual(const char *ifname);
extern int ethtool_bitrate(const char *ifname);
extern int ethtool_drvinf(const char *ifname, struct ethtool_drvinfo *drvinf);
extern int device_bitrate(const char *ifname);
extern int device_mtu(const char *ifname);
extern int device_irq_number(const char *ifname);
extern int device_bind_irq_to_cpu(int irq, int cpu);
extern void sock_print_net_stats(int sock);
extern int device_ifindex(const char *ifname);
extern short device_get_flags(const char *ifname);
extern void device_set_flags(const char *ifname, const short flags);

static inline short enter_promiscuous_mode(char *ifname)
{
	if (!strncmp("any", ifname, strlen("any")))
		return 0;

	short ifflags = device_get_flags(ifname);
	device_set_flags(ifname, ifflags | IFF_PROMISC);

	return ifflags;
}

static inline void leave_promiscuous_mode(char *ifname, short oldflags)
{
	if (!strncmp("any", ifname, strlen("any")))
		return;

	device_set_flags(ifname, oldflags);
}

#endif /* NETDEV_H */

/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Copyright 2009, 2010 Emmanuel Roullit.
 * Subject to the GPL, version 2.
 */

#ifndef XSYS_H
#define XSYS_H

#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/ethtool.h>
#include <linux/if.h>
#include <linux/wireless.h>
#include <termios.h>

#include "die.h"

extern int af_socket(int af);
extern int af_raw_socket(int af, int proto);
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
extern int device_address(const char *ifname, int af,
			  struct sockaddr_storage *ss);
extern int device_irq_number(const char *ifname);
extern int device_bind_irq_to_cpu(int irq, int cpu);
extern void sock_print_net_stats(int sock);
extern int device_ifindex(const char *ifname);
extern short device_get_flags(const char *ifname);
extern void device_set_flags(const char *ifname, const short flags);
extern int set_nonblocking(int fd);
extern int set_nonblocking_sloppy(int fd);
extern int set_reuseaddr(int fd);
extern void register_signal(int signal, void (*handler)(int));
extern void register_signal_f(int signal, void (*handler)(int), int flags);
extern int get_tty_size(void);

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

static inline int device_up(char *ifname)
{
	if (!ifname)
		return -EINVAL;
	if (!strncmp("any", ifname, strlen("any")))
		return 1;
	return (device_get_flags(ifname) & IFF_UP) == IFF_UP;
}

static inline int device_running(char *ifname)
{
	if (!ifname)
		return -EINVAL;
	if (!strncmp("any", ifname, strlen("any")))
		return 1;
	return (device_get_flags(ifname) & IFF_RUNNING) == IFF_RUNNING;
}

static inline int device_up_and_running(char *ifname)
{
	if (!ifname)
		return -EINVAL;
	if (!strncmp("any", ifname, strlen("any")))
		return 1;
	return (device_get_flags(ifname) & (IFF_UP | IFF_RUNNING)) ==
	       (IFF_UP | IFF_RUNNING);
}

#define DEFAULT_TTY_SIZE	80

#define __reset		"0"
#define __bold		"1"
#define __black		"30"
#define __red		"31"
#define __green		"32"
#define __yellow	"33"
#define __blue		"34"
#define __magenta	"35"
#define __cyan		"36"
#define __white		"37"
#define __on_black	"40"
#define __on_red	"41"
#define __on_green	"42"
#define __on_yellow	"43"
#define __on_blue	"44"
#define __on_magenta	"45"
#define __on_cyan	"46"
#define __on_white	"47"

#define colorize_start(fore)            "\033[" __##fore "m"
#define colorize_start_full(fore, back) "\033[" __##fore ";" __on_##back "m"
#define colorize_end()                  "\033[" __reset "m"
#define colorize_str(fore, text)                                     \
		colorize_start(fore) text colorize_end()
#define colorize_full_str(fore, back, text)                          \
		colorize_start_full(fore, back) text colorize_end()

#endif /* XSYS_H */

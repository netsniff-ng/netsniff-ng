/*
 * Copyright (C) 2009, 2010  Daniel Borkmann <daniel@netsniff-ng.org> and 
 *                           Emmanuel Roullit <emmanuel@netsniff-ng.org>
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
 */

#ifndef	_NET_CONFIG_H_
#define	_NET_CONFIG_H_

#include <netsniff-ng/types.h>
#include <netsniff-ng/print.h>
#include <linux/filter.h>

/* Internals */
#define DEFAULT_INTERFACE "lo"
#define INTERVAL_COUNTER_REFR   1000	/* in ms */

#define POLL_WAIT_INF           -1	/* CPU friendly and appropriate for normal usage */
#define POLL_WAIT_NONE           0	/* This will pull CPU usage to 100 % */

#define PROMISC_MODE_NONE        1

#define BPF_BYPASS               1
#define BPF_NO_BYPASS            0

#define PROC_NO_HIGHPRIO         1
#define PROC_NO_TOUCHIRQ         1

#define PCAP_NO_DUMP            -1

#define SYSD_ENABLE              1

#define PACKET_DONT_CARE        -1

#define MODE_CAPTURE             1
#define MODE_REPLAY              2
#define MODE_READ                3

struct system_data {
	/* Some more or less boolean conf values */
	int sysdaemon;
	int compatibility_mode;
	int blocking_mode;
	int no_prioritization;
	int no_touch_irq;
	int bypass_bpf;
	int packet_type;
	int mode;
	/* Daemon mode settings */
	char *pidfile;
	/* Berkeley Packet Filter rules */
	char *rulefile;
	/* Ethernet device */
	char *dev;
	short prev_nic_flags;
	int promisc_mode;
	int pcap_fd;
	struct sock_fprog bpf;
	void (*print_pkt) (uint8_t *, const struct tpacket_hdr *);
	int bind_cpu;
	unsigned int ring_size;
};

extern void init_configuration(struct system_data *config);
extern void set_configuration(int argc, char **argv, struct system_data *sd);
extern void check_config(struct system_data *sd);
extern void clean_config(struct system_data *sd);

#endif				/* _NET_CONFIG_H_ */

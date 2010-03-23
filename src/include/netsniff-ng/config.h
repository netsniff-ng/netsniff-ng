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

/*
 * Contains: 
 *    netsniff-ng configuration related routines
 */

#ifndef	_NET_CONFIG_H_
#define	_NET_CONFIG_H_

#include <netsniff-ng/types.h>
#include <netsniff-ng/print.h>

/* Internals */
#define DEFAULT_INTERFACE "lo"
#define INTERVAL_COUNTER_REFR   1000	/* in ms */

#define POLL_WAIT_INF           -1	/* CPU friendly and appropriate for normal usage */
#define POLL_WAIT_NONE           0	/* This will pull CPU usage to 100 % */

#define BPF_BYPASS               1
#define BPF_NO_BYPASS            0

#define PROC_NO_HIGHPRIO         1

#define PCAP_NO_DUMP            -1

#define SYSD_ENABLE              1

#define PACKET_DONT_CARE        -1

#define MODE_CAPTURE             0
#define MODE_REPLAY              1

typedef struct system_data {
	/* Some more or less boolean conf values */
	int sysdaemon;
	int blocking_mode;
	int no_prioritization;
	int bypass_bpf;
	int packet_type;
	int mode;
	/* Daemon mode settings */
	char *pidfile;
	/* Berkeley Packet Filter rules */
	char *rulefile;
	/* Ethernet device */
	char *dev;
	int pcap_fd;
	struct sock_filter *bpf;
	void (*print_pkt) (ring_buff_bytes_t *, const struct tpacket_hdr *);
} system_data_t;

extern void init_configuration(system_data_t * config);
extern void set_configuration(int argc, char **argv, system_data_t * sd);
extern void check_config(system_data_t * sd);
extern void clean_config(system_data_t * sd);

#endif				/* _NET_CONFIG_H_ */

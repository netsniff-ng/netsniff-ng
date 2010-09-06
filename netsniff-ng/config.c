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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "system.h"
#include "dump.h"
#include "macros.h"
#include "misc.h"
#include "config.h"
#include "netdev.h"
#include "xmalloc.h"

static const char *short_options = "MS:QIe:lqi:NxXg:vchd:p:r:P:Df:sb:B:Hnt:C";

static struct option long_options[] = {
	{"dev", required_argument, 0, 'd'},
	{"no-promisc", no_argument, 0, 'M'},
	{"dump", required_argument, 0, 'p'},
	{"replay", required_argument, 0, 'r'},
	{"read", required_argument, 0, 'i'},
	{"quit-after", required_argument, 0, 'q'},
	{"generate", required_argument, 0, 'g'},
	{"type", required_argument, 0, 't'},
	{"filter", required_argument, 0, 'f'},
	{"bind-cpu", required_argument, 0, 'b'},
	{"unbind-cpu", required_argument, 0, 'B'},
	{"prio-norm", no_argument, 0, 'H'},
	{"notouch-irq", no_argument, 0, 'Q'},
	{"non-block", no_argument, 0, 'n'},
	{"ring-size", required_argument, 0, 'S'},
	{"silent", no_argument, 0, 's'},
	{"payload", no_argument, 0, 'l'},
	{"c-style", no_argument, 0, 'C'},
	{"payload-hex", no_argument, 0, 'x'},
	{"all-hex", no_argument, 0, 'X'},
	{"no-payload", no_argument, 0, 'N'},
	{"regex", required_argument, 0, 'e'},
	{"less", no_argument, 0, 'q'},
	{"daemonize", no_argument, 0, 'D'},
	{"pidfile", required_argument, 0, 'P'},
	{"info", no_argument, 0, 'I'},
	{"version", no_argument, 0, 'v'},
	{"compatibility-mode", no_argument, 0, 'c'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};

void init_configuration(struct system_data *sd)
{
	assert(sd);
	memset(sd, 0, sizeof(*sd));

	sd->blocking_mode = POLL_WAIT_INF;
	sd->bypass_bpf = BPF_BYPASS;
	sd->packet_type = PACKET_DONT_CARE;
	sd->print_pkt = versatile_print;
	sd->pcap_fd = PCAP_NO_DUMP;
	sd->mode = MODE_CAPTURE;
	sd->bind_cpu = -1;
}

void set_configuration(int argc, char **argv, struct system_data *sd)
{
	int c, sl, slt;
	int opt_idx;

	char *optargp = NULL;

	assert(argv);
	assert(sd);

	while ((c = getopt_long(argc, argv, short_options, long_options, &opt_idx)) != EOF) {
		switch (c) {
		case 'h':
			help();
			exit(EXIT_SUCCESS);
			break;
		case 'v':
			version();
			exit(EXIT_SUCCESS);
			break;
		case 'd':
			if (sd->dev != NULL) {
				xfree(sd->dev);
			}

			sd->dev = xstrdup(optarg);
			if (!sd->dev) {
				err("Cannot allocate mem");
				exit(EXIT_FAILURE);
			}
			break;
		case 'n':
			sd->blocking_mode = POLL_WAIT_NONE;
			break;
		case 'M':
			sd->promisc_mode = PROMISC_MODE_NONE;
			break;
		case 'Q':
			sd->no_touch_irq = PROC_NO_TOUCHIRQ;
			break;
		case 'S':
			optargp = optarg;

			for (slt = sl = strlen(optarg); sl > 0; --sl) {
				if (!isdigit(optarg[slt - sl]))
					break;
				optargp++;
			}

			sd->ring_size = 0;
			if (sl == 2 && !strncmp(optargp, "KB", 2)) {
				sd->ring_size = 1;
			} else if (sl == 2 && !strncmp(optargp, "MB", 2)) {
				sd->ring_size = 1024;
			} else if (sl == 2 && !strncmp(optargp, "GB", 2)) {
				sd->ring_size = 1024 * 1024;
			} else {
				warn("Syntax error in ring size param!\n");
				exit(EXIT_FAILURE);
			}

			memset(optargp, 0, 2);
			sd->ring_size *= atoi(optarg);
			break;
		case 'H':
			sd->no_prioritization = PROC_NO_HIGHPRIO;
			break;
		case 't':
			sl = strlen(optarg);
			if (sl == 4 && !strncmp(optarg, "host", sl)) {
				sd->packet_type = PACKET_HOST;
			} else if (sl == 9 && !strncmp(optarg, "broadcast", sl)) {
				sd->packet_type = PACKET_BROADCAST;
			} else if (sl == 9 && !strncmp(optarg, "multicast", sl)) {
				sd->packet_type = PACKET_MULTICAST;
			} else if (sl == 6 && !strncmp(optarg, "others", sl)) {
				sd->packet_type = PACKET_OTHERHOST;
			} else if (sl == 8 && !strncmp(optarg, "outgoing", sl)) {
				sd->packet_type = PACKET_OUTGOING;
			} else {
				sd->packet_type = PACKET_DONT_CARE;
			}
			break;
		case 'f':
			sd->bypass_bpf = BPF_NO_BYPASS;
			sd->rulefile = xstrdup(optarg);
			break;
		case 's':
			/* Switch to silent mode */
			sd->print_pkt = NULL;
			break;
		case 'l':
			sd->print_pkt = payload_human_only_print;
			break;
		case 'N':
			sd->print_pkt = versatile_header_only_print;
			break;
		case 'x':
			sd->print_pkt = payload_hex_only_print;
			break;
		case 'X':
			sd->print_pkt = all_hex_only_print;
			break;
		case 'q':
			sd->print_pkt = reduced_print;
			break;
		case 'C':
			sd->print_pkt = versatile_hex_cstyle_print;
			break;
		case 'e':
			sd->print_pkt = regex_print;
			init_regex(optarg);
			break;
		case 'D':
			sd->sysdaemon = SYSD_ENABLE;
			/* Daemonize implies silent mode
			 * Users can still dump pcaps */
			sd->print_pkt = NULL;
			break;
		case 'P':
			sd->pidfile = xstrdup(optarg);
			break;
		case 'b':
			set_cpu_affinity(optarg);
			/* CPU to bind NIC INTR, takes first CPU! */
			sd->bind_cpu = atoi(optarg);
			break;
		case 'B':
			set_cpu_affinity_inv(optarg);
			break;
		case 'p':
			sd->pcap_fd = creat(optarg, DEFFILEMODE);
			if (sd->pcap_fd == -1) {
				err("Can't open file");
				exit(EXIT_FAILURE);
			}
			break;
		case 'r':
			sd->mode = MODE_REPLAY;

			sd->pcap_fd = open(optarg, O_RDONLY);
			if (sd->pcap_fd == -1) {
				err("Can't open file");
				exit(EXIT_FAILURE);
			}

			break;
		case 'i':
			sd->mode = MODE_READ;

			sd->pcap_fd = open(optarg, O_RDONLY);
			if (sd->pcap_fd == -1) {
				err("Can't open file");
				exit(EXIT_FAILURE);
			}

			break;
		case 'I':
			print_device_info();
			exit(EXIT_SUCCESS);
		case 'g':
			info("Option `g` not yet implemented!\n");
			break;
		case 'c':
			sd->compatibility_mode = 1;
			break;
		case '?':
			switch (optopt) {
			case 'd':
			case 'e':
			case 'g':
			case 'r':
			case 'f':
			case 't':
			case 'p':
			case 'S':
			case 'P':
			case 'i':
			case 'L':
			case 'b':
			case 'B':
				warn("Option -%c requires an argument!\n", optopt);
				exit(EXIT_FAILURE);
			default:
				if (isprint(optopt)) {
					warn("Unknown option character `0x%X\'!\n", optopt);
				}
				exit(EXIT_FAILURE);
			}

			return;
		default:
			abort();
		}
	}
}

void check_config(struct system_data *sd)
{
	assert(sd);

	if (sd->sysdaemon && !sd->pidfile) {
		help();
	}
}

void clean_config(struct system_data *sd)
{
	assert(sd);

	if (sd->pidfile)
		xfree(sd->pidfile);
	if (sd->rulefile)
		xfree(sd->rulefile);
	if (sd->dev)
		xfree(sd->dev);

	close(sd->pcap_fd);
}

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

#include <netsniff-ng/system.h>
#include <netsniff-ng/dump.h>
#include <netsniff-ng/macros.h>
#include <netsniff-ng/misc.h>
#include <netsniff-ng/config.h>

static struct option long_options[] = {
	{"dev", required_argument, 0, 'd'},
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
	{"non-block", no_argument, 0, 'n'},
	{"silent", no_argument, 0, 's'},
	{"payload", no_argument, 0, 'l'},
	{"payload-hex", no_argument, 0, 'x'},
	{"all-hex", no_argument, 0, 'X'},
	{"no-payload", no_argument, 0, 'N'},
	{"regex", required_argument, 0, 'e'},
	{"less", no_argument, 0, 'q'},
	{"daemonize", no_argument, 0, 'D'},
	{"pidfile", required_argument, 0, 'P'},
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};

void init_configuration(system_data_t * sd)
{
	assert(sd);
	memset(sd, 0, sizeof(*sd));

	sd->blocking_mode = POLL_WAIT_INF;
	sd->bypass_bpf = BPF_BYPASS;
	sd->packet_type = PACKET_DONT_CARE;
	sd->print_pkt = versatile_print;
	sd->pcap_fd = PCAP_NO_DUMP;
	sd->mode = MODE_CAPTURE;
	sd->bpf = NULL;
}

void set_configuration(int argc, char **argv, system_data_t * sd)
{
	int c, sl;
	int opt_idx;

	assert(argv);
	assert(sd);

	while ((c = getopt_long(argc, argv, "e:lqi:NxXg:vhd:p:r:P:Df:sb:B:Hnt:", long_options, &opt_idx)) != EOF) {
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
				free(sd->dev);
			}

			sd->dev = strdup(optarg);
			if (!sd->dev) {
				err("Cannot allocate mem");
				exit(EXIT_FAILURE);
			}
			break;
		case 'n':
			sd->blocking_mode = POLL_WAIT_NONE;
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
			sd->rulefile = strdup(optarg);
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
			sd->pidfile = strdup(optarg);
			break;
		case 'b':
			set_cpu_affinity(optarg);
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

			if (access(optarg, R_OK) != 0)
			{
				err("Insufficient permission to access %s\n", optarg);
				exit(EXIT_FAILURE);
			}

			sd->pcap_fd = open(optarg, O_RDONLY);
			if (sd->pcap_fd == -1) {
				err("Can't open file");
				exit(EXIT_FAILURE);
			}

			break;
		case 'i':
			sd->mode = MODE_READ;
			
			if (access(optarg, R_OK) != 0)
			{
				err("Insufficient permission to access %s\n", optarg);
				exit(EXIT_FAILURE);
			}

			sd->pcap_fd = open(optarg, O_RDONLY);
			if (sd->pcap_fd == -1) {
				err("Can't open file");
				exit(EXIT_FAILURE);
			}

			break;
		case 'g':
			info("Option `g` not yet implemented!\n");
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

void check_config(system_data_t * sd)
{
	assert(sd);

	if (sd->sysdaemon && !sd->pidfile) {
		help();
	}
}

void clean_config(system_data_t * sd)
{
	assert(sd);

	if (sd->pidfile)
		free(sd->pidfile);
	if (sd->rulefile)
		free(sd->rulefile);
	if (sd->dev)
		free(sd->dev);

	close(sd->pcap_fd);
}

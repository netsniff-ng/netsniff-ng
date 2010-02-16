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
#include <netsniff-ng/packet.h>
#include <netsniff-ng/macros.h>
#include <netsniff-ng/misc.h>
#include <netsniff-ng/config.h>

static struct option long_options[] = {
	{"dev", required_argument, 0, 'd'},
	{"dump", required_argument, 0, 'p'},
	{"replay", required_argument, 0, 'r'},
	{"quit-after", required_argument, 0, 'q'},
	{"generate", required_argument, 0, 'g'},
	{"type", required_argument, 0, 't'},
	{"filter", required_argument, 0, 'f'},
	{"bind-cpu", required_argument, 0, 'b'},
	{"unbind-cpu", required_argument, 0, 'B'},
	{"prio-norm", no_argument, 0, 'H'},
	{"non-block", no_argument, 0, 'n'},
	{"no-color", no_argument, 0, 'N'},
	{"silent", no_argument, 0, 's'},
	{"daemonize", no_argument, 0, 'D'},
	{"pidfile", required_argument, 0, 'P'},
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};

void init_configuration(system_data_t * config)
{
	assert(config);

	memset(config, 0, sizeof(*config));

	config->blocking_mode = POLL_WAIT_INF;
	config->bypass_bpf = BPF_BYPASS;
	config->packet_type = PACKET_DONT_CARE;
	config->print_pkt = versatile_print;
	config->dump_pcap_fd = -1;
}

void set_configuration(int argc, char **argv, system_data_t * sd)
{
	int c;
	int opt_idx;

	assert(argv);
	assert(sd);

	while ((c = getopt_long(argc, argv, "vhd:p:P:Df:sb:B:Hnt:", long_options, &opt_idx)) != EOF) {
		switch (c) {
		case 'h':
			{
				help();
				exit(EXIT_SUCCESS);
				break;
			}
		case 'v':
			{
				version();
				exit(EXIT_SUCCESS);
				break;
			}
		case 'd':
			{
				if (sd->dev != NULL) {
					free(sd->dev);
				}

				sd->dev = strdup(optarg);
				if (!sd->dev) {
					err("Cannot allocate mem");
					exit(EXIT_FAILURE);
				}
				break;
			}
		case 'n':
			{
				sd->blocking_mode = POLL_WAIT_NONE;
				break;
			}
		case 'H':
			{
				sd->no_prioritization = PROC_NO_HIGHPRIO;
				break;
			}
		case 't':
			{
				if (strlen(optarg) == 4 && !strncmp(optarg, "host", 4)) {
					sd->packet_type = PACKET_HOST;
				} else if (strlen(optarg) == 9 && !strncmp(optarg, "broadcast", 9)) {
					sd->packet_type = PACKET_BROADCAST;
				} else if (strlen(optarg) == 9 && !strncmp(optarg, "multicast", 9)) {
					sd->packet_type = PACKET_MULTICAST;
				} else if (strlen(optarg) == 6 && !strncmp(optarg, "others", 6)) {
					sd->packet_type = PACKET_OTHERHOST;
				} else if (strlen(optarg) == 8 && !strncmp(optarg, "outgoing", 8)) {
					sd->packet_type = PACKET_OUTGOING;
				} else {
					sd->packet_type = PACKET_DONT_CARE;
				}
				break;
			}
		case 'f':
			{
				sd->bypass_bpf = BPF_NO_BYPASS;
				sd->rulefile = strdup(optarg);
				break;
			}
		case 's':
			{
				/* Switch to silent mode */
				sd->print_pkt = NULL;
				break;
			}
		case 'D':
			{
				sd->sysdaemon = SYSD_ENABLE;
				/* Daemonize implies silent mode
				 * Users can still dump pcaps */
				sd->print_pkt = NULL;
				break;
			}
		case 'P':
			{
				sd->pidfile = strdup(optarg);
				break;
			}
		case 'b':
			{
				set_cpu_affinity(optarg);
				break;
			}
		case 'B':
			{
				set_cpu_affinity_inv(optarg);
				break;
			}
		case 'p':
			{
				sd->dump_pcap_fd = creat(optarg, DEFFILEMODE);

				if (sd->dump_pcap_fd == -1) {
					err("Can't open file");
					exit(EXIT_FAILURE);
				}

				break;
			}
		case '?':
			{
				switch (optopt) {
				case 'd':
				case 'f':
				case 'p':
				case 'P':
				case 'L':
				case 'b':
				case 'B':
					{
						warn("Option -%c requires an argument!\n", optopt);
						break;
					}
				default:
					{
						if (isprint(optopt)) {
							warn("Unknown option character `0x%X\'!\n", optopt);
						}
						break;
					}
				}

				return;
			}
		default:
			{
				abort();
			}
		}
	}
}

void check_config(system_data_t * sd)
{
	assert(sd);

	if (sd->sysdaemon && (!sd->pidfile || sd->dump_pcap_fd == -1)) {
		help();
		exit(EXIT_FAILURE);
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

	close(sd->dump_pcap_fd);
}

/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009-2011 Daniel Borkmann.
 * Copyright 2010 Emmanuel Roullit.
 * Subject to the GPL.
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <ctype.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>

#include "rx_ring.h"
#include "netdev.h"
#include "compiler.h"
#include "poll.h"
#include "bpf.h"
#include "version.h"
#include "signals.h"
#include "error_and_die.h"
#include "tprintf.h"
#include "dissector.h"
#include "xmalloc.h"
#include "system.h"

#define CPU_UNKNOWN  -1
#define CPU_NOTOUCH  -2
#define PACKET_ALL   -1

struct mode {
	char *device_in;
	char *device_out;
	char *filter;
	int cpu;
	/* dissector */
	int link_type;
	int print_mode;
	/* 0 for automatic, > 0 for manual */
	unsigned int reserve_size;
	int packet_type;
	int compress;
	bool encrypt;
	bool randomize;
	bool promiscuous;
};

static sig_atomic_t sigint = 0;

static const char *short_options = "d:i:o:rf:Mt:S:b:B:HQsqlxCXNe:vh";

static struct option long_options[] = {
	{"dev", required_argument, 0, 'd'},
	{"in", required_argument, 0, 'i'},
	{"out", required_argument, 0, 'o'},
	{"randomize", no_argument, 0, 'r'},
	{"filter", required_argument, 0, 'f'},
	{"no-promisc", no_argument, 0, 'M'},
	{"type", required_argument, 0, 't'},
	{"ring-size", required_argument, 0, 'S'},
	{"bind-cpu", required_argument, 0, 'b'},
	{"unbind-cpu", required_argument, 0, 'B'},
	{"prio-norm", no_argument, 0, 'H'},
	{"notouch-irq", no_argument, 0, 'Q'},
	{"silent", no_argument, 0, 's'},
	{"less", no_argument, 0, 'q'},
	{"payload", no_argument, 0, 'l'},
	{"payload-hex", no_argument, 0, 'x'},
	{"c-style", no_argument, 0, 'C'},
	{"all-hex", no_argument, 0, 'X'},
	{"no-payload", no_argument, 0, 'N'},
	{"regex", required_argument, 0, 'e'},
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};

static void signal_handler(int number)
{
	switch (number) {
	case SIGINT:
		sigint = 1;
		break;
	case SIGHUP:
		break;
	default:
		break;
	}
}

void enter_mode_pcap_to_tx(struct mode *mode)
{
	/* NOP */
}

void enter_mode_rx_to_tx(struct mode *mode)
{
	/* NOP */
}

void enter_mode_read_pcap(struct mode *mode)
{
	/* NOP */
}

void enter_mode_rx_to_pcap(struct mode *mode)
{
	/* NOP */
}

void enter_mode_rx_only(struct mode *mode)
{
	int sock, irq, ifindex;
	unsigned int size, it = 0;
	short ifflags = 0;
	uint8_t *packet;
	struct ring rx_ring;
	struct pollfd rx_poll;
	struct frame_map *hdr;
	struct sock_fprog bpf_ops;

	sock = pf_socket();

	memset(&rx_ring, 0, sizeof(rx_ring));
	memset(&rx_poll, 0, sizeof(rx_poll));
	memset(&bpf_ops, 0, sizeof(bpf_ops));

	ifindex = device_ifindex(mode->device_in);
	size = ring_size(mode->device_in, mode->reserve_size);

	bpf_parse_rules(mode->filter, &bpf_ops);
	bpf_attach_to_sock(sock, &bpf_ops);

	setup_rx_ring_layout(sock, &rx_ring, size);
	create_rx_ring(sock, &rx_ring);
	mmap_rx_ring(sock, &rx_ring);
	alloc_rx_ring_frames(&rx_ring);
	bind_rx_ring(sock, &rx_ring, ifindex);

	prepare_polling(sock, &rx_poll);
	dissector_init_all(mode->print_mode);

	if (mode->cpu >= 0 && ifindex > 0) {
		irq = device_irq_number(mode->device_in);
		device_bind_irq_to_cpu(mode->cpu, irq);
		printf("IRQ: %s:%d > CPU%d\n", mode->device_in, irq, 
		       mode->cpu);
	}

	if (mode->promiscuous == true) {
		ifflags = enter_promiscuous_mode(mode->device_in);
		printf("PROMISC\n");
	}

	printf("BPF:\n");
	bpf_dump_all(&bpf_ops);
	printf("MD: RX\n\n");

	while(likely(sigint == 0)) {
		while(user_may_pull_from_rx(rx_ring.frames[it].iov_base)) {
			hdr = rx_ring.frames[it].iov_base;
			packet = ((uint8_t *) hdr) + hdr->tp_h.tp_mac;

			if (mode->packet_type != PACKET_ALL)
				if (mode->packet_type != hdr->s_ll.sll_pkttype)
					goto next;

			show_frame_hdr(hdr, mode->print_mode);
			dissector_entry_point(packet, hdr->tp_h.tp_snaplen,
					      mode->link_type);

next:
			kernel_may_pull_from_rx(&hdr->tp_h);
			next_slot(&it, &rx_ring);

			if (unlikely(sigint == 1))
				break;
		}

		poll(&rx_poll, 1, -1);
		poll_error_maybe_die(sock, &rx_poll);
	}

	sock_print_net_stats(sock);

	dissector_cleanup_all();
	destroy_rx_ring(sock, &rx_ring);

	if (mode->promiscuous == true)
		leave_promiscuous_mode(mode->device_in, ifflags);

	close(sock);
}

static void help(void)
{
	printf("\n%s %s, the packet sniffing beast\n", PROGNAME_STRING,
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Usage: netsniff-ng [options]\n");
	printf("Options for input/output:\n");
	printf("  -i|-d|--dev|--in <dev|pcap>  Input source as netdev or pcap\n");
	printf("  -o|--out <dev|pcap>          Output source as netdev or pcap\n");
	printf("  -r|--randomize               Randomize packet forwarding order\n");
	printf("  -f|--filter <bpf-file>       Use BPF filter rule from file\n");
	printf("  -M|--no-promisc              No promiscuous mode for netdev\n");
	printf("  -t|--type <type>             Only show packets of defined type:\n");
	printf("                               host|broadcast|multicast|others|outgoing\n");
	printf("  -S|--ring-size <size>        Manually set ring size to <size>:\n");
	printf("                               mmap space in KB/MB/GB, e.g. \'10MB\'\n");
	printf("  -b|--bind-cpu <cpu>          Bind to specific CPU or CPU-range\n");
	printf("  -B|--unbind-cpu <cpu>        Forbid to use specific CPU or CPU-range\n");
	printf("  -H|--prio-norm               Do not high priorize process\n");
	printf("  -Q|--notouch-irq             Do not touch IRQ CPU affinity of NIC\n");
	printf("  -s|--silent                  Do not print captured packets\n");
	printf("  -q|--less                    Print less-verbose packet information\n");
	printf("  -l|--payload                 Only print human-readable payload\n");
	printf("  -x|--payload-hex             Only print payload in hex format\n");
	printf("  -C|--c-style                 Print full packet in C style hex format\n");
	printf("  -X|--all-hex                 Print packets in hex format\n");
	printf("  -N|--no-payload              Only print packet header\n");
	printf("  -e|--regex <expr>            Only print packet that matches regex\n");
	printf("  -v|--version                 Show version\n");
	printf("  -h|--help                    Show this help\n");
	printf("\n");
	printf("Examples:\n");
	printf("  netsniff-ng --in eth0 --out dump.pcap --silent --bind-cpu 0\n");
	printf("  netsniff-ng --in dump.pcap --out eth0 --silent --bind-cpu 0\n");
	printf("  netsniff-ng --in dump.pcap --no-payload\n");
	printf("  netsniff-ng --in eth0 --out eth1 --silent --bind-cpu 0\n");
	printf("  netsniff-ng --in any --filter icmp.bpf\n");
	printf("  netsniff-ng --regex \"user.*pass\"\n");
	printf("  netsniff-ng --dev wlan0 --prio-norm --all-hex --type outgoing\n");
	printf("\n");
	printf("Note:\n");
	printf("  This tool is targeted for network developers! You should\n");
	printf("  be aware of what you are doing and what these options above\n");
	printf("  mean! Only use this tool in an isolated LAN that you own!\n");
	printf("\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2009-2011 Daniel Borkmann <daniel@netsniff-ng.org>\n");
	printf("Copyright (C) 2009-2011 Emmanuel Roullit <emmanuel@netsniff-ng.org>\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");

	die();
}

static void version(void)
{
	printf("\n%s %s, the packet sniffing beast\n", PROGNAME_STRING,
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2009-2011 Daniel Borkmann <daniel@netsniff-ng.org>\n");
	printf("Copyright (C) 2009-2011 Emmanuel Roullit <emmanuel@netsniff-ng.org>\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");

	die();
}

static void header(void)
{
	printf("%s%s%s\n", colorize_start(bold), PROGNAME_STRING " " 
	       VERSION_STRING, colorize_end());
}

int main(int argc, char **argv)
{
	int c, i, j, opt_index;
	char *ptr;
	bool prio_high = true;
	struct mode mode;
	void (*enter_mode)(struct mode *mode) = NULL;

	check_for_root_maybe_die();

	memset(&mode, 0, sizeof(mode));
	mode.link_type = LINKTYPE_EN10MB;
	mode.print_mode = FNTTYPE_PRINT_NORM;
	mode.cpu = CPU_UNKNOWN;
	mode.packet_type = PACKET_ALL;
	mode.promiscuous = true;
	mode.encrypt = false;
	mode.compress = 0;
	mode.randomize = false;

	while ((c = getopt_long(argc, argv, short_options, long_options,
	       &opt_index)) != EOF) {
		switch (c) {
		case 'd':
		case 'i':
			mode.device_in = xstrdup(optarg);
			break;
		case 'o':
			mode.device_out = xstrdup(optarg);
			break;
		case 'r':
			mode.randomize = true;
			break;
		case 'f':
			mode.filter = xstrdup(optarg);
			break;
		case 'M':
			mode.promiscuous = false;
			break;
		case 't':
			if (!strncmp(optarg, "host", strlen("host")))
				mode.packet_type = PACKET_HOST;
			else if (!strncmp(optarg, "broadcast", strlen("broadcast")))
				mode.packet_type = PACKET_BROADCAST;
			else if (!strncmp(optarg, "multicast", strlen("multicast")))
				mode.packet_type = PACKET_MULTICAST;
			else if (!strncmp(optarg, "others", strlen("others")))
				mode.packet_type = PACKET_OTHERHOST;
			else if (!strncmp(optarg, "outgoing", strlen("outgoing")))
				mode.packet_type = PACKET_OUTGOING;
			else
				mode.packet_type = PACKET_ALL;
			break;
		case 'S':
			ptr = optarg;
			mode.reserve_size = 0;

			for (j = i = strlen(optarg); i > 0; --i) {
				if (!isdigit(optarg[j - i]))
					break;
				ptr++;
			}

			if (!strncmp(ptr, "KB", strlen("KB")))
				mode.reserve_size = 1 << 10;
			else if (!strncmp(ptr, "MB", strlen("MB")))
				mode.reserve_size = 1 << 20;
			else if (!strncmp(ptr, "GB", strlen("GB")))
				mode.reserve_size = 1 << 30;
			else
				error_and_die(EXIT_FAILURE, "Syntax error in "
					      "ring size param!\n");

			*ptr = 0;
			mode.reserve_size *= atoi(optarg);
			break;
		case 'b':
			set_cpu_affinity(optarg, 0);
			if (mode.cpu != CPU_NOTOUCH)
				mode.cpu = atoi(optarg);
			break;
		case 'B':
			set_cpu_affinity(optarg, 1);
			break;
		case 'H':
			prio_high = false;
			break;
		case 'Q':
			mode.cpu = CPU_NOTOUCH;
			break;
		case 's':
			mode.print_mode = FNTTYPE_PRINT_NONE;
			break;
		case 'q':
			mode.print_mode = FNTTYPE_PRINT_LESS;
			break;
		case 'l':
			mode.print_mode = FNTTYPE_PRINT_CHR1;
			break;
		case 'x':
			mode.print_mode = FNTTYPE_PRINT_HEX1;
			break;
		case 'C':
			mode.print_mode = FNTTYPE_PRINT_PAAC;
			break;
		case 'X':
			mode.print_mode = FNTTYPE_PRINT_HEX2;
			break;
		case 'N':
			mode.print_mode = FNTTYPE_PRINT_NOPA;
			break;
		case 'e': /* regex + arg, TODO: arg */
			mode.print_mode = FNTTYPE_PRINT_REGX;
			break;
		case 'v':
			version();
			break;
		case 'h':
			help();
			break;
		case '?':
			switch (optopt) {
			case 'd':
			case 'i':
			case 'o':
			case 'f':
			case 't':
			case 'S':
			case 'b':
			case 'B':
			case 'e':
				error_and_die(EXIT_FAILURE, "Option -%c "
					      "requires an argument!\n",
					      optopt);
			default:
				if (isprint(optopt))
					whine("Unknown option character "
					      "`0x%X\'!\n", optopt);
				exit(EXIT_FAILURE);
			}
		default:
			break;
		}
	}

	if (!mode.device_in)
		mode.device_in = "any";

	register_signal(SIGINT, signal_handler);
	register_signal(SIGHUP, signal_handler);
	register_signal(SIGUSR1, signal_handler);
	register_signal(SIGSEGV, muntrace_handler);

	tprintf_init();
	header();

	if (prio_high == true) {
		set_proc_prio(DEFAULT_PROCESS_PRIO);
		set_sched_status(DEFAULT_SCHED_POLICY, DEFAULT_SCHED_PRIO);
	}

	/* TODO: mode selection according to device_in and device_out */
	enter_mode = enter_mode_rx_only;
	enter_mode(&mode);

	tprintf_cleanup();
	return 0;
}


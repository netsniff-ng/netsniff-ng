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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>
#include <fcntl.h>

#include "rx_ring.h"
#include "tx_ring.h"
#include "netdev.h"
#include "compiler.h"
#include "pcap.h"
#include "poll.h"
#include "bpf.h"
#include "version.h"
#include "signals.h"
#include "write_or_die.h"
#include "die.h"
#include "tprintf.h"
#include "dissector.h"
#include "xmalloc.h"
#include "psched.h"
#include "misc.h"

#define CPU_UNKNOWN  -1
#define CPU_NOTOUCH  -2
#define PACKET_ALL   -1

struct mode {
	char *device_in;
	char *device_out;
	char *filter;
	int cpu;
	int mmap;
	int dump;
	/* dissector */
	int link_type;
	int print_mode;
	/* 0 for automatic, > 0 for manual */
	unsigned int reserve_size;
	int packet_type;
	bool randomize;
	bool promiscuous;
	enum pcap_ops_groups pcap;
};

static sig_atomic_t sigint = 0;

//static unsigned long interval = TX_KERNEL_PULL_INT;

static const char *short_options = "d:i:o:rf:Mt:S:k:b:B:HQmcsqlxCXNvh";

static struct option long_options[] = {
	{"dev", required_argument, 0, 'd'},
	{"in", required_argument, 0, 'i'},
	{"out", required_argument, 0, 'o'},
	{"randomize", no_argument, 0, 'r'},
	{"mmap", no_argument, 0, 'm'},
	{"clrw", no_argument, 0, 'c'},
	{"filter", required_argument, 0, 'f'},
	{"no-promisc", no_argument, 0, 'M'},
	{"type", required_argument, 0, 't'},
	{"ring-size", required_argument, 0, 'S'},
	{"kernel-pull", required_argument, 0, 'k'},
	{"bind-cpu", required_argument, 0, 'b'},
	{"unbind-cpu", required_argument, 0, 'B'},
	{"prio-high", no_argument, 0, 'H'},
	{"notouch-irq", no_argument, 0, 'Q'},
	{"silent", no_argument, 0, 's'},
	{"less", no_argument, 0, 'q'},
	{"payload", no_argument, 0, 'l'},
	{"payload-hex", no_argument, 0, 'x'},
	{"c-style", no_argument, 0, 'C'},
	{"all-hex", no_argument, 0, 'X'},
	{"no-payload", no_argument, 0, 'N'},
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
	printf("pcap->tx\n");
// if (device_up_and_running(mode.device) == 0)
//                error_and_die(EXIT_FAILURE, "Networking device not running!\n");
}

void enter_mode_rx_to_tx(struct mode *mode)
{
	printf("rx->tx\n");
}

void enter_mode_read_pcap(struct mode *mode)
{
	printf("pcap\n");
}

void enter_mode_rx_only_or_dump(struct mode *mode)
{
	int sock, irq, ifindex, fd = 0, ret;
	unsigned int size, it = 0;
	short ifflags = 0;
	uint8_t *packet;
	struct ring rx_ring;
	struct pollfd rx_poll;
	struct frame_map *hdr;
	struct sock_fprog bpf_ops;

	sock = pf_socket();

	if (mode->dump) {
		if (!pcap_ops[mode->pcap])
			panic("pcap group not supported!\n");
		if (!pcap_ops[mode->pcap]->write_pcap_pkt)
			panic("pcap group does not support write!\n");
		fd = open_or_die_m(mode->device_out,
				   O_CREAT | O_WRONLY | O_TRUNC,
				   S_IRUSR | S_IWUSR);
		ret = pcap_ops[mode->pcap]->push_file_header(fd);
		if (ret)
			panic("error writing pcap header!\n");
	}

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

			if (mode->dump) {
				struct pcap_pkthdr phdr;
				tpacket_hdr_to_pcap_pkthdr(&hdr->tp_h, &phdr);
				ret = pcap_ops[mode->pcap]->write_pcap_pkt(fd, &phdr,
									   packet, phdr.len);
				if (unlikely(ret != sizeof(phdr) + phdr.len))
					panic("write error to pcap!");
			}

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
	if (mode->dump) {
		pcap_ops[mode->pcap]->fsync_pcap(fd);
		close(fd);
	}
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
	printf("  -m|--mmap                    Mmap pcap file, otherwise use scatter/gather I/O\n");
	printf("  -c|--clrw                    Instead scatter/gather I/O use read/write I/O\n");
	printf("  -S|--ring-size <size>        Manually set ring size to <size>:\n");
	printf("                               mmap space in KB/MB/GB, e.g. \'10MB\'\n");
	printf("  -k|--kernel-pull <int>       Kernel pull from user interval in us\n");
	printf("                               Default is 10us where the TX_RING\n");
	printf("                               is populated with payload from uspace\n");
	printf("  -b|--bind-cpu <cpu>          Bind to specific CPU or CPU-range\n");
	printf("  -B|--unbind-cpu <cpu>        Forbid to use specific CPU or CPU-range\n");
	printf("  -H|--prio-high               Make this high priorize process\n");
	printf("  -Q|--notouch-irq             Do not touch IRQ CPU affinity of NIC\n");
	printf("  -s|--silent                  Do not print captured packets\n");
	printf("  -q|--less                    Print less-verbose packet information\n");
	printf("  -l|--payload                 Only print human-readable payload\n");
	printf("  -x|--payload-hex             Only print payload in hex format\n");
	printf("  -C|--c-style                 Print full packet in C style hex format\n");
	printf("  -X|--all-hex                 Print packets in hex format\n");
	printf("  -N|--no-payload              Only print packet header\n");
	printf("  -v|--version                 Show version\n");
	printf("  -h|--help                    Show this help\n");
	printf("\n");
	printf("Examples:\n");
	printf("  netsniff-ng --in eth0 --out dump.pcap --silent --bind-cpu 0\n");
	printf("  netsniff-ng --in dump.pcap --mmap --out eth0 --silent --bind-cpu 0\n");
	printf("  netsniff-ng --in dump.pcap --no-payload\n");
	printf("  netsniff-ng --in eth0 --out eth1 --silent --randomize --bind-cpu 0\n");
	printf("  netsniff-ng --in any --filter icmp.bpf\n");
	printf("  netsniff-ng --dev wlan0 --prio-norm --all-hex --type outgoing\n");
	printf("\n");
	printf("Note:\n");
	printf("  This tool is targeted for network developers! You should\n");
	printf("  be aware of what you are doing and what these options above\n");
	printf("  mean!\n");
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
	bool prio_high = false;
	struct mode mode;
	void (*enter_mode)(struct mode *mode) = NULL;

	check_for_root_maybe_die();

	memset(&mode, 0, sizeof(mode));
	mode.link_type = LINKTYPE_EN10MB;
	mode.print_mode = FNTTYPE_PRINT_NORM;
	mode.cpu = CPU_UNKNOWN;
	mode.packet_type = PACKET_ALL;
	mode.promiscuous = true;
	mode.randomize = false;
	mode.pcap = PCAP_OPS_SG;

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
				panic("Syntax error in ring size param!\n");

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
			prio_high = true;
			break;
		case 'c':
			mode.pcap = PCAP_OPS_RW;
			break;
		case 'm':
			mode.pcap = PCAP_OPS_MMAP;
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
				panic("Option -%c requires an argument!\n",
				      optopt);
			default:
				if (isprint(optopt))
					whine("Unknown option character "
					      "`0x%X\'!\n", optopt);
				die();
			}
		default:
			break;
		}
	}

	if (!mode.device_in)
		mode.device_in = xstrdup("any");

	register_signal(SIGINT, signal_handler);
	register_signal(SIGHUP, signal_handler);
	register_signal(SIGUSR1, signal_handler);
	register_signal(SIGSEGV, muntrace_handler);

	init_rw_pcap();
//	init_sg_pcap();
//	init_mmap_pcap();

	tprintf_init();
	header();

	if (prio_high == true) {
		set_proc_prio(DEFAULT_PROCESS_PRIO);
		set_sched_status(DEFAULT_SCHED_POLICY, DEFAULT_SCHED_PRIO);
	}

	if (device_mtu(mode.device_in) ||
	    !strncmp("any", mode.device_in, strlen(mode.device_in))) {
		if (!mode.device_out) {
			mode.dump = 0;
			enter_mode = enter_mode_rx_only_or_dump;
		} else if (device_mtu(mode.device_out))
			enter_mode = enter_mode_rx_to_tx;
		else {
			mode.dump = 1;
			enter_mode = enter_mode_rx_only_or_dump;
		}
	} else {
		if (device_mtu(mode.device_out))
			enter_mode = enter_mode_pcap_to_tx;
		else
			enter_mode = enter_mode_read_pcap;
	}

	if (!enter_mode)
		panic("Selection not supported!\n");
	enter_mode(&mode);

	tprintf_cleanup();
	cleanup_rw_pcap();
//	cleanup_sg_pcap();
//	cleanup_mmap_pcap();

	if (mode.device_in)
		xfree(mode.device_in);
	if (mode.device_out)
		xfree(mode.device_out);
	return 0;
}


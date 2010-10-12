/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
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

#define TMP_STAT_FILE "/tmp/netsniff-ng"

struct stats {
	pthread_spinlock_t lock;
	unsigned long rx_bytes;
	unsigned long rx_packets;
	unsigned long tx_bytes;
	unsigned long tx_packets;
};

struct mode {
	struct stats stats;
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

static const char *short_options = "d:i:o:z:Erf:Mt:S:b:B:HQsqlxCXNe:vh";

static struct option long_options[] = {
	{"dev", required_argument, 0, 'd'},
	{"in", required_argument, 0, 'i'},
	{"out", required_argument, 0, 'o'},
	{"compress", required_argument, 0, 'z'},
	{"encrypt", no_argument, 0, 'E'},
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

/* FIXME: only for SIGUSR1 */
static struct mode *pmode;

static void signal_handler(int number)
{
	FILE *fp = NULL;
	char file[256];

	switch (number) {
	case SIGINT:
		sigint = 1;
		break;
	case SIGHUP:
		break;
	case SIGUSR1:
		/*
		 * What we do here is to present a conform way of delivering
		 * runtime statistics to the user for postprocessing. The user
		 * is able to decide the interval for his own, since the
		 * counters are reset after writing. Some Perl or Shell script
		 * could transform the values and propagate them to Gnuplot or
		 * even Nagios for instance.
		 */
		snprintf(file, sizeof(file), "%s.%u", TMP_STAT_FILE, getpid());
		fp = fopen(file, "w+");
		if (fp == NULL)
			return;

		pthread_spin_lock(&pmode->stats.lock);
		fprintf(fp, "RX: %lu,%lu TX: %lu,%lu\n",
			pmode->stats.rx_bytes, pmode->stats.rx_packets,
			pmode->stats.tx_bytes, pmode->stats.tx_packets);

		/* Reset counters */
		pmode->stats.rx_bytes = 0;
		pmode->stats.rx_packets = 0;
		pmode->stats.tx_bytes = 0;
		pmode->stats.tx_packets = 0;
		pthread_spin_unlock(&pmode->stats.lock);

		fclose(fp);
		break;
	default:
		break;
	}
}

/*
 * PCAP_TO_TX mode:
 *
 * This means, a PCAP file is read and replayed by the device. By adding BPF
 * program, you can filter what should be retransmitted and what not.
 */
void enter_mode_pcap_to_tx(struct mode *mode)
{
	/* NOP */
}

/*
 * RX_TO_TX mode:
 *
 * RX to TX means that the packets will arrive into the RX_RING of device 1 
 * and will then be put into the TX_RING of device 2. So this can be considered 
 * as a unidirectional RX/TX_RING bridge. There's a randomize option in order 
 * to bring the packet order out of order. This could be used to test the 
 * robustness of UDP-based programs or to test the TCP stack.
 */
void enter_mode_rx_to_tx(struct mode *mode)
{
	/* NOP */
}

/*
 * PCAP_TO_PCAP mode:
 *
 * This mode is intended to transform a PCAP file into a PCAP file. netsniff-ng
 * is able to encrypt or compress PCAP files which is an extension to the 
 * standard, so this mode can tranform these files back to readable, 
 * standard-conform PCAP files that can be read with Wireshark and others.
 */
void enter_mode_pcap_to_pcap(struct mode *mode)
{
	/* NOP */
}

/*
 * PCAP_ONLY mode:
 *
 * This mode is intended to do a offline analysis of a PCAP file.
 */
void enter_mode_pcap_only(struct mode *mode)
{
	/* NOP */
}

/*
 * TX_ONLY mode:
 *
 * This mode is intended to act as a traffic generator. It randomly generates 
 * packets and pushes them into the TX_RING which is then flushed by the 
 * kernel. Configure options will follow soon.
 */
void enter_mode_tx_only(struct mode *mode)
{
	/* NOP */
}

/*
 * RX_TO_PCAP mode:
 *
 * See RX_ONLY mode but with the additional focus on writing the received 
 * packets into a PCAP formatted file. The focus here is to have a 'fastpath'
 * for dumping, not analyzing, so per default, we do not print packets.
 */
void enter_mode_rx_to_pcap(struct mode *mode)
{
	/* NOP */
}

/*
 * RX_ONLY mode:
 *
 * In this mode we only make usage of the RX_RING for network debugging.
 * Packets will be pushed into the ring by the kernel and we grab them 
 * with our user-defined printing mode.
 */
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

	/* IRQ affinity settings */
	if (mode->cpu >= 0 && ifindex > 0) {
		irq = device_irq_number(mode->device_in);
		device_bind_irq_to_cpu(mode->cpu, irq);
		printf("IRQ: %s:%d > CPU%d\n", mode->device_in, irq, 
		       mode->cpu);
	}

	/* Promiscuous mode settings */
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

			pthread_spin_lock(&mode->stats.lock);
			mode->stats.rx_bytes += hdr->tp_h.tp_len;
			mode->stats.rx_packets++;
			pthread_spin_unlock(&mode->stats.lock);

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
	printf("\n");
	printf("Options for input/output (aka capture/replay/analysis/transformation):\n");
	printf("  -i|--in <dev|pcap>     Input source as netdev or pcap[xz]\n");
	printf("  -o|--out <dev|pcap>    Output source as netdev or pcap[xz]\n");
	printf("\n");
	printf("Options for RX to PCAP and PCAP to PCAP mode:\n");
	printf("  -z|--compress <level>  Stores packets with Deflate compression\n");
	printf("  -E|--encrypt           Stores packets Twofish encrypted\n");
	printf("\n");
	printf("Options for RX to TX mode:\n");
	printf("  -r|--randomize         Randomize packet forwarding order\n");
	printf("\n");
#if 0 /* Or better as separate program */
	printf("Options for MITM:\n");
	printf("  -P|--poison            ARP spoofing for MITM sniffing\n");
	printf("\n");
#endif
	printf("Options for packet filtering:\n");
	printf("  -f|--filter <bpf-file> Use BPF filter rule from file\n");
#if 0
	printf("  -g|--gen-filter <rule> Generates BPF filter expression\n");
#endif
	printf("  -M|--no-promisc        No promiscuous mode for netdev\n");
	printf("  -t|--type <type>       Only show packets of defined type:\n");
	printf("                         host|broadcast|multicast|others|outgoing\n");
	printf("\n");
	printf("Options for RX and TX_RING:\n");
	printf("  -S|--ring-size <size>  Manually set ring size to <size>:\n");
	printf("                         mmap space in KB/MB/GB, e.g. \'10MB\'\n");
	printf("\n");
	printf("Options for system scheduler/process:\n");
	printf("  -b|--bind-cpu <cpu>    Bind to specific CPU or CPU-range\n");
	printf("  -B|--unbind-cpu <cpu>  Forbid to use specific CPU or CPU-range\n");
	printf("  -H|--prio-norm         Do not high priorize process\n");
	printf("  -Q|--notouch-irq       Do not touch IRQ CPU affinity of NIC\n");
	printf("\n");
	printf("Options for packet printing:\n");
	printf("  -s|--silent            Do not print captured packets\n");
	printf("  -q|--less              Print less-verbose packet information\n");
	printf("  -l|--payload           Only print human-readable payload\n");
	printf("  -x|--payload-hex       Only print payload in hex format\n");
	printf("  -C|--c-style           Print full packet in C style hex format\n");
	printf("  -X|--all-hex           Print packets in hex format\n");
	printf("  -N|--no-payload        Only print packet header\n");
	printf("  -e|--regex <expr>      Only print packet that matches regex\n");
	printf("\n");
	printf("Options, misc:\n");
	printf("  -v|--version           Show version\n");
	printf("  -h|--help              Show this help\n");
	printf("\n");
	printf("Note:\n");
	printf("  - Use \'any\' as device for listening on all NICs\n");
	printf("  - Sending a SIGUSR1 will show current packet statistics\n");
	printf("  - Binding netsniff-ng to a specific CPU increases performance\n");
	printf("    since NIC RX/TX interrupts will be bound to that CPU, too\n");
	printf("  - For more help try \'man netsniff-ng\'\n");
	printf("\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2009, 2010 Daniel Borkmann and Emmanuel Roullit\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");

	exit(EXIT_SUCCESS);
}

static void version(void)
{
	printf("\n%s %s, the packet sniffing beast\n", PROGNAME_STRING,
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2009, 2010 Daniel Borkmann and Emmanuel Roullit\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");

	exit(EXIT_SUCCESS);
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

	/* Default settings */
	memset(&mode, 0, sizeof(mode));
	pthread_spin_init(&mode.stats.lock, PTHREAD_PROCESS_SHARED);
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
		case 'd': /* dev + arg */
		case 'i': /* in + arg */
			/* file || netdev */
			mode.device_in = xstrdup(optarg);
			break;
		case 'o': /* out + arg */
			/* file || netdev */
			mode.device_out = xstrdup(optarg);
			break;
		case 'z': /* compress + arg */
			mode.compress = atoi(optarg);
			/* Deflate compression levels are between 1 and 9 */
			if (mode.compress < 1)
				mode.compress = 1;
			if (mode.compress > 9)
				mode.compress = 9;
			break;
		case 'E': /* encrypt */
			mode.encrypt = true;
			break;
		case 'r': /* randomize */
			mode.randomize = true;
			break;
		case 'f': /* filter + arg */
			/* file */
			mode.filter = xstrdup(optarg);
			break;
		case 'M': /* no-promisc */
			mode.promiscuous = false;
			break;
		case 't': /* type + arg */
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
		case 'S': /* ring-size + arg */
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
		case 'b': /* bind-cpu + arg */
			set_cpu_affinity(optarg, 0);
			/* Take the first CPU for rebinding the IRQ */
			if (mode.cpu != CPU_NOTOUCH)
				mode.cpu = atoi(optarg);
			break;
		case 'B': /* unbind-cpu + arg */
			set_cpu_affinity(optarg, 1);
			break;
		case 'H': /* prio-norm */
			prio_high = false;
			break;
		case 'Q': /* notouch-irq */
			mode.cpu = CPU_NOTOUCH;
			break;
		case 's': /* silent */
			mode.print_mode = FNTTYPE_PRINT_NONE;
			break;
		case 'q': /* less */
			mode.print_mode = FNTTYPE_PRINT_LESS;
			break;
		case 'l': /* payload */
			mode.print_mode = FNTTYPE_PRINT_CHR1;
			break;
		case 'x': /* payload-hex */
			mode.print_mode = FNTTYPE_PRINT_HEX1;
			break;
		case 'C': /* c-style */
			mode.print_mode = FNTTYPE_PRINT_PAAC;
			break;
		case 'X': /* all-hex */
			mode.print_mode = FNTTYPE_PRINT_HEX2;
			break;
		case 'N': /* no-payload */
			mode.print_mode = FNTTYPE_PRINT_NOPA;
			break;
		case 'e': /* regex + arg, TODO: arg */
			mode.print_mode = FNTTYPE_PRINT_REGX;
			break;
		case 'v': /* version */
			version();
			break;
		case 'h': /* help */
			help();
			break;
		case '?':
			switch (optopt) {
			case 'd':
			case 'i':
			case 'o':
			case 'z':
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

	/* Take the any-device (0) as default */
	if (!mode.device_in)
		mode.device_in = "any";

	register_signal(SIGINT, &signal_handler);
	register_signal(SIGHUP, &signal_handler);
	register_signal(SIGUSR1, &signal_handler);

	tprintf_init();
	header();

	if (prio_high == true) {
		set_proc_prio(DEFAULT_PROCESS_PRIO);
		set_sched_status(DEFAULT_SCHED_POLICY, DEFAULT_SCHED_PRIO);
	}

	/* TODO: mode selection according to device_in and device_out */
	pmode = &mode;
	enter_mode = enter_mode_rx_only;
	enter_mode(&mode);

	tprintf_cleanup();
	return 0;
}


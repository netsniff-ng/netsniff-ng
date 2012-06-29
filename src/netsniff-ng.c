/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009-2011 Daniel Borkmann.
 * Copyright 2010 Emmanuel Roullit.
 * Subject to the GPL, version 2.
 *
 * The first sniffer that invoked both, the zero-copy RX_RING as well as
 * the zero-copy TX_RING for high-performance network I/O and scatter/gather
 * or mmaped PCAP I/O.
 *
 *   "I knew that danger lay ahead, of course; but I did not expect to
 *   meet it in our own Shire. Can't a hobbit walk from the Water to the
 *   River in peace?" "But it is not your own Shire," said Gildor. "Others
 *   dwelt here before hobbits were; and others will dwell here again when
 *   hobbits are no more. The wide world is all about you: you can fence
 *   yourselves in, but you cannot for ever fence it out."
 *
 *     -- The Lord of the Rings, Gildor to Frodo,
 *        Chapter 'Three is Company'.
 */

/*

=head1 NAME

netsniff-ng - the packet sniffing beast

=head1 SYNOPSIS

netsniff-ng -i|-d|--dev|--in <dev|pcap> -o|--out <dev|pcap|dir|txf>
[-f|--filter <bpf-file>][-t|--type <type>][-F|--interval <uint>]
[-s|--silent][-J|--jumbo-support][-n|--num <uint>][-r|--rand]
[-M|--no-promisc][-m|--mmap | -c|--clrw][-S|--ring-size <size>]
[-k|--kernel-pull <uint>][-b|--bind-cpu <cpu> | -B|--unbind-cpu <cpu>]
[-H|--prio-high][-Q|--notouch-irq][-q|--less | -X|--hex | -l|--ascii]
[-v|--version][-h|--help]

=head1 DESCRIPTION

The first sniffer that invoked both, the zero-copy RX_RING as well as
the zero-copy TX_RING for high-performance network I/O and scatter/gather
or mmaped PCAP I/O.

=head1 EXAMPLES

=over

=item netsniff-ng --in eth0 --out dump.pcap

Capture traffic from interface 'eth0' and save it pcap file 'dump.pcap'

=item netsniff-ng --in any --filter http.bpf --payload

Capture HTTP traffic from any interface and print its payload on stdout

=item netsniff-ng --in wlan0 --bind-cpu 0,1

Capture all traffic from wlan0 interface.
Schedule process on CPU 0 and 1.

=back

=head1 OPTIONS

=over

=item -i|-d|--dev|--in <dev|pcap>

Input source. Can be a network device or pcap file.

=item -o|--out <dev|pcap|dir|txf>

Output sink. Can be a network device, pcap file, a trafgen txf file or a
directory. (There's only pcap to txf translation possible.)

=item -f|--filter <bpf-file>

Use BPF filter file from bpfc.

=item -t|--type <type>

=over

=item Only handle packets of defined type:

=over

=item - broadcast

=item - multicast

=item - others

=item - outgoing

=back

=back

=item -F|--interval <uint>

Dump interval in seconds. if -o is a directory, a new pcap will be created at each interval.
The older files are left untouched. (default value: 60 seconds)

=item -s|--silent

Do not print captured packets to stdout.

=item -J|--jumbo-support

Support for 64KB Super Jumbo Frames.

=item -n|--num <uint>

When zerp, capture/replay until SIGINT is received (default).
When non-zero, capture/replay the number of packets.

=item -r|--rand

Randomize packet forwarding order (replay mode only).

=item -M|--no-promisc

Do not place the interface in promiscuous mode.

=item -m|--mmap

Mmap pcap file i.e., for replaying. Default: scatter/gather I/O.

=item -c|--clrw

Instead of using scatter/gather I/O use slower read(2)/write(2) I/O.

=item -S|--ring-size <size>

Manually set ring size in KB/MB/GB, e.g. '10MB'.

=item -k|--kernel-pull <uint>

Kernel pull from user interval in microseconds. Default is 10us. (replay mode only).

=item -b|--bind-cpu <cpu>

Bind to specific CPU (or CPU-range).

=item -B|--unbind-cpu <cpu>

Forbid to use specific CPU (or CPU-range).

=item -H|--prio-high

Run the process in high-priority mode.

=item -Q|--notouch-irq

Do not touch IRQ CPU affinity of NIC.

=item -q|--less

Print less-verbose packet information.

=item -X|--hex

Print packet data in hex format.

=item -l|--ascii

Print human-readable packet data.

=item -v|--version

Print version.

=item -h|--help

Print help text and lists all options.

=back

=head1 AUTHOR

Written by Daniel Borkmann <daniel@netsniff-ng.org> and Emmanuel Roullit <emmanuel@netsniff-ng.org>

=head1 DOCUMENTATION

Documentation by Emmanuel Roullit <emmanuel@netsniff-ng.org>

=head1 BUGS

Please report bugs to <bugs@netsniff-ng.org>

=cut

*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <getopt.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdbool.h>
#include <pthread.h>
#include <fcntl.h>

#include "ring_rx.h"
#include "ring_tx.h"
#include "mac80211.h"
#include "xutils.h"
#include "built_in.h"
#include "pcap.h"
#include "bpf.h"
#include "xio.h"
#include "die.h"
#include "tprintf.h"
#include "dissector.h"
#include "xmalloc.h"
#include "mtrand.h"

#define CPU_UNKNOWN	-1
#define CPU_NOTOUCH	-2
#define PACKET_ALL	-1
#define DUMP_INTERVAL	60

struct mode {
	char *device_in;
	char *device_out;
	char *device_trans;
	char *filter;
	int cpu;
	int rfraw;
	int dump;
	uint32_t link_type;
	int print_mode;
	unsigned int reserve_size;
	int packet_type;
	bool randomize;
	bool promiscuous;
	enum pcap_ops_groups pcap;
	unsigned long kpull;
	int jumbo_support;
	int dump_dir;
	unsigned long dump_interval;
};

struct tx_stats {
	unsigned long tx_bytes;
	unsigned long tx_packets;
};

volatile sig_atomic_t sigint = 0;

static int tx_sock;
static unsigned long frame_cnt_max = 0;
static unsigned long interval = TX_KERNEL_PULL_INT;
static struct itimerval itimer;
static volatile bool next_dump = false;

static const char *short_options = "d:i:o:rf:MJt:S:k:n:b:B:HQmcsqXlvhF:Rg";

static struct option long_options[] = {
	{"dev", required_argument, 0, 'd'},
	{"in", required_argument, 0, 'i'},
	{"out", required_argument, 0, 'o'},
	{"rand", no_argument, 0, 'r'},
	{"rfraw", no_argument, 0, 'R'},
	{"mmap", no_argument, 0, 'm'},
	{"sg", no_argument, 0, 'g'},
	{"clrw", no_argument, 0, 'c'},
	{"jumbo-support", no_argument, 0, 'J'},
	{"filter", required_argument, 0, 'f'},
	{"no-promisc", no_argument, 0, 'M'},
	{"num", required_argument, 0, 'n'},
	{"type", required_argument, 0, 't'},
	{"interval", required_argument, 0, 'F'},
	{"ring-size", required_argument, 0, 'S'},
	{"kernel-pull", required_argument, 0, 'k'},
	{"bind-cpu", required_argument, 0, 'b'},
	{"unbind-cpu", required_argument, 0, 'B'},
	{"prio-high", no_argument, 0, 'H'},
	{"notouch-irq", no_argument, 0, 'Q'},
	{"silent", no_argument, 0, 's'},
	{"less", no_argument, 0, 'q'},
	{"hex", no_argument, 0, 'X'},
	{"ascii", no_argument, 0, 'l'},
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

static void timer_elapsed(int number)
{
	itimer.it_interval.tv_sec = 0;
	itimer.it_interval.tv_usec = interval;
	itimer.it_value.tv_sec = 0;
	itimer.it_value.tv_usec = interval;

	pull_and_flush_tx_ring(tx_sock);
	setitimer(ITIMER_REAL, &itimer, NULL);
}

static void timer_next_dump(int number)
{
	itimer.it_interval.tv_sec = interval;
	itimer.it_interval.tv_usec = 0;
	itimer.it_value.tv_sec = interval;
	itimer.it_value.tv_usec = 0;

	next_dump = true;
	setitimer(ITIMER_REAL, &itimer, NULL);
}

static void enter_mode_pcap_to_tx(struct mode *mode)
{
	int irq, ifindex, fd = 0, ret;
	unsigned int size, it = 0;
	struct ring tx_ring;
	struct frame_map *hdr;
	struct sock_fprog bpf_ops;
	struct tx_stats stats;
	uint8_t *out = NULL;
	unsigned long trunced = 0;
	struct timeval start, end, diff;

	if (!device_up_and_running(mode->device_out))
		panic("Device not up and running!\n");

	tx_sock = pf_socket();

	if (!pcap_ops[mode->pcap])
		panic("pcap group not supported!\n");
	fd = open_or_die(mode->device_in, O_RDONLY | O_LARGEFILE | O_NOATIME);
	ret = pcap_ops[mode->pcap]->pull_file_header(fd, &mode->link_type);
	if (ret)
		panic("error reading pcap header!\n");
	if (pcap_ops[mode->pcap]->prepare_reading_pcap) {
		ret = pcap_ops[mode->pcap]->prepare_reading_pcap(fd);
		if (ret)
			panic("error prepare reading pcap!\n");
	}

	fmemset(&tx_ring, 0, sizeof(tx_ring));
	fmemset(&bpf_ops, 0, sizeof(bpf_ops));
	fmemset(&stats, 0, sizeof(stats));

	if (mode->rfraw) {
		mode->device_trans = xstrdup(mode->device_out);
		xfree(mode->device_out);

		enter_rfmon_mac80211(mode->device_trans, &mode->device_out);
		if (mode->link_type != LINKTYPE_IEEE802_11)
			panic("Wrong linktype of pcap!\n");
	}

	ifindex = device_ifindex(mode->device_out);
	size = ring_size(mode->device_out, mode->reserve_size);

	bpf_parse_rules(mode->filter, &bpf_ops);

	set_packet_loss_discard(tx_sock);
	set_sockopt_hwtimestamp(tx_sock, mode->device_out);
	setup_tx_ring_layout(tx_sock, &tx_ring, size, mode->jumbo_support);
	create_tx_ring(tx_sock, &tx_ring);
	mmap_tx_ring(tx_sock, &tx_ring);
	alloc_tx_ring_frames(&tx_ring);
	bind_tx_ring(tx_sock, &tx_ring, ifindex);

	dissector_init_all(mode->print_mode);

	if (mode->cpu >= 0 && ifindex > 0) {
		irq = device_irq_number(mode->device_out);
		device_bind_irq_to_cpu(mode->cpu, irq);
		printf("IRQ: %s:%d > CPU%d\n", mode->device_out, irq, 
		       mode->cpu);
	}

	if (mode->kpull)
		interval = mode->kpull;

	itimer.it_interval.tv_sec = 0;
	itimer.it_interval.tv_usec = interval;
	itimer.it_value.tv_sec = 0;
	itimer.it_value.tv_usec = interval;
	setitimer(ITIMER_REAL, &itimer, NULL); 

	printf("BPF:\n");
	bpf_dump_all(&bpf_ops);
	printf("MD: TX %luus %s ", interval, pcap_ops[mode->pcap]->name);
	if (mode->rfraw)
		printf("802.11 raw via %s ", mode->device_out);
#ifdef _LARGEFILE64_SOURCE
	printf("lf64 ");
#endif 
	ioprio_print();
	printf("\n");

	gettimeofday(&start, NULL);

	while (likely(sigint == 0)) {
		while (user_may_pull_from_tx(tx_ring.frames[it].iov_base)) {
			struct pcap_pkthdr phdr;
			hdr = tx_ring.frames[it].iov_base;
			/* Kernel assumes: data = ph.raw + po->tp_hdrlen -
			 * sizeof(struct sockaddr_ll); */
			out = ((uint8_t *) hdr) + TPACKET_HDRLEN -
			      sizeof(struct sockaddr_ll);

			do {
				memset(&phdr, 0, sizeof(phdr));
				ret = pcap_ops[mode->pcap]->read_pcap_pkt(fd, &phdr,
						out, ring_frame_size(&tx_ring));
				if (unlikely(ret <= 0))
					goto out;
				if (ring_frame_size(&tx_ring) < phdr.len) {
					phdr.len = ring_frame_size(&tx_ring);
					trunced++;
				}
			} while (mode->filter && !bpf_run_filter(&bpf_ops, out, phdr.len));
			pcap_pkthdr_to_tpacket_hdr(&phdr, &hdr->tp_h);

			stats.tx_bytes += hdr->tp_h.tp_len;;
			stats.tx_packets++;

			show_frame_hdr(hdr, mode->print_mode, RING_MODE_EGRESS);
			dissector_entry_point(out, hdr->tp_h.tp_snaplen,
					      mode->link_type, mode->print_mode);

			kernel_may_pull_from_tx(&hdr->tp_h);
			next_slot_prewr(&it, &tx_ring);

			if (unlikely(sigint == 1))
				break;
			if (frame_cnt_max != 0 &&
			    stats.tx_packets >= frame_cnt_max) {
				sigint = 1;
				break;
			}
		}
	}
out:
	gettimeofday(&end, NULL);
	diff = tv_subtract(end, start);

	fflush(stdout);
	printf("\n");
	printf("\r%12lu frames outgoing\n", stats.tx_packets);
	printf("\r%12lu frames truncated (larger than frame)\n", trunced);
	printf("\r%12lu bytes outgoing\n", stats.tx_bytes);
	printf("\r%12lu sec, %lu usec in total\n", diff.tv_sec, diff.tv_usec);

	bpf_release(&bpf_ops);
	dissector_cleanup_all();
	destroy_tx_ring(tx_sock, &tx_ring);

	if (mode->rfraw)
		leave_rfmon_mac80211(mode->device_trans, mode->device_out);

	close(tx_sock);
	if (pcap_ops[mode->pcap]->prepare_close_pcap)
		pcap_ops[mode->pcap]->prepare_close_pcap(fd, PCAP_MODE_READ);
	close(fd);
}

static void enter_mode_rx_to_tx(struct mode *mode)
{
	int rx_sock, ifindex_in, ifindex_out;
	unsigned int size_in, size_out, it_in = 0, it_out = 0;
	unsigned long fcnt = 0;
	uint8_t *in, *out;
	short ifflags = 0;
	struct frame_map *hdr_in, *hdr_out;
	struct ring tx_ring;
	struct ring rx_ring;
	struct pollfd rx_poll;
	struct sock_fprog bpf_ops;

	if (!strncmp(mode->device_in, mode->device_out,
		     strlen(mode->device_in)))
		panic("Ingress/egress devices must be different!\n");
	if (!device_up_and_running(mode->device_out))
		panic("Egress device not up and running!\n");
	if (!device_up_and_running(mode->device_in))
		panic("Ingress device not up and running!\n");

	rx_sock = pf_socket();
	tx_sock = pf_socket();

	fmemset(&tx_ring, 0, sizeof(tx_ring));
	fmemset(&rx_ring, 0, sizeof(rx_ring));
	fmemset(&rx_poll, 0, sizeof(rx_poll));
	fmemset(&bpf_ops, 0, sizeof(bpf_ops));

	ifindex_in = device_ifindex(mode->device_in);
	size_in = ring_size(mode->device_in, mode->reserve_size);

	ifindex_out = device_ifindex(mode->device_out);
	size_out = ring_size(mode->device_out, mode->reserve_size);

	enable_kernel_bpf_jit_compiler();
	bpf_parse_rules(mode->filter, &bpf_ops);
	bpf_attach_to_sock(rx_sock, &bpf_ops);

	setup_rx_ring_layout(rx_sock, &rx_ring, size_in, mode->jumbo_support);
	create_rx_ring(rx_sock, &rx_ring);
	mmap_rx_ring(rx_sock, &rx_ring);
	alloc_rx_ring_frames(&rx_ring);
	bind_rx_ring(rx_sock, &rx_ring, ifindex_in);
	prepare_polling(rx_sock, &rx_poll);

	set_packet_loss_discard(tx_sock);
	setup_tx_ring_layout(tx_sock, &tx_ring, size_out, mode->jumbo_support);
	create_tx_ring(tx_sock, &tx_ring);
	mmap_tx_ring(tx_sock, &tx_ring);
	alloc_tx_ring_frames(&tx_ring);
	bind_tx_ring(tx_sock, &tx_ring, ifindex_out);

	mt_init_by_seed_time();
	dissector_init_all(mode->print_mode);

	 if (mode->promiscuous == true) {
		ifflags = enter_promiscuous_mode(mode->device_in);
		printf("PROMISC\n");
	}

	if (mode->kpull)
		interval = mode->kpull;

	itimer.it_interval.tv_sec = 0;
	itimer.it_interval.tv_usec = interval;
	itimer.it_value.tv_sec = 0;
	itimer.it_value.tv_usec = interval;
	setitimer(ITIMER_REAL, &itimer, NULL);

	printf("BPF:\n");
	bpf_dump_all(&bpf_ops);
	printf("MD: RXTX %luus\n\n", interval);
	printf("Running! Hang up with ^C!\n\n");

	while (likely(sigint == 0)) {
		while (user_may_pull_from_rx(rx_ring.frames[it_in].iov_base)) {
			hdr_in = rx_ring.frames[it_in].iov_base;
			in = ((uint8_t *) hdr_in) + hdr_in->tp_h.tp_mac;
			fcnt++;
			if (mode->packet_type != PACKET_ALL)
				if (mode->packet_type != hdr_in->s_ll.sll_pkttype)
					goto next;

			hdr_out = tx_ring.frames[it_out].iov_base;
			out = ((uint8_t *) hdr_out) + TPACKET_HDRLEN -
			      sizeof(struct sockaddr_ll);

			for (; !user_may_pull_from_tx(tx_ring.frames[it_out].iov_base) &&
			       likely(!sigint);) {
				if (mode->randomize)
					next_rnd_slot(&it_out, &tx_ring);
				else
					next_slot(&it_out, &tx_ring);
				hdr_out = tx_ring.frames[it_out].iov_base;
				out = ((uint8_t *) hdr_out) + TPACKET_HDRLEN -
				      sizeof(struct sockaddr_ll);
			}

			tpacket_hdr_clone(&hdr_out->tp_h, &hdr_in->tp_h);
			fmemcpy(out, in, hdr_in->tp_h.tp_len);

			kernel_may_pull_from_tx(&hdr_out->tp_h);
			if (mode->randomize)
				next_rnd_slot(&it_out, &tx_ring);
			else
				next_slot(&it_out, &tx_ring);

			show_frame_hdr(hdr_in, mode->print_mode, RING_MODE_INGRESS);
			dissector_entry_point(in, hdr_in->tp_h.tp_snaplen,
					      mode->link_type, mode->print_mode);

			if (frame_cnt_max != 0 && fcnt >= frame_cnt_max) {
				sigint = 1;
				break;
			}
next:
			kernel_may_pull_from_rx(&hdr_in->tp_h);
			next_slot(&it_in, &rx_ring);

			if (unlikely(sigint == 1))
				goto out;
		}

		poll(&rx_poll, 1, -1);
		poll_error_maybe_die(rx_sock, &rx_poll);
	}
out:
	sock_print_net_stats(rx_sock, 0);

	bpf_release(&bpf_ops);
	dissector_cleanup_all();
	destroy_tx_ring(tx_sock, &tx_ring);
	destroy_rx_ring(rx_sock, &rx_ring);

	if (mode->promiscuous == true)
		leave_promiscuous_mode(mode->device_in, ifflags);

	close(tx_sock);
	close(rx_sock);
}

static void enter_mode_read_pcap(struct mode *mode)
{
	int ret, fd, fdo = 0;
	struct pcap_pkthdr phdr;
	struct sock_fprog bpf_ops;
	struct tx_stats stats;
	struct frame_map fm;
	uint8_t *out;
	size_t out_len;
	unsigned long trunced = 0;
	struct timeval start, end, diff;

	if (!pcap_ops[mode->pcap])
		panic("pcap group not supported!\n");
	fd = open_or_die(mode->device_in, O_RDONLY | O_LARGEFILE | O_NOATIME);
	ret = pcap_ops[mode->pcap]->pull_file_header(fd, &mode->link_type);
	if (ret)
		panic("error reading pcap header!\n");
	if (pcap_ops[mode->pcap]->prepare_reading_pcap) {
		ret = pcap_ops[mode->pcap]->prepare_reading_pcap(fd);
		if (ret)
			panic("error prepare reading pcap!\n");
	}

	fmemset(&fm, 0, sizeof(fm));
	fmemset(&bpf_ops, 0, sizeof(bpf_ops));
	fmemset(&stats, 0, sizeof(stats));

	bpf_parse_rules(mode->filter, &bpf_ops);
	dissector_init_all(mode->print_mode);

	out_len = 64 * 1024;
	out = xmalloc_aligned(out_len, CO_CACHE_LINE_SIZE);

	printf("BPF:\n");
	bpf_dump_all(&bpf_ops);
	printf("MD: RD %s ", pcap_ops[mode->pcap]->name);
#ifdef _LARGEFILE64_SOURCE
	printf("lf64 ");
#endif 
	ioprio_print();
	printf("\n");

	if (mode->device_out) {
		fdo = open_or_die_m(mode->device_out, O_RDWR | O_CREAT |
				    O_TRUNC | O_LARGEFILE, DEFFILEMODE);
	}

	gettimeofday(&start, NULL);

	while (likely(sigint == 0)) {
		do {
			memset(&phdr, 0, sizeof(phdr));
			ret = pcap_ops[mode->pcap]->read_pcap_pkt(fd, &phdr,
					out, out_len);
			if (unlikely(ret < 0))
				goto out;
			if (unlikely(phdr.len == 0)) {
				trunced++;
				continue;
			}
			if (unlikely(phdr.len > out_len)) {
				phdr.len = out_len;
				trunced++;
			}
		} while (mode->filter &&
			 !bpf_run_filter(&bpf_ops, out, phdr.len));

		pcap_pkthdr_to_tpacket_hdr(&phdr, &fm.tp_h);

		stats.tx_bytes += fm.tp_h.tp_len;
		stats.tx_packets++;

		show_frame_hdr(&fm, mode->print_mode, RING_MODE_EGRESS);
		dissector_entry_point(out, fm.tp_h.tp_snaplen,
				      mode->link_type, mode->print_mode);

		if (mode->device_out) {
			int i = 0;
			char bout[80];
			slprintf(bout, sizeof(bout), "{\n  ");
			write_or_die(fdo, bout, strlen(bout));

			while (i < fm.tp_h.tp_snaplen) {
				slprintf(bout, sizeof(bout), "0x%02x, ", out[i]);
				write_or_die(fdo, bout, strlen(bout));
				i++;
				if (i % 10 == 0) {
					slprintf(bout, sizeof(bout), "\n", out[i]);
					write_or_die(fdo, bout, strlen(bout));
					if (i < fm.tp_h.tp_snaplen) {
						slprintf(bout, sizeof(bout), "  ", out[i]);
						write_or_die(fdo, bout, strlen(bout));
					}
				}
			}
			if (i % 10 != 0) {
				slprintf(bout, sizeof(bout), "\n");
				write_or_die(fdo, bout, strlen(bout));
			}
			slprintf(bout, sizeof(bout), "}\n\n");
			write_or_die(fdo, bout, strlen(bout));
		}

		if (frame_cnt_max != 0 &&
		    stats.tx_packets >= frame_cnt_max) {
			sigint = 1;
			break;
		}
	}
out:
	gettimeofday(&end, NULL);
	diff = tv_subtract(end, start);

	fflush(stdout);
	printf("\n");
	printf("\r%12lu frames outgoing\n", stats.tx_packets);
	printf("\r%12lu frames truncated (larger than mtu)\n", trunced);
	printf("\r%12lu bytes outgoing\n", stats.tx_bytes);
	printf("\r%12lu sec, %lu usec in total\n", diff.tv_sec, diff.tv_usec);

	xfree(out);

	bpf_release(&bpf_ops);
	dissector_cleanup_all();
	if (pcap_ops[mode->pcap]->prepare_close_pcap)
		pcap_ops[mode->pcap]->prepare_close_pcap(fd, PCAP_MODE_READ);
	close(fd);

	if (mode->device_out)
		close(fdo);
}

static void finish_multi_pcap_file(struct mode *mode, int fd)
{
	pcap_ops[mode->pcap]->fsync_pcap(fd);
	if (pcap_ops[mode->pcap]->prepare_close_pcap)
		pcap_ops[mode->pcap]->prepare_close_pcap(fd, PCAP_MODE_WRITE);
	close(fd);

	fmemset(&itimer, 0, sizeof(itimer));
	setitimer(ITIMER_REAL, &itimer, NULL);
}

static int next_multi_pcap_file(struct mode *mode, int fd)
{
	int ret;
	char tmp[512];

	pcap_ops[mode->pcap]->fsync_pcap(fd);
	if (pcap_ops[mode->pcap]->prepare_close_pcap)
		pcap_ops[mode->pcap]->prepare_close_pcap(fd, PCAP_MODE_WRITE);
	close(fd);

	slprintf(tmp, sizeof(tmp), "%s/%lu.pcap", mode->device_out, time(0));

	fd = open_or_die_m(tmp, O_RDWR | O_CREAT | O_TRUNC | O_LARGEFILE,
			   DEFFILEMODE);
	ret = pcap_ops[mode->pcap]->push_file_header(fd, mode->link_type);
	if (ret)
		panic("error writing pcap header!\n");
	if (pcap_ops[mode->pcap]->prepare_writing_pcap) {
		ret = pcap_ops[mode->pcap]->prepare_writing_pcap(fd);
		if (ret)
			panic("error prepare writing pcap!\n");
	}

	return fd;
}

static int begin_multi_pcap_file(struct mode *mode)
{
	int fd, ret;
	char tmp[512];

	if (!pcap_ops[mode->pcap])
		panic("pcap group not supported!\n");
	if (mode->device_out[strlen(mode->device_out) - 1] == '/')
		mode->device_out[strlen(mode->device_out) - 1] = 0;

	slprintf(tmp, sizeof(tmp), "%s/%lu.pcap", mode->device_out, time(0));

	fd = open_or_die_m(tmp, O_RDWR | O_CREAT | O_TRUNC | O_LARGEFILE,
			   DEFFILEMODE);
	ret = pcap_ops[mode->pcap]->push_file_header(fd, mode->link_type);
	if (ret)
		panic("error writing pcap header!\n");
	if (pcap_ops[mode->pcap]->prepare_writing_pcap) {
		ret = pcap_ops[mode->pcap]->prepare_writing_pcap(fd);
		if (ret)
			panic("error prepare writing pcap!\n");
	}

	interval = mode->dump_interval;
	itimer.it_interval.tv_sec = interval;
	itimer.it_interval.tv_usec = 0;
	itimer.it_value.tv_sec = interval;
	itimer.it_value.tv_usec = 0;
	setitimer(ITIMER_REAL, &itimer, NULL);

	return fd;
}

static void finish_single_pcap_file(struct mode *mode, int fd)
{
	pcap_ops[mode->pcap]->fsync_pcap(fd);
	if (pcap_ops[mode->pcap]->prepare_close_pcap)
		pcap_ops[mode->pcap]->prepare_close_pcap(fd, PCAP_MODE_WRITE);
	close(fd);
}

static int begin_single_pcap_file(struct mode *mode)
{
	int fd, ret;

	if (!pcap_ops[mode->pcap])
		panic("pcap group not supported!\n");
	fd = open_or_die_m(mode->device_out,
			   O_RDWR | O_CREAT | O_TRUNC | O_LARGEFILE,
			   DEFFILEMODE);
	ret = pcap_ops[mode->pcap]->push_file_header(fd, mode->link_type);
	if (ret)
		panic("error writing pcap header!\n");
	if (pcap_ops[mode->pcap]->prepare_writing_pcap) {
		ret = pcap_ops[mode->pcap]->prepare_writing_pcap(fd);
		if (ret)
			panic("error prepare writing pcap!\n");
	}

	return fd;
}

static void enter_mode_rx_only_or_dump(struct mode *mode)
{
	int sock, irq, ifindex, fd = 0, ret;
	unsigned int size, it = 0;
	unsigned long fcnt = 0, skipped = 0;
	short ifflags = 0;
	uint8_t *packet;
	struct ring rx_ring;
	struct pollfd rx_poll;
	struct frame_map *hdr;
	struct sock_fprog bpf_ops;
	struct timeval start, end, diff;

	if (!device_up_and_running(mode->device_in))
		panic("Device not up and running!\n");

	sock = pf_socket();

	if (mode->rfraw) {
		mode->device_trans = xstrdup(mode->device_in);
		xfree(mode->device_in);

		enter_rfmon_mac80211(mode->device_trans, &mode->device_in);
		mode->link_type = LINKTYPE_IEEE802_11;
	}

	if (mode->dump) {
		struct stat tmp;
		fmemset(&tmp, 0, sizeof(tmp));
		ret = stat(mode->device_out, &tmp);
		if (ret < 0) {
			mode->dump_dir = 0;
			goto try_file;
		}
		mode->dump_dir = !!S_ISDIR(tmp.st_mode);
		if (mode->dump_dir) {
			fd = begin_multi_pcap_file(mode);
		} else {
try_file:
			fd = begin_single_pcap_file(mode);
		}
	}

	fmemset(&rx_ring, 0, sizeof(rx_ring));
	fmemset(&rx_poll, 0, sizeof(rx_poll));
	fmemset(&bpf_ops, 0, sizeof(bpf_ops));

	ifindex = device_ifindex(mode->device_in);
	size = ring_size(mode->device_in, mode->reserve_size);

	enable_kernel_bpf_jit_compiler();
	bpf_parse_rules(mode->filter, &bpf_ops);
	bpf_attach_to_sock(sock, &bpf_ops);

	set_sockopt_hwtimestamp(sock, mode->device_in);
	setup_rx_ring_layout(sock, &rx_ring, size, mode->jumbo_support);
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
	printf("MD: RX %s ", mode->dump ? pcap_ops[mode->pcap]->name : "");
	if (mode->rfraw)
		printf("802.11 raw via %s ", mode->device_in);
#ifdef _LARGEFILE64_SOURCE
	printf("lf64 ");
#endif 
	ioprio_print();
	printf("\n");

	gettimeofday(&start, NULL);

	while (likely(sigint == 0)) {
		while (user_may_pull_from_rx(rx_ring.frames[it].iov_base)) {
			hdr = rx_ring.frames[it].iov_base;
			packet = ((uint8_t *) hdr) + hdr->tp_h.tp_mac;
			fcnt++;

			if (mode->packet_type != PACKET_ALL)
				if (mode->packet_type != hdr->s_ll.sll_pkttype)
					goto next;
			if (unlikely(ring_frame_size(&rx_ring) <
				     hdr->tp_h.tp_snaplen)) {
				skipped++;
				goto next;
			}
			if (mode->dump) {
				struct pcap_pkthdr phdr;
				tpacket_hdr_to_pcap_pkthdr(&hdr->tp_h, &phdr);
				ret = pcap_ops[mode->pcap]->write_pcap_pkt(fd, &phdr,
									   packet, phdr.len);
				if (unlikely(ret != sizeof(phdr) + phdr.len))
					panic("Write error to pcap!\n");
			}

			show_frame_hdr(hdr, mode->print_mode, RING_MODE_INGRESS);
			dissector_entry_point(packet, hdr->tp_h.tp_snaplen,
					      mode->link_type, mode->print_mode);

			if (frame_cnt_max != 0 && fcnt >= frame_cnt_max) {
				sigint = 1;
				break;
			}
next:
			kernel_may_pull_from_rx(&hdr->tp_h);
			next_slot_prerd(&it, &rx_ring);

			if (unlikely(sigint == 1))
				break;
			if (mode->dump && next_dump) {
				struct tpacket_stats kstats;
				socklen_t slen = sizeof(kstats);
				fmemset(&kstats, 0, sizeof(kstats));
				getsockopt(sock, SOL_PACKET, PACKET_STATISTICS,
					   &kstats, &slen);
				fd = next_multi_pcap_file(mode, fd);
				next_dump = false;
				if (mode->print_mode == FNTTYPE_PRINT_NONE) {
					printf(".(+%lu/-%lu)",
					       1UL * kstats.tp_packets -
					       kstats.tp_drops -
					       skipped, 1UL * kstats.tp_drops +
					       skipped);
					fflush(stdout);
				}
			}
		}

		poll(&rx_poll, 1, -1);
		poll_error_maybe_die(sock, &rx_poll);
	}

	gettimeofday(&end, NULL);
	diff = tv_subtract(end, start);

	if (!(mode->dump_dir && mode->print_mode == FNTTYPE_PRINT_NONE)) {
		sock_print_net_stats(sock, skipped);
		printf("\r%12lu  sec, %lu usec in total\n", diff.tv_sec,
		       diff.tv_usec);
	} else {
		printf("\n\n");
		fflush(stdout);
	}

	bpf_release(&bpf_ops);
	dissector_cleanup_all();
	destroy_rx_ring(sock, &rx_ring);

	if (mode->promiscuous == true)
		leave_promiscuous_mode(mode->device_in, ifflags);

	if (mode->rfraw)
		leave_rfmon_mac80211(mode->device_trans, mode->device_in);

	close(sock);

	if (mode->dump) {
		if (mode->dump_dir)
			finish_multi_pcap_file(mode, fd);
		else
			finish_single_pcap_file(mode, fd);
	}
}

static void help(void)
{
	printf("\n%s %s, the packet sniffing beast\n", PROGNAME_STRING,
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Usage: netsniff-ng [options]\n");
	printf("Options:\n");
	printf("  -i|-d|--dev|--in <dev|pcap> Input source as netdev or pcap\n");
	printf("  -o|--out <dev|pcap|dir|txf> Output sink as netdev, pcap, directory, txf file\n");
	printf("  -f|--filter <bpf-file>      Use BPF filter file from bpfc\n");
	printf("  -t|--type <type>            Only handle packets of defined type:\n");
	printf("                              host|broadcast|multicast|others|outgoing\n");
	printf("  -F|--interval <uint>        Dump interval in sec if -o is a directory where\n");
	printf("                              pcap files should be stored (default: 60)\n");
	printf("  -J|--jumbo-support          Support for 64KB Super Jumbo Frames\n");
	printf("                              Default RX/TX slot: 2048Byte\n");
	printf("  -R|--rfraw                  Capture or inject raw 802.11 frames\n");
	printf("  -n|--num <uint>             Number of packets until exit\n");
	printf("  `--     0                   Loop until interrupted (default)\n");
	printf("   `-     n                   Send n packets and done\n");
	printf("Options for printing:\n");
	printf("  -s|--silent                 Do not print captured packets\n");
	printf("  -q|--less                   Print less-verbose packet information\n");
	printf("  -X|--hex                    Print packet data in hex format\n");
	printf("  -l|--ascii                  Print human-readable packet data\n");
	printf("Options, advanced:\n");
	printf("  -r|--rand                   Randomize packet forwarding order\n");
	printf("  -M|--no-promisc             No promiscuous mode for netdev\n");
	printf("  -m|--mmap                   Mmap pcap file i.e., for replaying\n");
	printf("  -g|--sg                     Scatter/gather pcap file I/O\n");
	printf("  -c|--clrw                   Use slower read(2)/write(2) I/O\n");
	printf("  -S|--ring-size <size>       Manually set ring size to <size>:\n");
	printf("                              mmap space in KB/MB/GB, e.g. \'10MB\'\n");
	printf("  -k|--kernel-pull <uint>     Kernel pull from user interval in us\n");
	printf("                              Default is 10us where the TX_RING\n");
	printf("                              is populated with payload from uspace\n");
	printf("  -b|--bind-cpu <cpu>         Bind to specific CPU (or CPU-range)\n");
	printf("  -B|--unbind-cpu <cpu>       Forbid to use specific CPU (or CPU-range)\n");
	printf("  -H|--prio-high              Make this high priority process\n");
	printf("  -Q|--notouch-irq            Do not touch IRQ CPU affinity of NIC\n");
	printf("  -v|--version                Show version\n");
	printf("  -h|--help                   Guess what?!\n");
	printf("\n");
	printf("Examples:\n");
	printf("  netsniff-ng --in eth0 --out dump.pcap --silent --bind-cpu 0\n");
	printf("  netsniff-ng --in wlan0 --rfraw --out dump.pcap --silent --bind-cpu 0\n");
	printf("  netsniff-ng --in dump.pcap --mmap --out eth0 --silent --bind-cpu 0\n");
	printf("  netsniff-ng --in dump.pcap --out dump.txf --silent --bind-cpu 0\n");
	printf("  netsniff-ng --in eth0 --out eth1 --silent --bind-cpu 0 --type host\n");
	printf("  netsniff-ng --in eth1 --out /opt/probe1/ -s -m -J --interval 30 -b 0\n");
	printf("  netsniff-ng --in any --filter http.bpf --jumbo-support --ascii\n");
	printf("\n");
	printf("Note:\n");
	printf("  This tool is targeted for network developers! You should\n");
	printf("  be aware of what you are doing and what these options above\n");
	printf("  mean! Use netsniff-ng's bpfc compiler for generating filter files.\n");
	printf("  Further, netsniff-ng automatically enables the kernel BPF JIT\n");
	printf("  if present. Txf file output is only possible if the input source\n");
	printf("  is a pcap file.\n");
	printf("\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2009-2012 Daniel Borkmann <daniel@netsniff-ng.org>\n");
	printf("Copyright (C) 2009-2012 Emmanuel Roullit <emmanuel@netsniff-ng.org>\n");
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
	printf("Copyright (C) 2009-2012 Daniel Borkmann <daniel@netsniff-ng.org>\n");
	printf("Copyright (C) 2009-2012 Emmanuel Roullit <emmanuel@netsniff-ng.org>\n");
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
	int c, i, j, opt_index, ops_touched = 0;
	char *ptr;
	bool prio_high = false;
	struct mode mode;
	void (*enter_mode)(struct mode *mode) = NULL;

	check_for_root_maybe_die();

	fmemset(&mode, 0, sizeof(mode));
	mode.link_type = LINKTYPE_EN10MB;
	mode.print_mode = FNTTYPE_PRINT_NORM;
	mode.cpu = CPU_UNKNOWN;
	mode.packet_type = PACKET_ALL;
	mode.promiscuous = true;
	mode.randomize = false;
	mode.pcap = PCAP_OPS_SG;
	mode.dump_interval = DUMP_INTERVAL;

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
		case 'R':
			mode.link_type = LINKTYPE_IEEE802_11;
			mode.rfraw = 1;
			break;
		case 'r':
			mode.randomize = true;
			break;
		case 'J':
			mode.jumbo_support = 1;
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
			ops_touched = 1;
			break;
		case 'm':
			mode.pcap = PCAP_OPS_MMAP;
			ops_touched = 1;
			break;
		case 'g':
			mode.pcap = PCAP_OPS_SG;
			ops_touched = 1;
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
		case 'X':
			mode.print_mode = (mode.print_mode == FNTTYPE_PRINT_ASCII) ?
				FNTTYPE_PRINT_HEX_ASCII : FNTTYPE_PRINT_HEX;
			break;
		case 'l':
			mode.print_mode = (mode.print_mode == FNTTYPE_PRINT_HEX) ?
				FNTTYPE_PRINT_HEX_ASCII : FNTTYPE_PRINT_ASCII;
			break;
		case 'k':
			mode.kpull = (unsigned long) atol(optarg);
			break;
		case 'n':
			frame_cnt_max = (unsigned long) atol(optarg);
			break;
		case 'F':
			mode.dump_interval = (unsigned long) atol(optarg);
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
			case 'F':
			case 'n':
			case 'S':
			case 'b':
			case 'k':
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

	init_pcap(mode.jumbo_support);
	tprintf_init();
	header();

	if (prio_high == true) {
		set_proc_prio(get_default_proc_prio());
		set_sched_status(get_default_sched_policy(),
				 get_default_sched_prio());
	}

	if (mode.device_in && (device_mtu(mode.device_in) ||
	    !strncmp("any", mode.device_in, strlen(mode.device_in)))) {
		if (!mode.device_out) {
			mode.dump = 0;
			enter_mode = enter_mode_rx_only_or_dump;
		} else if (device_mtu(mode.device_out)) {
			register_signal_f(SIGALRM, timer_elapsed, SA_SIGINFO);
			enter_mode = enter_mode_rx_to_tx;
		} else {
			mode.dump = 1;
			register_signal_f(SIGALRM, timer_next_dump, SA_SIGINFO);
			enter_mode = enter_mode_rx_only_or_dump;
			if (!ops_touched)
				mode.pcap = PCAP_OPS_SG;
		}
	} else {
		if (mode.device_out && device_mtu(mode.device_out)) {
			register_signal_f(SIGALRM, timer_elapsed, SA_SIGINFO);
			enter_mode = enter_mode_pcap_to_tx;
			if (!ops_touched)
				mode.pcap = PCAP_OPS_MMAP;
		} else {
			enter_mode = enter_mode_read_pcap;
			if (!ops_touched)
				mode.pcap = PCAP_OPS_SG;
		}
	}

	if (!enter_mode)
		panic("Selection not supported!\n");
	enter_mode(&mode);

	tprintf_cleanup();
	cleanup_pcap();

	if (mode.device_in)
		xfree(mode.device_in);
	if (mode.device_out)
		xfree(mode.device_out);
	if (mode.device_trans)
		xfree(mode.device_trans);

	return 0;
}

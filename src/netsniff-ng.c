/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009-2013 Daniel Borkmann.
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
#include <sys/fsuid.h>
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

enum dump_mode {
	DUMP_INTERVAL_TIME,
	DUMP_INTERVAL_SIZE,
};

struct ctx {
	char *device_in, *device_out, *device_trans, *filter, *prefix;
	int cpu, rfraw, dump, print_mode, dump_dir, jumbo_support, packet_type, verbose;
	unsigned long kpull, dump_interval, reserve_size, tx_bytes, tx_packets;
	bool randomize, promiscuous;
	enum pcap_ops_groups pcap;
	enum dump_mode dump_mode;
	uint32_t link_type;
};

volatile sig_atomic_t sigint = 0;

static volatile bool next_dump = false;

static const char *short_options = "d:i:o:rf:MJt:S:k:n:b:B:HQmcsqXlvhF:RgAP:V";
static const struct option long_options[] = {
	{"dev",			required_argument,	NULL, 'd'},
	{"in",			required_argument,	NULL, 'i'},
	{"out",			required_argument,	NULL, 'o'},
	{"filter",		required_argument,	NULL, 'f'},
	{"num",			required_argument,	NULL, 'n'},
	{"type",		required_argument,	NULL, 't'},
	{"interval",		required_argument,	NULL, 'F'},
	{"ring-size",		required_argument,	NULL, 'S'},
	{"kernel-pull",		required_argument,	NULL, 'k'},
	{"bind-cpu",		required_argument,	NULL, 'b'},
	{"unbind-cpu",		required_argument,	NULL, 'B'},
	{"prefix",		required_argument,	NULL, 'P'},
	{"rand",		no_argument,		NULL, 'r'},
	{"rfraw",		no_argument,		NULL, 'R'},
	{"mmap",		no_argument,		NULL, 'm'},
	{"sg",			no_argument,		NULL, 'g'},
	{"clrw",		no_argument,		NULL, 'c'},
	{"jumbo-support",	no_argument,		NULL, 'J'},
	{"no-promisc",		no_argument,		NULL, 'M'},
	{"prio-high",		no_argument,		NULL, 'H'},
	{"notouch-irq",		no_argument,		NULL, 'Q'},
	{"silent",		no_argument,		NULL, 's'},
	{"less",		no_argument,		NULL, 'q'},
	{"hex",			no_argument,		NULL, 'X'},
	{"ascii",		no_argument,		NULL, 'l'},
	{"no-sock-mem",		no_argument,		NULL, 'A'},
	{"verbose",		no_argument,		NULL, 'V'},
	{"version",		no_argument,		NULL, 'v'},
	{"help",		no_argument,		NULL, 'h'},
	{NULL, 0, NULL, 0}
};

static int tx_sock;

static struct itimerval itimer;

static unsigned long frame_count_max = 0, interval = TX_KERNEL_PULL_INT;

#define set_system_socket_memory(vals) \
	do { \
		if ((vals[0] = get_system_socket_mem(sock_rmem_max)) < SMEM_SUG_MAX) \
			set_system_socket_mem(sock_rmem_max, SMEM_SUG_MAX); \
		if ((vals[1] = get_system_socket_mem(sock_rmem_def)) < SMEM_SUG_DEF) \
			set_system_socket_mem(sock_rmem_def, SMEM_SUG_DEF); \
		if ((vals[2] = get_system_socket_mem(sock_wmem_max)) < SMEM_SUG_MAX) \
			set_system_socket_mem(sock_wmem_max, SMEM_SUG_MAX); \
		if ((vals[3] = get_system_socket_mem(sock_wmem_def)) < SMEM_SUG_DEF) \
			set_system_socket_mem(sock_wmem_def, SMEM_SUG_DEF); \
	} while (0)

#define reset_system_socket_memory(vals) \
	do { \
		set_system_socket_mem(sock_rmem_max, vals[0]); \
		set_system_socket_mem(sock_rmem_def, vals[1]); \
		set_system_socket_mem(sock_wmem_max, vals[2]); \
		set_system_socket_mem(sock_wmem_def, vals[3]); \
	} while (0)

#define __pcap_io		pcap_ops[ctx->pcap]

static void signal_handler(int number)
{
	switch (number) {
	case SIGINT:
		sigint = 1;
	case SIGHUP:
	default:
		break;
	}
}

static void timer_elapsed(int unused)
{
	itimer.it_interval.tv_sec = 0;
	itimer.it_interval.tv_usec = interval;

	itimer.it_value.tv_sec = 0;
	itimer.it_value.tv_usec = interval;

	pull_and_flush_tx_ring(tx_sock);
	setitimer(ITIMER_REAL, &itimer, NULL);
}

static void timer_next_dump(int unused)
{
	itimer.it_interval.tv_sec = interval;
	itimer.it_interval.tv_usec = 0;

	itimer.it_value.tv_sec = interval;
	itimer.it_value.tv_usec = 0;

	next_dump = true;
	setitimer(ITIMER_REAL, &itimer, NULL);
}

static inline bool dump_to_pcap(struct ctx *ctx)
{
	return ctx->dump;
}

static void pcap_to_xmit(struct ctx *ctx)
{
	__label__ out;
	uint8_t *out = NULL;
	int irq, ifindex, fd = 0, ret;
	unsigned int size, it = 0;
	unsigned long trunced = 0;
	struct ring tx_ring;
	struct frame_map *hdr;
	struct sock_fprog bpf_ops;
	struct timeval start, end, diff;
	struct pcap_pkthdr phdr;

	if (!device_up_and_running(ctx->device_out) && !ctx->rfraw)
		panic("Device not up and running!\n");

	bug_on(!__pcap_io);

	tx_sock = pf_socket();

	fd = open_or_die(ctx->device_in, O_RDONLY | O_LARGEFILE | O_NOATIME);

	ret = __pcap_io->pull_file_header(fd, &ctx->link_type);
	if (ret)
		panic("Error reading pcap header!\n");

	if (__pcap_io->prepare_reading_pcap) {
		ret = __pcap_io->prepare_reading_pcap(fd);
		if (ret)
			panic("Error prepare reading pcap!\n");
	}

	fmemset(&tx_ring, 0, sizeof(tx_ring));
	fmemset(&bpf_ops, 0, sizeof(bpf_ops));

	if (ctx->rfraw) {
		ctx->device_trans = xstrdup(ctx->device_out);
		xfree(ctx->device_out);

		enter_rfmon_mac80211(ctx->device_trans, &ctx->device_out);
		if (ctx->link_type != LINKTYPE_IEEE802_11)
			panic("Wrong linktype of pcap!\n");
	}

	ifindex = device_ifindex(ctx->device_out);

	size = ring_size(ctx->device_out, ctx->reserve_size);

	bpf_parse_rules(ctx->filter, &bpf_ops);

	set_packet_loss_discard(tx_sock);
	set_sockopt_hwtimestamp(tx_sock, ctx->device_out);

	setup_tx_ring_layout(tx_sock, &tx_ring, size, ctx->jumbo_support);
	create_tx_ring(tx_sock, &tx_ring, ctx->verbose);
	mmap_tx_ring(tx_sock, &tx_ring);
	alloc_tx_ring_frames(&tx_ring);
	bind_tx_ring(tx_sock, &tx_ring, ifindex);

	dissector_init_all(ctx->print_mode);

	if (ctx->cpu >= 0 && ifindex > 0) {
		irq = device_irq_number(ctx->device_out);
		device_bind_irq_to_cpu(irq, ctx->cpu);

		if (ctx->verbose)
			printf("IRQ: %s:%d > CPU%d\n",
			       ctx->device_out, irq, ctx->cpu);
	}

	if (ctx->kpull)
		interval = ctx->kpull;

	if (ctx->verbose) {
		printf("BPF:\n");
		bpf_dump_all(&bpf_ops);

		printf("MD: TX %luus %s ", interval, pcap_ops[ctx->pcap]->name);
		if (ctx->rfraw)
			printf("802.11 raw via %s ", ctx->device_out);
#ifdef _LARGEFILE64_SOURCE
		printf("lf64 ");
#endif 
		ioprio_print();
		printf("\n");
	}
	printf("Running! Hang up with ^C!\n\n");
	fflush(stdout);

	itimer.it_interval.tv_sec = 0;
	itimer.it_interval.tv_usec = interval;

	itimer.it_value.tv_sec = 0;
	itimer.it_value.tv_usec = interval;

	setitimer(ITIMER_REAL, &itimer, NULL); 

	bug_on(gettimeofday(&start, NULL));

	while (likely(sigint == 0)) {
		while (user_may_pull_from_tx(tx_ring.frames[it].iov_base)) {
			hdr = tx_ring.frames[it].iov_base;

			/* Kernel assumes: data = ph.raw + po->tp_hdrlen -
			 *                        sizeof(struct sockaddr_ll); */
			out = ((uint8_t *) hdr) + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll);

			do {
				ret = __pcap_io->read_pcap_pkt(fd, &phdr, out,
							       ring_frame_size(&tx_ring));
				if (unlikely(ret <= 0))
					goto out;

				if (ring_frame_size(&tx_ring) < phdr.len) {
					phdr.len = ring_frame_size(&tx_ring);
					trunced++;
				}
			} while (ctx->filter && !bpf_run_filter(&bpf_ops, out, phdr.len));

			pcap_pkthdr_to_tpacket_hdr(&phdr, &hdr->tp_h);

			ctx->tx_bytes += hdr->tp_h.tp_len;;
			ctx->tx_packets++;

			show_frame_hdr(hdr, ctx->print_mode, RING_MODE_EGRESS);

			dissector_entry_point(out, hdr->tp_h.tp_snaplen,
					      ctx->link_type, ctx->print_mode);

			kernel_may_pull_from_tx(&hdr->tp_h);

			it++;
			if (it >= tx_ring.layout.tp_frame_nr)
				it = 0;

			if (unlikely(sigint == 1))
				break;

			if (frame_count_max != 0) {
				if (ctx->tx_packets >= frame_count_max) {
					sigint = 1;
					break;
				}
			}
		}
	}

	out:

	bug_on(gettimeofday(&end, NULL));
	diff = tv_subtract(end, start);

	bpf_release(&bpf_ops);

	dissector_cleanup_all();
	destroy_tx_ring(tx_sock, &tx_ring);

	if (ctx->rfraw)
		leave_rfmon_mac80211(ctx->device_trans, ctx->device_out);

	if (__pcap_io->prepare_close_pcap)
		__pcap_io->prepare_close_pcap(fd, PCAP_MODE_READ);

	close(fd);
	close(tx_sock);

	fflush(stdout);
	printf("\n");
	printf("\r%12lu packets outgoing\n", ctx->tx_packets);
	printf("\r%12lu packets truncated in file\n", trunced);
	printf("\r%12lu bytes outgoing\n", ctx->tx_bytes);
	printf("\r%12lu sec, %lu usec in total\n", diff.tv_sec, diff.tv_usec);
}

static void receive_to_xmit(struct ctx *ctx)
{
	short ifflags = 0;
	uint8_t *in, *out;
	int rx_sock, ifindex_in, ifindex_out;
	unsigned int size_in, size_out, it_in = 0, it_out = 0;
	unsigned long frame_count = 0;
	struct frame_map *hdr_in, *hdr_out;
	struct ring tx_ring, rx_ring;
	struct pollfd rx_poll;
	struct sock_fprog bpf_ops;

	if (!strncmp(ctx->device_in, ctx->device_out, IFNAMSIZ))
		panic("Ingress/egress devices must be different!\n");
	if (!device_up_and_running(ctx->device_out))
		panic("Egress device not up and running!\n");
	if (!device_up_and_running(ctx->device_in))
		panic("Ingress device not up and running!\n");

	rx_sock = pf_socket();
	tx_sock = pf_socket();

	fmemset(&tx_ring, 0, sizeof(tx_ring));
	fmemset(&rx_ring, 0, sizeof(rx_ring));
	fmemset(&rx_poll, 0, sizeof(rx_poll));
	fmemset(&bpf_ops, 0, sizeof(bpf_ops));

	ifindex_in = device_ifindex(ctx->device_in);
	ifindex_out = device_ifindex(ctx->device_out);

	size_in = ring_size(ctx->device_in, ctx->reserve_size);
	size_out = ring_size(ctx->device_out, ctx->reserve_size);

	enable_kernel_bpf_jit_compiler();

	bpf_parse_rules(ctx->filter, &bpf_ops);
	bpf_attach_to_sock(rx_sock, &bpf_ops);

	setup_rx_ring_layout(rx_sock, &rx_ring, size_in, ctx->jumbo_support);
	create_rx_ring(rx_sock, &rx_ring, ctx->verbose);
	mmap_rx_ring(rx_sock, &rx_ring);
	alloc_rx_ring_frames(&rx_ring);
	bind_rx_ring(rx_sock, &rx_ring, ifindex_in);
	prepare_polling(rx_sock, &rx_poll);

	set_packet_loss_discard(tx_sock);
	setup_tx_ring_layout(tx_sock, &tx_ring, size_out, ctx->jumbo_support);
	create_tx_ring(tx_sock, &tx_ring, ctx->verbose);
	mmap_tx_ring(tx_sock, &tx_ring);
	alloc_tx_ring_frames(&tx_ring);
	bind_tx_ring(tx_sock, &tx_ring, ifindex_out);

	dissector_init_all(ctx->print_mode);

	 if (ctx->promiscuous)
		ifflags = enter_promiscuous_mode(ctx->device_in);

	if (ctx->kpull)
		interval = ctx->kpull;

	itimer.it_interval.tv_sec = 0;
	itimer.it_interval.tv_usec = interval;

	itimer.it_value.tv_sec = 0;
	itimer.it_value.tv_usec = interval;

	setitimer(ITIMER_REAL, &itimer, NULL);

	if (ctx->verbose) {
		printf("BPF:\n");
		bpf_dump_all(&bpf_ops);

		printf("MD: RXTX %luus\n\n", interval);
	}
	printf("Running! Hang up with ^C!\n\n");
	fflush(stdout);

	while (likely(sigint == 0)) {
		while (user_may_pull_from_rx(rx_ring.frames[it_in].iov_base)) {
			__label__ next;

			hdr_in = rx_ring.frames[it_in].iov_base;
			in = ((uint8_t *) hdr_in) + hdr_in->tp_h.tp_mac;

			frame_count++;

			if (ctx->packet_type != -1)
				if (ctx->packet_type != hdr_in->s_ll.sll_pkttype)
					goto next;

			hdr_out = tx_ring.frames[it_out].iov_base;
			out = ((uint8_t *) hdr_out) + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll);

			for (; !user_may_pull_from_tx(tx_ring.frames[it_out].iov_base) &&
			       likely(!sigint);) {
				if (ctx->randomize)
					next_rnd_slot(&it_out, &tx_ring);
				else {
					it_out++;
					if (it_out >= tx_ring.layout.tp_frame_nr)
						it_out = 0;
				}

				hdr_out = tx_ring.frames[it_out].iov_base;
				out = ((uint8_t *) hdr_out) + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll);
			}

			tpacket_hdr_clone(&hdr_out->tp_h, &hdr_in->tp_h);
			fmemcpy(out, in, hdr_in->tp_h.tp_len);

			kernel_may_pull_from_tx(&hdr_out->tp_h);
			if (ctx->randomize)
				next_rnd_slot(&it_out, &tx_ring);
			else {
				it_out++;
				if (it_out >= tx_ring.layout.tp_frame_nr)
					it_out = 0;
			}

			show_frame_hdr(hdr_in, ctx->print_mode, RING_MODE_INGRESS);

			dissector_entry_point(in, hdr_in->tp_h.tp_snaplen,
					      ctx->link_type, ctx->print_mode);

			if (frame_count_max != 0) {
				if (frame_count >= frame_count_max) {
					sigint = 1;
					break;
				}
			}

			next:

			kernel_may_pull_from_rx(&hdr_in->tp_h);

			it_in++;
			if (it_in >= rx_ring.layout.tp_frame_nr)
				it_in = 0;

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

	if (ctx->promiscuous)
		leave_promiscuous_mode(ctx->device_in, ifflags);

	close(tx_sock);
	close(rx_sock);
}

static void translate_pcap_to_txf(int fdo, uint8_t *out, size_t len)
{
	size_t bytes_done = 0;
	char bout[80];

	slprintf(bout, sizeof(bout), "{\n  ");
	write_or_die(fdo, bout, strlen(bout));

	while (bytes_done < len) {
		slprintf(bout, sizeof(bout), "0x%02x, ", out[bytes_done]);
		write_or_die(fdo, bout, strlen(bout));

		bytes_done++;

		if (bytes_done % 10 == 0) {
			slprintf(bout, sizeof(bout), "\n");
			write_or_die(fdo, bout, strlen(bout));

			if (bytes_done < len) {
				slprintf(bout, sizeof(bout), "  ");
				write_or_die(fdo, bout, strlen(bout));
			}
		}
	}
	if (bytes_done % 10 != 0) {
		slprintf(bout, sizeof(bout), "\n");
		write_or_die(fdo, bout, strlen(bout));
	}

	slprintf(bout, sizeof(bout), "}\n\n");
	write_or_die(fdo, bout, strlen(bout));
}

static void read_pcap(struct ctx *ctx)
{
	__label__ out;
	uint8_t *out;
	int ret, fd, fdo = 0;
	unsigned long trunced = 0;
	size_t out_len;
	struct pcap_pkthdr phdr;
	struct sock_fprog bpf_ops;
	struct frame_map fm;
	struct timeval start, end, diff;

	bug_on(!__pcap_io);

	fd = open_or_die(ctx->device_in, O_RDONLY | O_LARGEFILE | O_NOATIME);

	ret = __pcap_io->pull_file_header(fd, &ctx->link_type);
	if (ret)
		panic("Error reading pcap header!\n");

	if (__pcap_io->prepare_reading_pcap) {
		ret = __pcap_io->prepare_reading_pcap(fd);
		if (ret)
			panic("Error prepare reading pcap!\n");
	}

	fmemset(&fm, 0, sizeof(fm));
	fmemset(&bpf_ops, 0, sizeof(bpf_ops));

	bpf_parse_rules(ctx->filter, &bpf_ops);

	dissector_init_all(ctx->print_mode);

	out_len = round_up(1024 * 1024, PAGE_SIZE);
	out = xmalloc_aligned(out_len, CO_CACHE_LINE_SIZE);

	if (ctx->verbose) {
		printf("BPF:\n");
		bpf_dump_all(&bpf_ops);

		printf("MD: RD %s ", __pcap_io->name);
#ifdef _LARGEFILE64_SOURCE
		printf("lf64 ");
#endif 
		ioprio_print();
		printf("\n");
	}
	printf("Running! Hang up with ^C!\n\n");
	fflush(stdout);

	if (ctx->device_out)
		fdo = open_or_die_m(ctx->device_out, O_RDWR | O_CREAT |
				    O_TRUNC | O_LARGEFILE, DEFFILEMODE);

	bug_on(gettimeofday(&start, NULL));

	while (likely(sigint == 0)) {
		do {
			ret = __pcap_io->read_pcap_pkt(fd, &phdr, out, out_len);
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
		} while (ctx->filter && !bpf_run_filter(&bpf_ops, out, phdr.len));

		pcap_pkthdr_to_tpacket_hdr(&phdr, &fm.tp_h);

		ctx->tx_bytes += fm.tp_h.tp_len;
		ctx->tx_packets++;

		show_frame_hdr(&fm, ctx->print_mode, RING_MODE_EGRESS);

		dissector_entry_point(out, fm.tp_h.tp_snaplen,
				      ctx->link_type, ctx->print_mode);

		if (ctx->device_out)
			translate_pcap_to_txf(fdo, out, fm.tp_h.tp_snaplen);

		if (frame_count_max != 0) {
			if (ctx->tx_packets >= frame_count_max) {
				sigint = 1;
				break;
			}
		}
	}

	out:

	bug_on(gettimeofday(&end, NULL));
	diff = tv_subtract(end, start);

	bpf_release(&bpf_ops);

	dissector_cleanup_all();

	if (__pcap_io->prepare_close_pcap)
		__pcap_io->prepare_close_pcap(fd, PCAP_MODE_READ);

	close(fd);
	if (ctx->device_out)
		close(fdo);

	xfree(out);

	fflush(stdout);
	printf("\n");
	printf("\r%12lu packets outgoing\n", ctx->tx_packets);
	printf("\r%12lu packets truncated in file\n", trunced);
	printf("\r%12lu bytes outgoing\n", ctx->tx_bytes);
	printf("\r%12lu sec, %lu usec in total\n", diff.tv_sec, diff.tv_usec);
}

static void finish_multi_pcap_file(struct ctx *ctx, int fd)
{
	__pcap_io->fsync_pcap(fd);

	if (__pcap_io->prepare_close_pcap)
		__pcap_io->prepare_close_pcap(fd, PCAP_MODE_WRITE);

	close(fd);

	fmemset(&itimer, 0, sizeof(itimer));
	setitimer(ITIMER_REAL, &itimer, NULL);
}

static int next_multi_pcap_file(struct ctx *ctx, int fd)
{
	int ret;
	char fname[512];

	__pcap_io->fsync_pcap(fd);

	if (__pcap_io->prepare_close_pcap)
		__pcap_io->prepare_close_pcap(fd, PCAP_MODE_WRITE);

	close(fd);

	slprintf(fname, sizeof(fname), "%s/%s%lu.pcap", ctx->device_out,
		 ctx->prefix ? : "dump-", time(0));

	fd = open_or_die_m(fname, O_RDWR | O_CREAT | O_TRUNC |
			   O_LARGEFILE, DEFFILEMODE);

	ret = __pcap_io->push_file_header(fd, ctx->link_type);
	if (ret)
		panic("Error writing pcap header!\n");

	if (__pcap_io->prepare_writing_pcap) {
		ret = __pcap_io->prepare_writing_pcap(fd);
		if (ret)
			panic("Error prepare writing pcap!\n");
	}

	return fd;
}

static int begin_multi_pcap_file(struct ctx *ctx)
{
	int fd, ret;
	char fname[256];

	bug_on(!__pcap_io);

	if (ctx->device_out[strlen(ctx->device_out) - 1] == '/')
		ctx->device_out[strlen(ctx->device_out) - 1] = 0;

	slprintf(fname, sizeof(fname), "%s/%s%lu.pcap", ctx->device_out,
		 ctx->prefix ? : "dump-", time(0));

	fd = open_or_die_m(fname, O_RDWR | O_CREAT | O_TRUNC |
			   O_LARGEFILE, DEFFILEMODE);

	ret = __pcap_io->push_file_header(fd, ctx->link_type);
	if (ret)
		panic("Error writing pcap header!\n");

	if (__pcap_io->prepare_writing_pcap) {
		ret = __pcap_io->prepare_writing_pcap(fd);
		if (ret)
			panic("Error prepare writing pcap!\n");
	}

	if (ctx->dump_mode == DUMP_INTERVAL_TIME) {
		interval = ctx->dump_interval;

		itimer.it_interval.tv_sec = interval;
		itimer.it_interval.tv_usec = 0;

		itimer.it_value.tv_sec = interval;
		itimer.it_value.tv_usec = 0;

		setitimer(ITIMER_REAL, &itimer, NULL);
	} else {
		interval = 0;
	}

	return fd;
}

static void finish_single_pcap_file(struct ctx *ctx, int fd)
{
	__pcap_io->fsync_pcap(fd);

	if (__pcap_io->prepare_close_pcap)
		__pcap_io->prepare_close_pcap(fd, PCAP_MODE_WRITE);

	close(fd);
}

static int begin_single_pcap_file(struct ctx *ctx)
{
	int fd, ret;

	bug_on(!__pcap_io);

	fd = open_or_die_m(ctx->device_out, O_RDWR | O_CREAT | O_TRUNC |
			   O_LARGEFILE, DEFFILEMODE);

	ret = __pcap_io->push_file_header(fd, ctx->link_type);
	if (ret)
		panic("Error writing pcap header!\n");

	if (__pcap_io->prepare_writing_pcap) {
		ret = __pcap_io->prepare_writing_pcap(fd);
		if (ret)
			panic("Error prepare writing pcap!\n");
	}

	return fd;
}

static void print_pcap_file_stats(int sock, struct ctx *ctx, unsigned long skipped)
{
	unsigned long good, bad;
	struct tpacket_stats kstats;
	socklen_t slen = sizeof(kstats);

	fmemset(&kstats, 0, sizeof(kstats));
	getsockopt(sock, SOL_PACKET, PACKET_STATISTICS, &kstats, &slen);
	
	if (ctx->print_mode == PRINT_NONE) {
		good = kstats.tp_packets - kstats.tp_drops - skipped;
		bad = kstats.tp_drops + skipped;

		printf(".(+%lu/-%lu)", good, bad);
		fflush(stdout);
	}
}

static void recv_only_or_dump(struct ctx *ctx)
{
	uint8_t *packet;
	short ifflags = 0;
	int sock, irq, ifindex, fd = 0, ret;
	unsigned int size, it = 0;
	unsigned long frame_count = 0, skipped = 0;
	struct ring rx_ring;
	struct pollfd rx_poll;
	struct frame_map *hdr;
	struct sock_fprog bpf_ops;
	struct timeval start, end, diff;
	struct pcap_pkthdr phdr;

	if (!device_up_and_running(ctx->device_in) && !ctx->rfraw)
		panic("Device not up and running!\n");

	sock = pf_socket();

	if (ctx->rfraw) {
		ctx->device_trans = xstrdup(ctx->device_in);
		xfree(ctx->device_in);

		enter_rfmon_mac80211(ctx->device_trans, &ctx->device_in);
		ctx->link_type = LINKTYPE_IEEE802_11;
	}

	if (dump_to_pcap(ctx)) {
		__label__ try_file;
		struct stat stats;

		fmemset(&stats, 0, sizeof(stats));
		ret = stat(ctx->device_out, &stats);
		if (ret < 0) {
			ctx->dump_dir = 0;
			goto try_file;
		}

		ctx->dump_dir = S_ISDIR(stats.st_mode);
		if (ctx->dump_dir) {
			fd = begin_multi_pcap_file(ctx);
		} else {
		try_file:
			fd = begin_single_pcap_file(ctx);
		}
	}

	fmemset(&rx_ring, 0, sizeof(rx_ring));
	fmemset(&rx_poll, 0, sizeof(rx_poll));
	fmemset(&bpf_ops, 0, sizeof(bpf_ops));

	ifindex = device_ifindex(ctx->device_in);

	size = ring_size(ctx->device_in, ctx->reserve_size);

	enable_kernel_bpf_jit_compiler();

	bpf_parse_rules(ctx->filter, &bpf_ops);
	bpf_attach_to_sock(sock, &bpf_ops);

	set_sockopt_hwtimestamp(sock, ctx->device_in);

	setup_rx_ring_layout(sock, &rx_ring, size, ctx->jumbo_support);
	create_rx_ring(sock, &rx_ring, ctx->verbose);
	mmap_rx_ring(sock, &rx_ring);
	alloc_rx_ring_frames(&rx_ring);
	bind_rx_ring(sock, &rx_ring, ifindex);

	prepare_polling(sock, &rx_poll);
	dissector_init_all(ctx->print_mode);

	if (ctx->cpu >= 0 && ifindex > 0) {
		irq = device_irq_number(ctx->device_in);
		device_bind_irq_to_cpu(irq, ctx->cpu);

		if (ctx->verbose)
			printf("IRQ: %s:%d > CPU%d\n",
			       ctx->device_in, irq, ctx->cpu);
	}

	if (ctx->promiscuous)
		ifflags = enter_promiscuous_mode(ctx->device_in);

	if (ctx->verbose) {
		printf("BPF:\n");
		bpf_dump_all(&bpf_ops);

		printf("MD: RX %s ", ctx->dump ? pcap_ops[ctx->pcap]->name : "");
		if (ctx->rfraw)
			printf("802.11 raw via %s ", ctx->device_in);
#ifdef _LARGEFILE64_SOURCE
		printf("lf64 ");
#endif 
		ioprio_print();
		printf("\n");
	}
	printf("Running! Hang up with ^C!\n\n");
	fflush(stdout);

	bug_on(gettimeofday(&start, NULL));

	while (likely(sigint == 0)) {
		while (user_may_pull_from_rx(rx_ring.frames[it].iov_base)) {
			__label__ next;

			hdr = rx_ring.frames[it].iov_base;
			packet = ((uint8_t *) hdr) + hdr->tp_h.tp_mac;
			frame_count++;

			if (ctx->packet_type != -1)
				if (ctx->packet_type != hdr->s_ll.sll_pkttype)
					goto next;

			if (unlikely(ring_frame_size(&rx_ring) < hdr->tp_h.tp_snaplen)) {
				skipped++;
				goto next;
			}

			if (dump_to_pcap(ctx)) {
				tpacket_hdr_to_pcap_pkthdr(&hdr->tp_h, &phdr);

				ret = __pcap_io->write_pcap_pkt(fd, &phdr, packet, phdr.len);
				if (unlikely(ret != sizeof(phdr) + phdr.len))
					panic("Write error to pcap!\n");
			}

			show_frame_hdr(hdr, ctx->print_mode, RING_MODE_INGRESS);

			dissector_entry_point(packet, hdr->tp_h.tp_snaplen,
					      ctx->link_type, ctx->print_mode);

			if (frame_count_max != 0) {
				if (frame_count >= frame_count_max) {
					sigint = 1;
					break;
				}
			}

			next:

			kernel_may_pull_from_rx(&hdr->tp_h);

			it++;
			if (it >= rx_ring.layout.tp_frame_nr)
				it = 0;

			if (unlikely(sigint == 1))
				break;

			if (dump_to_pcap(ctx)) {
				if (ctx->dump_mode == DUMP_INTERVAL_SIZE) {
					interval += hdr->tp_h.tp_snaplen;

					if (interval > ctx->dump_interval) {
						next_dump = true;
						interval = 0;
					}
				}

				if (next_dump) {
					fd = next_multi_pcap_file(ctx, fd);
					next_dump = false;

					if (ctx->verbose)
						print_pcap_file_stats(sock, ctx, skipped);
				}
			}
		}

		poll(&rx_poll, 1, -1);
		poll_error_maybe_die(sock, &rx_poll);
	}

	bug_on(gettimeofday(&end, NULL));
	diff = tv_subtract(end, start);

	if (!(ctx->dump_dir && ctx->print_mode == PRINT_NONE)) {
		sock_print_net_stats(sock, skipped);

		printf("\r%12lu  sec, %lu usec in total\n",
		       diff.tv_sec, diff.tv_usec);
	} else {
		printf("\n\n");
		fflush(stdout);
	}

	bpf_release(&bpf_ops);
	dissector_cleanup_all();
	destroy_rx_ring(sock, &rx_ring);

	if (ctx->promiscuous)
		leave_promiscuous_mode(ctx->device_in, ifflags);

	if (ctx->rfraw)
		leave_rfmon_mac80211(ctx->device_trans, ctx->device_in);

	close(sock);

	if (dump_to_pcap(ctx)) {
		if (ctx->dump_dir)
			finish_multi_pcap_file(ctx, fd);
		else
			finish_single_pcap_file(ctx, fd);
	}
}

static void help(void)
{
	printf("\nnetsniff-ng %s, the packet sniffing beast\n", VERSION_STRING);
	puts("http://www.netsniff-ng.org\n\n"
	     "Usage: netsniff-ng [options]\n"
	     "Options:\n"
	     "  -i|-d|--dev|--in <dev|pcap> Input source as netdev or pcap\n"
	     "  -o|--out <dev|pcap|dir|txf> Output sink as netdev, pcap, directory, txf file\n"
	     "  -f|--filter <bpf-file>      Use BPF filter file from bpfc\n"
	     "  -t|--type <type>            Only handle packets of defined type:\n"
	     "                              host|broadcast|multicast|others|outgoing\n"
	     "  -F|--interval <size/time>   Dump interval in time or size if -o is a directory\n"
	     "                              pcap swap spec: <num>KiB/MiB/GiB/s/sec/min/hrs\n"
	     "  -J|--jumbo-support          Support for 64KB Super Jumbo Frames\n"
	     "                              Default RX/TX slot: 2048Byte\n"
	     "  -R|--rfraw                  Capture or inject raw 802.11 frames\n"
	     "  -n|--num <uint>             Number of packets until exit\n"
	     "  `--     0                   Loop until interrupted (default)\n"
	     "   `-     n                   Send n packets and done\n"
	     "Options for printing:\n"
	     "  -s|--silent                 Do not print captured packets\n"
	     "  -q|--less                   Print less-verbose packet information\n"
	     "  -X|--hex                    Print packet data in hex format\n"
	     "  -l|--ascii                  Print human-readable packet data\n"
	     "Options, advanced:\n"
	     "  -P|--prefix <name>          Prefix for pcaps stored in directory\n"
	     "  -r|--rand                   Randomize packet forwarding order\n"
	     "  -M|--no-promisc             No promiscuous mode for netdev\n"
	     "  -A|--no-sock-mem            Don't tune core socket memory\n"
	     "  -m|--mmap                   Mmap pcap file i.e., for replaying\n"
	     "  -g|--sg                     Scatter/gather pcap file I/O\n"
	     "  -c|--clrw                   Use slower read(2)/write(2) I/O\n"
	     "  -S|--ring-size <size>       Manually set ring size to <size>:\n"
	     "                              mmap space in KiB/MiB/GiB, e.g. \'10MiB\'\n"
	     "  -k|--kernel-pull <uint>     Kernel pull from user interval in us\n"
	     "                              Default is 10us where the TX_RING\n"
	     "                              is populated with payload from uspace\n"
	     "  -b|--bind-cpu <cpu>         Bind to specific CPU (or CPU-range)\n"
	     "  -B|--unbind-cpu <cpu>       Forbid to use specific CPU (or CPU-range)\n"
	     "  -H|--prio-high              Make this high priority process\n"
	     "  -Q|--notouch-irq            Do not touch IRQ CPU affinity of NIC\n"
	     "  -V|--verbose                Be more verbose\n"
	     "  -v|--version                Show version\n"
	     "  -h|--help                   Guess what?!\n\n"
	     "Examples:\n"
	     "  netsniff-ng --in eth0 --out dump.pcap --silent --bind-cpu 0\n"
	     "  netsniff-ng --in wlan0 --rfraw --out dump.pcap --silent --bind-cpu 0\n"
	     "  netsniff-ng --in dump.pcap --mmap --out eth0 -k1000 --silent --bind-cpu 0\n"
	     "  netsniff-ng --in dump.pcap --out dump.txf --silent --bind-cpu 0\n"
	     "  netsniff-ng --in eth0 --out eth1 --silent --bind-cpu 0 --type host\n"
	     "  netsniff-ng --in eth1 --out /opt/probe/ -s -m -J --interval 100MiB -b 0\n"
	     "  netsniff-ng --in any --filter http.bpf --jumbo-support --ascii -V\n\n"
	     "Note:\n"
	     "  This tool is targeted for network developers! You should\n"
	     "  be aware of what you are doing and what these options above\n"
	     "  mean! Use netsniff-ng's bpfc compiler for generating filter files.\n"
	     "  Further, netsniff-ng automatically enables the kernel BPF JIT\n"
	     "  if present. Txf file output is only possible if the input source\n"
	     "  is a pcap file.\n\n"
	     "Please report bugs to <bugs@netsniff-ng.org>\n"
	     "Copyright (C) 2009-2013 Daniel Borkmann <daniel@netsniff-ng.org>\n"
	     "Copyright (C) 2009-2012 Emmanuel Roullit <emmanuel@netsniff-ng.org>\n"
	     "Copyright (C) 2012      Markus Amend <markus@netsniff-ng.org>\n"
	     "License: GNU GPL version 2.0\n"
	     "This is free software: you are free to change and redistribute it.\n"
	     "There is NO WARRANTY, to the extent permitted by law.\n");
	die();
}

static void version(void)
{
	printf("\nnetsniff-ng %s, the packet sniffing beast\n", VERSION_STRING);
	puts("http://www.netsniff-ng.org\n\n"
	     "Please report bugs to <bugs@netsniff-ng.org>\n"
	     "Copyright (C) 2009-2013 Daniel Borkmann <daniel@netsniff-ng.org>\n"
	     "Copyright (C) 2009-2012 Emmanuel Roullit <emmanuel@netsniff-ng.org>\n"
	     "Copyright (C) 2012      Markus Amend <markus@netsniff-ng.org>\n"
	     "License: GNU GPL version 2.0\n"
	     "This is free software: you are free to change and redistribute it.\n"
	     "There is NO WARRANTY, to the extent permitted by law.\n");
	die();
}

static void header(void)
{
	printf("%s%s%s\n", colorize_start(bold), "netsniff-ng " VERSION_STRING, colorize_end());
}

int main(int argc, char **argv)
{
	char *ptr;
	int c, i, j, opt_index, ops_touched = 0, vals[4] = {0};
	bool prio_high = false, setsockmem = true;
	void (*main_loop)(struct ctx *ctx) = NULL;
	struct ctx ctx = {
		.link_type = LINKTYPE_EN10MB,
		.print_mode = PRINT_NORM,
		.cpu = -1,
		.packet_type = -1,
		.promiscuous = true,
		.randomize = false,
		.pcap = PCAP_OPS_SG,
		.dump_interval = 60,
		.dump_mode = DUMP_INTERVAL_TIME,
	};

	setfsuid(getuid());
	setfsgid(getgid());

	srand(time(NULL));

	while ((c = getopt_long(argc, argv, short_options, long_options,
				&opt_index)) != EOF) {
		switch (c) {
		case 'd':
		case 'i':
			ctx.device_in = xstrdup(optarg);
			break;
		case 'o':
			ctx.device_out = xstrdup(optarg);
			break;
		case 'P':
			ctx.prefix = xstrdup(optarg);
			break;
		case 'R':
			ctx.link_type = LINKTYPE_IEEE802_11;
			ctx.rfraw = 1;
			break;
		case 'r':
			ctx.randomize = true;
			break;
		case 'J':
			ctx.jumbo_support = 1;
			break;
		case 'f':
			ctx.filter = xstrdup(optarg);
			break;
		case 'M':
			ctx.promiscuous = false;
			break;
		case 'A':
			setsockmem = false;
			break;
		case 't':
			if (!strncmp(optarg, "host", strlen("host")))
				ctx.packet_type = PACKET_HOST;
			else if (!strncmp(optarg, "broadcast", strlen("broadcast")))
				ctx.packet_type = PACKET_BROADCAST;
			else if (!strncmp(optarg, "multicast", strlen("multicast")))
				ctx.packet_type = PACKET_MULTICAST;
			else if (!strncmp(optarg, "others", strlen("others")))
				ctx.packet_type = PACKET_OTHERHOST;
			else if (!strncmp(optarg, "outgoing", strlen("outgoing")))
				ctx.packet_type = PACKET_OUTGOING;
			else
				ctx.packet_type = -1;
			break;
		case 'S':
			ptr = optarg;
			ctx.reserve_size = 0;

			for (j = i = strlen(optarg); i > 0; --i) {
				if (!isdigit(optarg[j - i]))
					break;
				ptr++;
			}

			if (!strncmp(ptr, "KiB", strlen("KiB")))
				ctx.reserve_size = 1 << 10;
			else if (!strncmp(ptr, "MiB", strlen("MiB")))
				ctx.reserve_size = 1 << 20;
			else if (!strncmp(ptr, "GiB", strlen("GiB")))
				ctx.reserve_size = 1 << 30;
			else
				panic("Syntax error in ring size param!\n");
			*ptr = 0;

			ctx.reserve_size *= strtol(optarg, NULL, 0);
			break;
		case 'b':
			set_cpu_affinity(optarg, 0);
			/* Take the first CPU for rebinding the IRQ */
			if (ctx.cpu != -2)
				ctx.cpu = strtol(optarg, NULL, 0);
			break;
		case 'B':
			set_cpu_affinity(optarg, 1);
			break;
		case 'H':
			prio_high = true;
			break;
		case 'c':
			ctx.pcap = PCAP_OPS_RW;
			ops_touched = 1;
			break;
		case 'm':
			ctx.pcap = PCAP_OPS_MMAP;
			ops_touched = 1;
			break;
		case 'g':
			ctx.pcap = PCAP_OPS_SG;
			ops_touched = 1;
			break;
		case 'Q':
			ctx.cpu = -2;
			break;
		case 's':
			ctx.print_mode = PRINT_NONE;
			break;
		case 'q':
			ctx.print_mode = PRINT_LESS;
			break;
		case 'X':
			ctx.print_mode =
				(ctx.print_mode == PRINT_ASCII) ?
				 PRINT_HEX_ASCII : PRINT_HEX;
			break;
		case 'l':
			ctx.print_mode =
				(ctx.print_mode == PRINT_HEX) ?
				 PRINT_HEX_ASCII : PRINT_ASCII;
			break;
		case 'k':
			ctx.kpull = strtol(optarg, NULL, 0);
			break;
		case 'n':
			frame_count_max = strtol(optarg, NULL, 0);
			break;
		case 'F':
			ptr = optarg;
			ctx.dump_interval = 0;

			for (j = i = strlen(optarg); i > 0; --i) {
				if (!isdigit(optarg[j - i]))
					break;
				ptr++;
			}

			if (!strncmp(ptr, "KiB", strlen("KiB"))) {
				ctx.dump_interval = 1 << 10;
				ctx.dump_mode = DUMP_INTERVAL_SIZE;
			} else if (!strncmp(ptr, "MiB", strlen("MiB"))) {
				ctx.dump_interval = 1 << 20;
				ctx.dump_mode = DUMP_INTERVAL_SIZE;
			} else if (!strncmp(ptr, "GiB", strlen("GiB"))) {
				ctx.dump_interval = 1 << 30;
				ctx.dump_mode = DUMP_INTERVAL_SIZE;
			} else if (!strncmp(ptr, "sec", strlen("sec"))) {
				ctx.dump_interval = 1;
				ctx.dump_mode = DUMP_INTERVAL_TIME;
			} else if (!strncmp(ptr, "min", strlen("min"))) {
				ctx.dump_interval = 60;
				ctx.dump_mode = DUMP_INTERVAL_TIME;
			} else if (!strncmp(ptr, "hrs", strlen("hrs"))) {
				ctx.dump_interval = 60 * 60;
				ctx.dump_mode = DUMP_INTERVAL_TIME;
			} else if (!strncmp(ptr, "s", strlen("s"))) {
				ctx.dump_interval = 1;
				ctx.dump_mode = DUMP_INTERVAL_TIME;
			} else {
				panic("Syntax error in time/size param!\n");
			}

			*ptr = 0;
			ctx.dump_interval *= strtol(optarg, NULL, 0);
			break;
		case 'V':
			ctx.verbose = 1;
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
			case 'P':
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

	if (!ctx.device_in)
		ctx.device_in = xstrdup("any");

	register_signal(SIGINT, signal_handler);
	register_signal(SIGHUP, signal_handler);

	header();

	init_pcap(ctx.jumbo_support);
	tprintf_init();

	if (prio_high) {
		set_proc_prio(get_default_proc_prio());
		set_sched_status(get_default_sched_policy(), get_default_sched_prio());
	}

	if (ctx.device_in && (device_mtu(ctx.device_in) ||
	    !strncmp("any", ctx.device_in, strlen(ctx.device_in)))) {
		if (!ctx.device_out) {
			ctx.dump = 0;
			main_loop = recv_only_or_dump;
		} else if (device_mtu(ctx.device_out)) {
			register_signal_f(SIGALRM, timer_elapsed, SA_SIGINFO);
			main_loop = receive_to_xmit;
		} else {
			ctx.dump = 1;
			register_signal_f(SIGALRM, timer_next_dump, SA_SIGINFO);
			main_loop = recv_only_or_dump;
			if (!ops_touched)
				ctx.pcap = PCAP_OPS_SG;
		}
	} else {
		if (ctx.device_out && device_mtu(ctx.device_out)) {
			register_signal_f(SIGALRM, timer_elapsed, SA_SIGINFO);
			main_loop = pcap_to_xmit;
			if (!ops_touched)
				ctx.pcap = PCAP_OPS_MMAP;
		} else {
			main_loop = read_pcap;
			if (!ops_touched)
				ctx.pcap = PCAP_OPS_SG;
		}
	}

	bug_on(!main_loop);

	if (setsockmem)
		set_system_socket_memory(vals);

	main_loop(&ctx);

	if (setsockmem)
		reset_system_socket_memory(vals);

	tprintf_cleanup();
	cleanup_pcap();

	free(ctx.device_in);
	free(ctx.device_out);
	free(ctx.device_trans);
	free(ctx.prefix);

	return 0;
}

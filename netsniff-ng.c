/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009-2013 Daniel Borkmann.
 * Copyright 2010 Emmanuel Roullit.
 * Subject to the GPL, version 2.
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
#include <inttypes.h>
#include <limits.h>

#include "ring_rx.h"
#include "ring_tx.h"
#include "mac80211.h"
#include "dev.h"
#include "built_in.h"
#include "pcap_io.h"
#include "privs.h"
#include "proc.h"
#include "bpf.h"
#include "ioops.h"
#include "die.h"
#include "irq.h"
#include "str.h"
#include "sig.h"
#include "config.h"
#include "sock.h"
#include "geoip.h"
#include "lockme.h"
#include "tprintf.h"
#include "timer.h"
#include "tstamping.h"
#include "dissector.h"
#include "xmalloc.h"

enum dump_mode {
	DUMP_INTERVAL_TIME,
	DUMP_INTERVAL_SIZE,
};

struct ctx {
	char *device_in, *device_out, *device_trans, *filter, *prefix;
	int cpu, rfraw, dump, print_mode, dump_dir, packet_type, lo_ifindex;
	unsigned long kpull, dump_interval, tx_bytes, tx_packets;
	size_t reserve_size;
	bool randomize, promiscuous, enforce, jumbo, dump_bpf, hwtimestamp, verbose;
	enum pcap_ops_groups pcap;
	enum dump_mode dump_mode;
	uid_t uid;
	gid_t gid;
	uint32_t link_type, magic;
	uint32_t fanout_group, fanout_type;
	uint64_t pkts_seen, pkts_recvd, pkts_drops;
	uint64_t pkts_recvd_last, pkts_drops_last, pkts_skipd_last;
	unsigned long overwrite_interval, file_number;
};

static volatile sig_atomic_t sigint = 0, sighup = 0;
static volatile bool next_dump = false;
static volatile sig_atomic_t sighup_time = 0;

static const char *short_options =
	"d:i:o:rf:MNJt:S:k:n:b:HQmcsqXlvhF:RGAO:P:Vu:g:T:DBUC:K:L:w";
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
	{"overwrite",		required_argument,	NULL, 'O'},
	{"prefix",		required_argument,	NULL, 'P'},
	{"user",		required_argument,	NULL, 'u'},
	{"group",		required_argument,	NULL, 'g'},
	{"magic",		required_argument,	NULL, 'T'},
	{"fanout-group",	required_argument,	NULL, 'C'},
	{"fanout-type",		required_argument,	NULL, 'K'},
	{"fanout-opts",		required_argument,	NULL, 'L'},
	{"rand",		no_argument,		NULL, 'r'},
	{"rfraw",		no_argument,		NULL, 'R'},
	{"mmap",		no_argument,		NULL, 'm'},
	{"sg",			no_argument,		NULL, 'G'},
	{"clrw",		no_argument,		NULL, 'c'},
	{"jumbo-support",	no_argument,		NULL, 'J'},
	{"no-promisc",		no_argument,		NULL, 'M'},
	{"no-hwtimestamp",	no_argument,		NULL, 'N'},
	{"prio-high",		no_argument,		NULL, 'H'},
	{"notouch-irq",		no_argument,		NULL, 'Q'},
	{"dump-pcap-types",	no_argument,		NULL, 'D'},
	{"dump-bpf",		no_argument,		NULL, 'B'},
	{"silent",		no_argument,		NULL, 's'},
	{"less",		no_argument,		NULL, 'q'},
	{"hex",			no_argument,		NULL, 'X'},
	{"ascii",		no_argument,		NULL, 'l'},
	{"no-sock-mem",		no_argument,		NULL, 'A'},
	{"update",		no_argument,		NULL, 'U'},
	{"cooked",		no_argument,		NULL, 'w'},
	{"verbose",		no_argument,		NULL, 'V'},
	{"version",		no_argument,		NULL, 'v'},
	{"help",		no_argument,		NULL, 'h'},
	{NULL, 0, NULL, 0}
};

static const char *copyright =
	"Please report bugs at https://github.com/netsniff-ng/netsniff-ng/issues\n"
	"Copyright (C) 2009-2013 Daniel Borkmann <dborkma@tik.ee.ethz.ch>\n"
	"Copyright (C) 2009-2012 Emmanuel Roullit <emmanuel.roullit@gmail.com>\n"
	"Copyright (C) 2012 Markus Amend <markus@netsniff-ng.org>\n"
	"Swiss federal institute of technology (ETH Zurich)\n"
	"License: GNU GPL version 2.0\n"
	"This is free software: you are free to change and redistribute it.\n"
	"There is NO WARRANTY, to the extent permitted by law.";

static int tx_sock;
static struct itimerval itimer;
static unsigned long frame_count_max = 0, interval = TX_KERNEL_PULL_INT;
static time_t start_time;

#define __pcap_io		pcap_ops[ctx->pcap]

static void signal_handler(int number)
{
	switch (number) {
	case SIGINT:
	case SIGQUIT:
	case SIGTERM:
		sigint = 1;
		break;
	case SIGHUP:
		sighup = 1;
		sighup_time = (sig_atomic_t)(time(NULL) - start_time);
		break;
	default:
		break;
	}
}

static void timer_elapsed(int unused __maybe_unused)
{
	int ret;

	set_itimer_interval_value(&itimer, 0, interval);

	ret = pull_and_flush_tx_ring(tx_sock);
	if (unlikely(ret < 0)) {
		/* We could hit EBADF if the socket has been closed before
		 * the timer was triggered.
		 */
		if (errno != EBADF && errno != ENOBUFS)
			panic("Flushing TX_RING failed: %s!\n", strerror(errno));
	}

	setitimer(ITIMER_REAL, &itimer, NULL);
}

static void timer_purge(void)
{
	int ret;

	ret = pull_and_flush_tx_ring_wait(tx_sock);
	if (unlikely(ret < 0)) {
		if (errno != EBADF && errno != ENOBUFS)
			panic("Flushing TX_RING failed: %s!\n", strerror(errno));
	}

	set_itimer_interval_value(&itimer, 0, 0);
	setitimer(ITIMER_REAL, &itimer, NULL);
}

static void timer_next_dump(int unused __maybe_unused)
{
	set_itimer_interval_value(&itimer, interval, 0);
	next_dump = true;
	setitimer(ITIMER_REAL, &itimer, NULL);
}

static inline bool dump_to_pcap(struct ctx *ctx)
{
	return ctx->dump;
}

static void on_panic_del_rfmon(void *arg)
{
	leave_rfmon_mac80211(arg);
}

static inline void setup_rfmon_mac80211_dev(struct ctx *ctx, char **rfmon_dev)
{
	ctx->device_trans = xstrdup(*rfmon_dev);
	xfree(*rfmon_dev);

	enter_rfmon_mac80211(ctx->device_trans, rfmon_dev);
	panic_handler_add(on_panic_del_rfmon, *rfmon_dev);
}

static int update_rx_stats(struct ctx *ctx, int sock, bool is_v3)
{
	uint64_t packets, drops;
	int ret;

	ret = get_rx_net_stats(sock, &packets, &drops, is_v3);
	if (ret)
		return ret;

	drops += ctx->pkts_skipd_last;
	ctx->pkts_seen += ctx->pkts_skipd_last;
	ctx->pkts_recvd += packets;
	ctx->pkts_drops += drops;
	ctx->pkts_recvd_last = packets;
	ctx->pkts_drops_last = drops;
	ctx->pkts_skipd_last = 0;

	return 0;
}

static void dump_rx_stats(struct ctx *ctx, int sock, bool is_v3)
{
	if (update_rx_stats(ctx, sock, is_v3))
		return;

	printf("\r%12"PRIu64"  packets incoming (%"PRIu64" unread on exit)\n",
	       is_v3 ? ctx->pkts_seen : ctx->pkts_recvd,
	       is_v3 ? ctx->pkts_recvd - ctx->pkts_seen : 0);
	printf("\r%12"PRIu64"  packets passed filter\n",
	       ctx->pkts_recvd - ctx->pkts_drops);
	printf("\r%12"PRIu64"  packets failed filter (out of space)\n",
	       ctx->pkts_drops);

	if (ctx->pkts_recvd  > 0)
		printf("\r%12.4lf%% packet droprate\n",
		       (1.0 * ctx->pkts_drops / ctx->pkts_recvd) * 100.0);
}

static void pcap_to_xmit(struct ctx *ctx)
{
	uint8_t *out = NULL;
	int ifindex, fd = 0, ret;
	size_t size;
	unsigned int it = 0;
	unsigned long trunced = 0;
	struct ring tx_ring;
	struct frame_map *hdr;
	struct sock_fprog bpf_ops;
	struct timeval start, end, diff;
	pcap_pkthdr_t phdr;

	if (!device_up_and_running(ctx->device_out) && !ctx->rfraw)
		panic("Device not up and running!\n");

	bug_on(!__pcap_io);

	tx_sock = pf_socket();

	if (!strncmp("-", ctx->device_in, strlen("-"))) {
		fd = dup_or_die(fileno(stdin));
		close(fileno(stdin));
		if (ctx->pcap == PCAP_OPS_MM)
			ctx->pcap = PCAP_OPS_SG;
	} else {
		fd = open_or_die(ctx->device_in, O_RDONLY | O_LARGEFILE | O_NOATIME);
	}

	if (__pcap_io->init_once_pcap)
		__pcap_io->init_once_pcap(true);

	ret = __pcap_io->pull_fhdr_pcap(fd, &ctx->magic, &ctx->link_type);
	if (ret)
		panic("Error reading pcap header!\n");

	if (__pcap_io->prepare_access_pcap) {
		ret = __pcap_io->prepare_access_pcap(fd, PCAP_MODE_RD, ctx->jumbo);
		if (ret)
			panic("Error prepare reading pcap!\n");
	}

	if (ctx->rfraw) {
		setup_rfmon_mac80211_dev(ctx, &ctx->device_out);

		if (ctx->link_type != LINKTYPE_IEEE802_11 &&
		    ctx->link_type != LINKTYPE_IEEE802_11_RADIOTAP)
			panic("Wrong linktype of pcap!\n");
	}

	ifindex = device_ifindex(ctx->device_out);
	size = ring_size(ctx->device_out, ctx->reserve_size);

	bpf_parse_rules(ctx->filter, &bpf_ops, ctx->link_type);
	if (ctx->dump_bpf)
		bpf_dump_all(&bpf_ops);

	ring_tx_setup(&tx_ring, tx_sock, size, ifindex, ctx->jumbo, ctx->verbose);

	dissector_init_all(ctx->print_mode);

	if (ctx->cpu >= 0 && ifindex > 0) {
		int irq = device_irq_number(ctx->device_out);
		device_set_irq_affinity(irq, ctx->cpu);

		if (ctx->verbose)
			printf("IRQ: %s:%d > CPU%d\n",
			       ctx->device_out, irq, ctx->cpu);
	}

	if (ctx->kpull)
		interval = ctx->kpull;

	set_itimer_interval_value(&itimer, 0, interval);
	setitimer(ITIMER_REAL, &itimer, NULL);

	drop_privileges(ctx->enforce, ctx->uid, ctx->gid);

	printf("Running! Hang up with ^C!\n\n");
	fflush(stdout);

	bug_on(gettimeofday(&start, NULL));

	while (likely(sigint == 0)) {
		while (user_may_pull_from_tx(tx_ring.frames[it].iov_base)) {
			hdr = tx_ring.frames[it].iov_base;
			out = ((uint8_t *) hdr) + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll);

			do {
				ret = __pcap_io->read_pcap(fd, &phdr, ctx->magic, out,
							   ring_frame_size(&tx_ring));
				if (unlikely(ret <= 0))
					goto out;

				if (ring_frame_size(&tx_ring) <
				    pcap_get_length(&phdr, ctx->magic)) {
					pcap_set_length(&phdr, ctx->magic,
							ring_frame_size(&tx_ring));
					trunced++;
				}
			} while (ctx->filter &&
				 !bpf_run_filter(&bpf_ops, out,
						 pcap_get_length(&phdr, ctx->magic)));

			pcap_pkthdr_to_tpacket_hdr(&phdr, ctx->magic, &hdr->tp_h, NULL);

			ctx->tx_bytes += hdr->tp_h.tp_len;;
			ctx->tx_packets++;

			show_frame_hdr(out, hdr->tp_h.tp_snaplen,
				       ctx->link_type, hdr, ctx->print_mode,
				       ctx->tx_packets);

			dissector_entry_point(out, hdr->tp_h.tp_snaplen,
					      ctx->link_type, ctx->print_mode,
					      &hdr->s_ll);

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
	timersub(&end, &start, &diff);

	timer_purge();

	bpf_release(&bpf_ops);

	dissector_cleanup_all();
	destroy_tx_ring(tx_sock, &tx_ring);

	if (ctx->rfraw)
		leave_rfmon_mac80211(ctx->device_out);

	if (__pcap_io->prepare_close_pcap)
		__pcap_io->prepare_close_pcap(fd, PCAP_MODE_RD);

	if (!strncmp("-", ctx->device_in, strlen("-")))
		dup2(fd, fileno(stdin));
	close(fd);

	close(tx_sock);

	fflush(stdout);
	printf("\n");
	printf("\r%12lu packets outgoing\n", ctx->tx_packets);
	printf("\r%12lu packets truncated in file\n", trunced);
	printf("\r%12lu bytes outgoing\n", ctx->tx_bytes);
	printf("\r%12lu sec, %lu usec in total\n", diff.tv_sec, diff.tv_usec);
}

static inline bool __skip_packet(struct ctx *ctx, struct sockaddr_ll *sll)
{
	if (ctx->packet_type != -1)
		return ctx->packet_type != sll->sll_pkttype;

	/* when receving from the loopback device, each packet is seen twice,
	 * so drop the outgoing ones to avoid duplicates
	 */
	return (sll->sll_ifindex == ctx->lo_ifindex) &&
	       (sll->sll_pkttype == PACKET_OUTGOING);
}

static inline bool skip_packet(struct ctx *ctx, struct sockaddr_ll *sll)
{
	bool skip = __skip_packet(ctx, sll);

	if (skip)
		ctx->pkts_skipd_last++;
	return skip;
}

static void receive_to_xmit(struct ctx *ctx)
{
	short ifflags = 0;
	uint8_t *in, *out;
	int rx_sock, ifindex_in, ifindex_out, ret;
	size_t size_in, size_out;
	unsigned int it_in = 0, it_out = 0;
	struct frame_map *hdr_in, *hdr_out;
	struct ring tx_ring, rx_ring;
	struct pollfd rx_poll;
	struct sock_fprog bpf_ops;

	if (!strncmp(ctx->device_in, ctx->device_out, IFNAMSIZ))
		panic("Ingress/egress devices must be different!\n");
	if (!device_up_and_running(ctx->device_out))
		panic("Egress device not up and running!\n");

	rx_sock = pf_socket();
	tx_sock = pf_socket();

	ifindex_in = device_ifindex(ctx->device_in);
	ifindex_out = device_ifindex(ctx->device_out);

	size_in = ring_size(ctx->device_in, ctx->reserve_size);
	size_out = ring_size(ctx->device_out, ctx->reserve_size);

	enable_kernel_bpf_jit_compiler();

	bpf_parse_rules(ctx->filter, &bpf_ops, ctx->link_type);
	if (ctx->dump_bpf)
		bpf_dump_all(&bpf_ops);
	bpf_attach_to_sock(rx_sock, &bpf_ops);

	ring_rx_setup(&rx_ring, rx_sock, size_in, ifindex_in, &rx_poll, false, ctx->jumbo,
		      ctx->verbose, ctx->fanout_group, ctx->fanout_type);
	ring_tx_setup(&tx_ring, tx_sock, size_out, ifindex_out, ctx->jumbo, ctx->verbose);

	dissector_init_all(ctx->print_mode);

	if (ctx->promiscuous)
		ifflags = device_enter_promiscuous_mode(ctx->device_in);

	if (ctx->kpull)
		interval = ctx->kpull;

	set_itimer_interval_value(&itimer, 0, interval);
	setitimer(ITIMER_REAL, &itimer, NULL);

	drop_privileges(ctx->enforce, ctx->uid, ctx->gid);

	printf("Running! Hang up with ^C!\n\n");
	fflush(stdout);

	while (likely(sigint == 0)) {
		while (user_may_pull_from_rx(rx_ring.frames[it_in].iov_base)) {
			hdr_in = rx_ring.frames[it_in].iov_base;
			in = ((uint8_t *) hdr_in) + hdr_in->tp_h.tp_mac;

			if (skip_packet(ctx, &hdr_in->s_ll))
				goto next;

			ctx->pkts_seen++;

			hdr_out = tx_ring.frames[it_out].iov_base;
			out = ((uint8_t *) hdr_out) + TPACKET2_HDRLEN - sizeof(struct sockaddr_ll);

			while (!user_may_pull_from_tx(tx_ring.frames[it_out].iov_base) &&
			       likely(!sigint)) {
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
			memcpy(out, in, hdr_in->tp_h.tp_len);

			kernel_may_pull_from_tx(&hdr_out->tp_h);
			if (ctx->randomize)
				next_rnd_slot(&it_out, &tx_ring);
			else {
				it_out++;
				if (it_out >= tx_ring.layout.tp_frame_nr)
					it_out = 0;
			}

			show_frame_hdr(in, hdr_in->tp_h.tp_snaplen,
				       ctx->link_type, hdr_in, ctx->print_mode,
				       ctx->pkts_seen);

			dissector_entry_point(in, hdr_in->tp_h.tp_snaplen,
					      ctx->link_type, ctx->print_mode,
					      &hdr_in->s_ll);

			if (frame_count_max != 0) {
				if (ctx->pkts_seen >= frame_count_max) {
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

		ret = poll(&rx_poll, 1, -1);
		if (unlikely(ret < 0)) {
			if (errno != EINTR)
				panic("Poll failed!\n");
		}
	}

out:
	timer_purge();

	dump_rx_stats(ctx, rx_sock, false);

	bpf_release(&bpf_ops);

	dissector_cleanup_all();

	destroy_tx_ring(tx_sock, &tx_ring);
	destroy_rx_ring(rx_sock, &rx_ring);

	if (ctx->promiscuous)
		device_leave_promiscuous_mode(ctx->device_in, ifflags);

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
		slprintf(bout, sizeof(bout), "0x%02x,", out[bytes_done]);
		write_or_die(fdo, bout, strlen(bout));

		bytes_done++;

		if (bytes_done % 10 == 0) {
			slprintf(bout, sizeof(bout), "\n");
			write_or_die(fdo, bout, strlen(bout));

			if (bytes_done < len) {
				slprintf(bout, sizeof(bout), "  ");
				write_or_die(fdo, bout, strlen(bout));
			}
		} else if (bytes_done < len) {
			slprintf(bout, sizeof(bout), " ");
			write_or_die(fdo, bout, strlen(bout));
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
	uint8_t *out;
	int ret, fd, fdo = 0;
	unsigned long trunced = 0;
	size_t out_len;
	pcap_pkthdr_t phdr;
	struct sock_fprog bpf_ops;
	struct frame_map fm;
	struct timeval start, end, diff;
	bool is_out_pcap = ctx->device_out && strstr(ctx->device_out, ".pcap");
	const struct pcap_file_ops *pcap_out_ops = pcap_ops[PCAP_OPS_RW];

	bug_on(!__pcap_io);

	if (!strncmp("-", ctx->device_in, strlen("-"))) {
		fd = dup_or_die(fileno(stdin));
		close(fileno(stdin));
		if (ctx->pcap == PCAP_OPS_MM)
			ctx->pcap = PCAP_OPS_SG;
	} else {
		/* O_NOATIME requires privileges, in case we don't have
		 * them, retry without them at a minor cost of updating
		 * atime in case the fs has been mounted as such.
		 */
		fd = open(ctx->device_in, O_RDONLY | O_LARGEFILE | O_NOATIME);
		if (fd < 0 && errno == EPERM)
			fd = open_or_die(ctx->device_in, O_RDONLY | O_LARGEFILE);
		if (fd < 0)
			panic("Cannot open file %s! %s.\n", ctx->device_in,
			      strerror(errno));
	}

	if (__pcap_io->init_once_pcap)
		__pcap_io->init_once_pcap(false);

	ret = __pcap_io->pull_fhdr_pcap(fd, &ctx->magic, &ctx->link_type);
	if (ret)
		panic("Error reading pcap header!\n");

	if (__pcap_io->prepare_access_pcap) {
		ret = __pcap_io->prepare_access_pcap(fd, PCAP_MODE_RD, ctx->jumbo);
		if (ret)
			panic("Error prepare reading pcap!\n");
	}

	memset(&fm, 0, sizeof(fm));

	bpf_parse_rules(ctx->filter, &bpf_ops, ctx->link_type);
	if (ctx->dump_bpf)
		bpf_dump_all(&bpf_ops);

	dissector_init_all(ctx->print_mode);

	out_len = round_up(1024 * 1024, RUNTIME_PAGE_SIZE);
	out = xmalloc_aligned(out_len, CO_CACHE_LINE_SIZE);

	if (ctx->device_out) {
		if (!strncmp("-", ctx->device_out, strlen("-"))) {
			fdo = dup_or_die(fileno(stdout));
			close(fileno(stdout));
		} else {
			fdo = open_or_die_m(ctx->device_out, O_RDWR | O_CREAT |
					    O_TRUNC | O_LARGEFILE, DEFFILEMODE);
		}
	}

	if (is_out_pcap) {
		ret = pcap_out_ops->push_fhdr_pcap(fdo, ctx->magic,
						   ctx->link_type);
		if (ret)
			panic("Error writing pcap header!\n");
	}

	drop_privileges(ctx->enforce, ctx->uid, ctx->gid);

	printf("Running! Hang up with ^C!\n\n");
	fflush(stdout);

	bug_on(gettimeofday(&start, NULL));

	while (likely(sigint == 0)) {
		do {
			ret = __pcap_io->read_pcap(fd, &phdr, ctx->magic,
						   out, out_len);
			if (unlikely(ret < 0))
				goto out;

			if (unlikely(pcap_get_length(&phdr, ctx->magic) == 0)) {
				trunced++;
				continue;
			}

			if (unlikely(pcap_get_length(&phdr, ctx->magic) > out_len)) {
				pcap_set_length(&phdr, ctx->magic, out_len);
				trunced++;
			}
		} while (ctx->filter &&
			 !bpf_run_filter(&bpf_ops, out,
					 pcap_get_length(&phdr, ctx->magic)));

		pcap_pkthdr_to_tpacket_hdr(&phdr, ctx->magic, &fm.tp_h, &fm.s_ll);

		ctx->tx_bytes += fm.tp_h.tp_len;
		ctx->tx_packets++;

		show_frame_hdr(out, fm.tp_h.tp_snaplen, ctx->link_type, &fm,
			       ctx->print_mode, ctx->tx_packets);

		dissector_entry_point(out, fm.tp_h.tp_snaplen,
				      ctx->link_type, ctx->print_mode,
				      &fm.s_ll);

		if (is_out_pcap) {
			size_t pcap_len = pcap_get_length(&phdr, ctx->magic);
			int wlen = pcap_out_ops->write_pcap(fdo, &phdr,
							    ctx->magic, out,
							    pcap_len);
			if (unlikely(wlen != (int)pcap_get_total_length(&phdr, ctx->magic)))
				panic("Error writing to pcap!\n");
		} else if (ctx->device_out) {
			translate_pcap_to_txf(fdo, out, fm.tp_h.tp_snaplen);
		}

		if (frame_count_max != 0) {
			if (ctx->tx_packets >= frame_count_max) {
				sigint = 1;
				break;
			}
		}
	}

out:
	bug_on(gettimeofday(&end, NULL));
	timersub(&end, &start, &diff);

	bpf_release(&bpf_ops);

	dissector_cleanup_all();

	if (__pcap_io->prepare_close_pcap)
		__pcap_io->prepare_close_pcap(fd, PCAP_MODE_RD);

	xfree(out);

	fflush(stdout);
	printf("\n");
	printf("\r%12lu packets outgoing\n", ctx->tx_packets);
	printf("\r%12lu packets truncated in file\n", trunced);
	printf("\r%12lu bytes outgoing\n", ctx->tx_bytes);
	printf("\r%12lu sec, %lu usec in total\n", diff.tv_sec, diff.tv_usec);

	if (!strncmp("-", ctx->device_in, strlen("-")))
		dup2(fd, fileno(stdin));
	close(fd);

	if (ctx->device_out) {
		if (!strncmp("-", ctx->device_out, strlen("-")))
			dup2(fdo, fileno(stdout));
		close(fdo);
	}
}

static void generate_multi_pcap_filename(struct ctx *ctx, char *fname, size_t size, time_t ftime)
{
	if (ctx->overwrite_interval > 0) {
		slprintf(fname, size, "%s/%s%010lu.pcap", ctx->device_out,
			 ctx->prefix, ctx->file_number);

		ctx->file_number++;

		if (ctx->file_number >= ctx->overwrite_interval)
			ctx->file_number = 0;
	} else {
		slprintf(fname, size, "%s/%s%lu.pcap", ctx->device_out,
			 ctx->prefix, ftime);
	}
}

static void finish_multi_pcap_file(struct ctx *ctx, int fd)
{
	__pcap_io->fsync_pcap(fd);

	if (__pcap_io->prepare_close_pcap)
		__pcap_io->prepare_close_pcap(fd, PCAP_MODE_WR);

	close(fd);

	memset(&itimer, 0, sizeof(itimer));
	setitimer(ITIMER_REAL, &itimer, NULL);
}

static int next_multi_pcap_file(struct ctx *ctx, int fd)
{
	int ret;
	char fname[PATH_MAX] = {0};
	time_t ftime;

	__pcap_io->fsync_pcap(fd);

	if (__pcap_io->prepare_close_pcap)
		__pcap_io->prepare_close_pcap(fd, PCAP_MODE_WR);

	close(fd);

	if (sighup_time > 0) {
		ftime = (time_t)(start_time + sighup_time);
		sighup_time = 0;
	} else
		ftime = time(NULL);

	generate_multi_pcap_filename(ctx, fname, sizeof(fname), ftime);

	fd = open_or_die_m(fname, O_RDWR | O_CREAT | O_TRUNC |
			   O_LARGEFILE, DEFFILEMODE);

	ret = __pcap_io->push_fhdr_pcap(fd, ctx->magic, ctx->link_type);
	if (ret)
		panic("Error writing pcap header!\n");

	if (__pcap_io->prepare_access_pcap) {
		ret = __pcap_io->prepare_access_pcap(fd, PCAP_MODE_WR, true);
		if (ret)
			panic("Error prepare writing pcap!\n");
	}

	return fd;
}

static void reset_interval(struct ctx *ctx)
{
	if (ctx->dump_mode == DUMP_INTERVAL_TIME) {
		interval = ctx->dump_interval;

		set_itimer_interval_value(&itimer, interval, 0);
		setitimer(ITIMER_REAL, &itimer, NULL);
	} else {
		interval = 0;
	}
}

static int begin_multi_pcap_file(struct ctx *ctx)
{
	int fd, ret;
	char fname[PATH_MAX] = {0};

	bug_on(!__pcap_io);

	if (ctx->device_out[strlen(ctx->device_out) - 1] == '/')
		ctx->device_out[strlen(ctx->device_out) - 1] = 0;

	generate_multi_pcap_filename(ctx, fname, sizeof(fname), time(NULL));

	fd = open_or_die_m(fname, O_RDWR | O_CREAT | O_TRUNC |
			   O_LARGEFILE, DEFFILEMODE);

	ret = __pcap_io->push_fhdr_pcap(fd, ctx->magic, ctx->link_type);
	if (ret)
		panic("Error writing pcap header!\n");

	if (__pcap_io->prepare_access_pcap) {
		ret = __pcap_io->prepare_access_pcap(fd, PCAP_MODE_WR, true);
		if (ret)
			panic("Error prepare writing pcap!\n");
	}

	reset_interval(ctx);

	return fd;
}

static void finish_single_pcap_file(struct ctx *ctx, int fd)
{
	__pcap_io->fsync_pcap(fd);

	if (__pcap_io->prepare_close_pcap)
		__pcap_io->prepare_close_pcap(fd, PCAP_MODE_WR);

	if (strncmp("-", ctx->device_out, strlen("-")))
		close(fd);
	else
		dup2(fd, fileno(stdout));
}

static int begin_single_pcap_file(struct ctx *ctx)
{
	int fd, ret;
	char fname[PATH_MAX];

	bug_on(!__pcap_io);

	if (!strncmp("-", ctx->device_out, strlen("-"))) {
		fd = dup_or_die(fileno(stdout));
		close(fileno(stdout));
		if (ctx->pcap == PCAP_OPS_MM)
			ctx->pcap = PCAP_OPS_SG;
	} else {
		time_t t;
		struct tm *ltm;

		t = time(NULL);
		if (t == -1)
			panic("time() failed\n");

		ltm = localtime(&t);
		if (ltm == NULL)
			panic("localtime() failed\n");

		strftime(fname, sizeof(fname), ctx->device_out, ltm);

		fd = open_or_die_m(fname,
				   O_RDWR | O_CREAT | O_TRUNC |
				   O_LARGEFILE, DEFFILEMODE);
	}

	ret = __pcap_io->push_fhdr_pcap(fd, ctx->magic, ctx->link_type);
	if (ret)
		panic("Error writing pcap header!\n");

	if (__pcap_io->prepare_access_pcap) {
		ret = __pcap_io->prepare_access_pcap(fd, PCAP_MODE_WR, true);
		if (ret)
			panic("Error prepare writing pcap!\n");
	}

	return fd;
}

static void update_pcap_next_dump(struct ctx *ctx, unsigned long snaplen,
				  int *fd, int sock, bool is_v3)
{
	if (!dump_to_pcap(ctx))
		return;

	if (ctx->dump_mode == DUMP_INTERVAL_SIZE) {
		interval += snaplen;
		if (interval > ctx->dump_interval) {
			next_dump = true;
			interval = 0;
		}
	}

	if (sighup) {
		if (ctx->verbose)
			printf("SIGHUP received, prematurely rotating pcap\n");
		sighup = 0;
		next_dump = true;
		reset_interval(ctx);
	}

	if (next_dump) {
		*fd = next_multi_pcap_file(ctx, *fd);
		next_dump = false;

		if (update_rx_stats(ctx, sock, is_v3))
			return;

		if (ctx->verbose && ctx->print_mode == PRINT_NONE)
			printf(".(+%"PRIu64"/-%"PRIu64")",
			       ctx->pkts_recvd_last - ctx->pkts_drops_last,
			       ctx->pkts_drops_last);
	}
}

#ifdef HAVE_TPACKET3
static void walk_t3_block(struct block_desc *pbd, struct ctx *ctx,
			  int sock, int *fd)
{
	int num_pkts = pbd->h1.num_pkts, i;
	struct tpacket3_hdr *hdr;
	struct sockaddr_ll *sll;

	hdr = (void *) ((uint8_t *) pbd + pbd->h1.offset_to_first_pkt);
	sll = (void *) ((uint8_t *) hdr + TPACKET_ALIGN(sizeof(*hdr)));

	for (i = 0; i < num_pkts && likely(sigint == 0); ++i) {
		uint8_t *packet = ((uint8_t *) hdr + hdr->tp_mac);
		pcap_pkthdr_t phdr;

		if (skip_packet(ctx, sll))
			goto next;

		ctx->pkts_seen++;

		if (dump_to_pcap(ctx)) {
			int ret;

			tpacket3_hdr_to_pcap_pkthdr(hdr, sll, &phdr, ctx->magic);

			ret = __pcap_io->write_pcap(*fd, &phdr, ctx->magic, packet,
						    pcap_get_length(&phdr, ctx->magic));
			if (unlikely(ret != (int) pcap_get_total_length(&phdr, ctx->magic)))
				panic("Write error to pcap!\n");
		}

		__show_frame_hdr(packet, hdr->tp_snaplen, ctx->link_type, sll,
				 hdr, ctx->print_mode, true, ctx->pkts_seen);

		dissector_entry_point(packet, hdr->tp_snaplen, ctx->link_type,
				      ctx->print_mode, sll);
next:
                hdr = (void *) ((uint8_t *) hdr + hdr->tp_next_offset);
		sll = (void *) ((uint8_t *) hdr + TPACKET_ALIGN(sizeof(*hdr)));

		if (frame_count_max != 0) {
			if (unlikely(ctx->pkts_seen >= frame_count_max)) {
				sigint = 1;
				break;
			}
		}

		update_pcap_next_dump(ctx, hdr->tp_snaplen, fd, sock, true);
	}
}
#endif /* HAVE_TPACKET3 */

static void recv_only_or_dump(struct ctx *ctx)
{
	short ifflags = 0;
	int sock, ifindex, fd = 0, ret;
	size_t size;
	unsigned int it = 0;
	struct ring rx_ring;
	struct pollfd rx_poll;
	struct sock_fprog bpf_ops;
	struct timeval start, end, diff;
	bool is_v3 = is_defined(HAVE_TPACKET3);

	sock = pf_socket_type(ctx->link_type);

	ifindex = device_ifindex(ctx->device_in);
	size = ring_size(ctx->device_in, ctx->reserve_size);

	enable_kernel_bpf_jit_compiler();

	bpf_parse_rules(ctx->filter, &bpf_ops, ctx->link_type);
	if (ctx->dump_bpf)
		bpf_dump_all(&bpf_ops);
	bpf_attach_to_sock(sock, &bpf_ops);

	if (ctx->hwtimestamp) {
		ret = set_sockopt_hwtimestamp(sock, ctx->device_in);
		if (ret == 0 && ctx->verbose)
			printf("HW timestamping enabled\n");
	}

	ring_rx_setup(&rx_ring, sock, size, ifindex, &rx_poll, is_v3, true,
		      ctx->verbose, ctx->fanout_group, ctx->fanout_type);

	dissector_init_all(ctx->print_mode);

	if (ctx->cpu >= 0 && ifindex > 0) {
		int irq = device_irq_number(ctx->device_in);
		device_set_irq_affinity(irq, ctx->cpu);

		if (ctx->verbose)
			printf("IRQ: %s:%d > CPU%d\n",
			       ctx->device_in, irq, ctx->cpu);
	}

	if (ctx->promiscuous)
		ifflags = device_enter_promiscuous_mode(ctx->device_in);

	if (dump_to_pcap(ctx) && __pcap_io->init_once_pcap)
		__pcap_io->init_once_pcap(true);

	drop_privileges(ctx->enforce, ctx->uid, ctx->gid);

	if (dump_to_pcap(ctx)) {
		struct stat stats;

		ret = stat(ctx->device_out, &stats);
		if (ret < 0)
			ctx->dump_dir = 0;
		else
			ctx->dump_dir = S_ISDIR(stats.st_mode);

		if (ctx->dump_dir)
			fd = begin_multi_pcap_file(ctx);
		else
			fd = begin_single_pcap_file(ctx);
	}

	printf("Running! Hang up with ^C!\n\n");
	fflush(stdout);

	bug_on(gettimeofday(&start, NULL));

	while (likely(sigint == 0)) {
#ifdef HAVE_TPACKET3
		struct block_desc *pbd;

		while (user_may_pull_from_rx_block((pbd = rx_ring.frames[it].iov_base))) {
			walk_t3_block(pbd, ctx, sock, &fd);

			kernel_may_pull_from_rx_block(pbd);
			it = (it + 1) % rx_ring.layout3.tp_block_nr;

			if (unlikely(sigint == 1))
				break;
		}
#else
		while (user_may_pull_from_rx(rx_ring.frames[it].iov_base)) {
			struct frame_map *hdr = rx_ring.frames[it].iov_base;
			uint8_t *packet = ((uint8_t *) hdr) + hdr->tp_h.tp_mac;
			pcap_pkthdr_t phdr;

			if (skip_packet(ctx, &hdr->s_ll))
				goto next;

			ctx->pkts_seen++;

			if (unlikely(ring_frame_size(&rx_ring) < hdr->tp_h.tp_snaplen)) {
				/* XXX: silently ignore for now. We used to
				 * report them with dump_rx_stats()  */
				goto next;
			}

			if (dump_to_pcap(ctx)) {
				tpacket_hdr_to_pcap_pkthdr(&hdr->tp_h, &hdr->s_ll, &phdr, ctx->magic);

				ret = __pcap_io->write_pcap(fd, &phdr, ctx->magic, packet,
							    pcap_get_length(&phdr, ctx->magic));
				if (unlikely(ret != (int) pcap_get_total_length(&phdr, ctx->magic)))
					panic("Write error to pcap!\n");
			}

			show_frame_hdr(packet, hdr->tp_h.tp_snaplen,
				       ctx->link_type, hdr, ctx->print_mode,
				       ctx->pkts_seen);

			dissector_entry_point(packet, hdr->tp_h.tp_snaplen,
					      ctx->link_type, ctx->print_mode,
					      &hdr->s_ll);

			if (frame_count_max != 0) {
				if (unlikely(ctx->pkts_seen >= frame_count_max)) {
					sigint = 1;
					break;
				}
			}

next:
			kernel_may_pull_from_rx(&hdr->tp_h);
			it = (it + 1) % rx_ring.layout.tp_frame_nr;

			if (unlikely(sigint == 1))
				break;

			update_pcap_next_dump(ctx, hdr->tp_h.tp_snaplen, &fd,
					      sock, is_v3);
		}
#endif /* HAVE_TPACKET3 */

		ret = poll(&rx_poll, 1, -1);
		if (unlikely(ret < 0)) {
			if (errno != EINTR)
				panic("Poll failed!\n");
		}
	}

	bug_on(gettimeofday(&end, NULL));
	timersub(&end, &start, &diff);

	dump_rx_stats(ctx, sock, is_v3);
	printf("\r%12lu  sec, %lu usec in total\n",
			diff.tv_sec, diff.tv_usec);

	bpf_release(&bpf_ops);
	dissector_cleanup_all();
	destroy_rx_ring(sock, &rx_ring);

	if (ctx->promiscuous)
		device_leave_promiscuous_mode(ctx->device_in, ifflags);

	if (ctx->rfraw)
		leave_rfmon_mac80211(ctx->device_in);

	if (dump_to_pcap(ctx)) {
		if (ctx->dump_dir)
			finish_multi_pcap_file(ctx, fd);
		else
			finish_single_pcap_file(ctx, fd);
	}

	close(sock);
}

static void init_ctx(struct ctx *ctx)
{
	memset(ctx, 0, sizeof(*ctx));

	ctx->uid = getuid();
	ctx->gid = getgid();

	ctx->cpu = -1;
	ctx->packet_type = -1;

	ctx->fanout_type = PACKET_FANOUT_ROLLOVER;

	ctx->magic = ORIGINAL_TCPDUMP_MAGIC;
	ctx->print_mode = PRINT_NORM;
	ctx->pcap = PCAP_OPS_SG;

	ctx->dump_mode = DUMP_INTERVAL_TIME;
	ctx->dump_interval = 60;

	ctx->promiscuous = true;
	ctx->randomize = false;
	ctx->hwtimestamp = true;
}

static void destroy_ctx(struct ctx *ctx)
{
	free(ctx->device_in);
	free(ctx->device_out);
	free(ctx->device_trans);

	free(ctx->prefix);
}

static void __noreturn help(void)
{
	printf("netsniff-ng %s, the packet sniffing beast\n", VERSION_STRING);
	puts("http://www.netsniff-ng.org\n\n"
	     "Usage: netsniff-ng [options] [filter-expression]\n"
	     "Options:\n"
	     "  -i|-d|--dev|--in <dev|pcap|->  Input source as netdev, pcap or pcap stdin\n"
	     "  -o|--out <dev|pcap|dir|cfg|->  Output sink as netdev, pcap, directory, trafgen, or stdout\n"
	     "  -C|--fanout-group <id>         Join packet fanout group\n"
	     "  -K|--fanout-type <type>        Apply fanout discipline: hash|lb|cpu|rnd|roll|qm\n"
	     "  -L|--fanout-opts <opts>        Additional fanout options: defrag|roll\n"
	     "  -f|--filter <bpf-file|-|expr>  Use BPF filter from bpfc file/stdin or tcpdump-like expression\n"
	     "  -t|--type <type>               Filter for: host|broadcast|multicast|others|outgoing\n"
	     "  -F|--interval <size|time>      Dump interval if -o is a dir: <num>KiB/MiB/GiB/s/sec/min/hrs\n"
	     "  -R|--rfraw                     Capture or inject raw 802.11 frames\n"
	     "  -n|--num <0|uint>              Number of packets until exit (def: 0)\n"
	     "  -P|--prefix <name>             Prefix for pcaps stored in directory\n"
	     "  -O|--overwrite <N>             Limit the number of pcaps to N (file names use numbers 0 to N-1)\n"
	     "  -T|--magic <pcap-magic>        Pcap magic number/pcap format to store, see -D\n"
	     "  -w|--cooked                    Use Linux \"cooked\" header instead of link header\n"
	     "  -D|--dump-pcap-types           Dump pcap types and magic numbers and quit\n"
	     "  -B|--dump-bpf                  Dump generated BPF assembly\n"
	     "  -r|--rand                      Randomize packet forwarding order (dev->dev)\n"
	     "  -M|--no-promisc                No promiscuous mode for netdev\n"
	     "  -A|--no-sock-mem               Don't tune core socket memory\n"
	     "  -N|--no-hwtimestamp            Disable hardware time stamping\n"
	     "  -m|--mmap                      Mmap(2) pcap file I/O, e.g. for replaying pcaps\n"
	     "  -G|--sg                        Scatter/gather pcap file I/O\n"
	     "  -c|--clrw                      Use slower read(2)/write(2) I/O\n"
	     "  -S|--ring-size <size>          Specify ring size to: <num>KiB/MiB/GiB\n"
	     "  -k|--kernel-pull <uint>        Kernel pull from user interval in us (def: 10us)\n"
	     "  -J|--jumbo-support             Support replay/fwd 64KB Super Jumbo Frames (def: 2048B)\n"
	     "  -b|--bind-cpu <cpu>            Bind to specific CPU\n"
	     "  -u|--user <userid>             Drop privileges and change to userid\n"
	     "  -g|--group <groupid>           Drop privileges and change to groupid\n"
	     "  -H|--prio-high                 Make this high priority process\n"
	     "  -Q|--notouch-irq               Do not touch IRQ CPU affinity of NIC\n"
	     "  -s|--silent                    Do not print captured packets\n"
	     "  -q|--less                      Print less-verbose packet information\n"
	     "  -X|--hex                       Print packet data in hex format\n"
	     "  -l|--ascii                     Print human-readable packet data\n"
	     "  -U|--update                    Update GeoIP databases\n"
	     "  -V|--verbose                   Be more verbose\n"
	     "  -v|--version                   Show version and exit\n"
	     "  -h|--help                      Guess what?!\n\n"
	     "Examples:\n"
	     "  netsniff-ng --in eth0 --out dump.pcap -s -T 0xa1b2c3d4 --bind-cpu 0 tcp or udp\n"
	     "  netsniff-ng --in wlan0 --rfraw --out dump.pcap --silent --bind-cpu 0\n"
	     "  netsniff-ng --in dump.pcap --mmap --out eth0 -k1000 --silent --bind-cpu 0\n"
	     "  netsniff-ng --in dump.pcap --out dump.cfg --silent --bind-cpu 0\n"
	     "  netsniff-ng --in dump.pcap --out dump2.pcap --silent tcp\n"
	     "  netsniff-ng --in eth0 --out eth1 --silent --bind-cpu 0 -J --type host\n"
	     "  netsniff-ng --in eth1 --out /opt/probe/ -s -m --interval 100MiB -b 0\n"
	     "  netsniff-ng --in vlan0 --out dump.pcap -c -u `id -u bob` -g `id -g bob`\n"
	     "  netsniff-ng --in any --filter http.bpf --jumbo-support --ascii -V\n\n"
	     "Note:\n"
	     "  For introducing bit errors, delays with random variation and more\n"
	     "  while replaying pcaps, make use of tc(8) with its disciplines (e.g. netem).\n");
	puts(copyright);
	die();
}

static void __noreturn version(void)
{
	printf("netsniff-ng %s, Git id: %s\n", VERSION_LONG, GITVERSION);
	puts("the packet sniffing beast\n"
	     "http://www.netsniff-ng.org\n");
	puts(copyright);
	die();
}

int main(int argc, char **argv)
{
	char *ptr;
	int c, i, j, cpu_tmp, ops_touched = 0, vals[4] = {0};
	bool prio_high = false, setsockmem = true;
	void (*main_loop)(struct ctx *ctx) = NULL;
	struct ctx ctx;

	init_ctx(&ctx);
	start_time = time(NULL);
	srand(start_time);

	while ((c = getopt_long(argc, argv, short_options, long_options,
				NULL)) != EOF) {
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
		case 'O':
			ctx.overwrite_interval = strtoul(optarg, NULL, 0);
			break;
		case 'R':
			ctx.rfraw = 1;
			break;
		case 'r':
			ctx.randomize = true;
			break;
		case 'J':
			ctx.jumbo = true;
			break;
		case 'T':
			ctx.magic = (uint32_t) strtoul(optarg, NULL, 0);
			pcap_check_magic(ctx.magic);
			break;
		case 'f':
			ctx.filter = xstrdup(optarg);
			break;
		case 'M':
			ctx.promiscuous = false;
			break;
		case 'N':
			ctx.hwtimestamp = false;
			break;
		case 'A':
			setsockmem = false;
			break;
		case 'u':
			ctx.uid = strtoul(optarg, NULL, 0);
			ctx.enforce = true;
			break;
		case 'g':
			ctx.gid = strtoul(optarg, NULL, 0);
			ctx.enforce = true;
			break;
		case 'C':
			ctx.fanout_group = strtoul(optarg, NULL, 0);
			if (ctx.fanout_group == 0)
				panic("Non-zero fanout group id required!\n");
			break;
		case 'K':
			if (!strncmp(optarg, "hash", strlen("hash")))
				ctx.fanout_type = PACKET_FANOUT_HASH;
			else if (!strncmp(optarg, "lb", strlen("lb")) ||
				 !strncmp(optarg, "rr", strlen("rr")))
				ctx.fanout_type = PACKET_FANOUT_LB;
			else if (!strncmp(optarg, "cpu", strlen("cpu")))
				ctx.fanout_type = PACKET_FANOUT_CPU;
			else if (!strncmp(optarg, "rnd", strlen("rnd")))
				ctx.fanout_type = PACKET_FANOUT_RND;
			else if (!strncmp(optarg, "roll", strlen("roll")))
				ctx.fanout_type = PACKET_FANOUT_ROLLOVER;
			else if (!strncmp(optarg, "qm", strlen("qm")))
				ctx.fanout_type = PACKET_FANOUT_QM;
			else
				panic("Unknown fanout type!\n");
			break;
		case 'L':
			if (!strncmp(optarg, "defrag", strlen("defrag")))
				ctx.fanout_type |= PACKET_FANOUT_FLAG_DEFRAG;
			else if (!strncmp(optarg, "roll", strlen("roll")))
				ctx.fanout_type |= PACKET_FANOUT_FLAG_ROLLOVER;
			else
				panic("Unknown fanout option!\n");
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

			ctx.reserve_size *= strtoul(optarg, NULL, 0);
			break;
		case 'b':
			cpu_tmp = strtol(optarg, NULL, 0);

			cpu_affinity(cpu_tmp);
			if (ctx.cpu != -2)
				ctx.cpu = cpu_tmp;
			break;
		case 'H':
			prio_high = true;
			break;
		case 'c':
			ctx.pcap = PCAP_OPS_RW;
			ops_touched = 1;
			break;
		case 'm':
			ctx.pcap = PCAP_OPS_MM;
			ops_touched = 1;
			break;
		case 'G':
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
			ctx.kpull = strtoul(optarg, NULL, 0);
			break;
		case 'n':
			frame_count_max = strtoul(optarg, NULL, 0);
			break;
		case 'F':
			ptr = optarg;
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

			ctx.dump_interval *= strtoul(optarg, NULL, 0);
			break;
		case 'V':
			ctx.verbose = true;
			break;
		case 'B':
			ctx.dump_bpf = true;
			break;
		case 'D':
			pcap_dump_type_features();
			die();
			break;
		case 'U':
			update_geoip();
			die();
			break;
		case 'w':
			ctx.link_type = LINKTYPE_LINUX_SLL;
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
			case 'O':
			case 'F':
			case 'n':
			case 'S':
			case 'b':
			case 'k':
			case 'T':
			case 'u':
			case 'g':
			case 'e':
				panic("Option -%c requires an argument!\n",
				      optopt);
			default:
				if (isprint(optopt))
					printf("Unknown option character `0x%X\'!\n", optopt);
				die();
			}
		default:
			break;
		}
	}

	if (!ctx.filter && optind != argc)
		ctx.filter = argv2str(optind, argc, argv);

	if (!ctx.device_in)
		ctx.device_in = xstrdup("any");

	if (!strcmp(ctx.device_in, "any") || !strcmp(ctx.device_in, "lo"))
		ctx.lo_ifindex = device_ifindex("lo");

	if (!ctx.prefix)
		ctx.prefix = xstrdup("dump-");

	register_signal(SIGINT, signal_handler);
	register_signal(SIGQUIT, signal_handler);
	register_signal(SIGTERM, signal_handler);
	register_signal(SIGHUP, signal_handler);

	tprintf_init();

	if (prio_high) {
		set_proc_prio(-20);
		set_sched_status(SCHED_FIFO, sched_get_priority_max(SCHED_FIFO));
	}

	if (device_mtu(ctx.device_in) || !strncmp("any", ctx.device_in, strlen(ctx.device_in))) {
		if (ctx.rfraw)
			setup_rfmon_mac80211_dev(&ctx, &ctx.device_in);

		if (!ctx.link_type)
			ctx.link_type = pcap_dev_to_linktype(ctx.device_in);
		if (link_has_sll_hdr(ctx.link_type)) {
			switch (ctx.magic) {
			case ORIGINAL_TCPDUMP_MAGIC:
				ctx.magic = ORIGINAL_TCPDUMP_MAGIC_LL;
				break;
			case NSEC_TCPDUMP_MAGIC:
				ctx.magic = NSEC_TCPDUMP_MAGIC_LL;
				break;
			case ___constant_swab32(ORIGINAL_TCPDUMP_MAGIC):
				ctx.magic = ___constant_swab32(ORIGINAL_TCPDUMP_MAGIC_LL);
				break;
			case ___constant_swab32(NSEC_TCPDUMP_MAGIC):
				ctx.magic = ___constant_swab32(NSEC_TCPDUMP_MAGIC_LL);
				break;
			}
		}


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
				ctx.pcap = PCAP_OPS_MM;
		} else {
			setsockmem = false;
			main_loop = read_pcap;
			if (!ops_touched)
				ctx.pcap = PCAP_OPS_SG;
		}
	}

	bug_on(!main_loop);

	init_geoip(0);
	if (setsockmem)
		set_system_socket_memory(vals, array_size(vals));
	if (!ctx.enforce)
		xlockme();

	if (ctx.verbose)
		printf("pcap file I/O method: %s\n", pcap_ops_group_to_str[ctx.pcap]);

	main_loop(&ctx);

	if (!ctx.enforce)
		xunlockme();
	if (setsockmem)
		reset_system_socket_memory(vals, array_size(vals));
	destroy_geoip();

	device_restore_irq_affinity_list();
	tprintf_cleanup();

	destroy_ctx(&ctx);
	return 0;
}

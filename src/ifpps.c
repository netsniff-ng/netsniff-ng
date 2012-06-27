/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 *
 * A tiny tool to provide top-like reliable networking statistics.
 * Why? Well, some time ago I used iptraf to display network traffic
 * statistics. During that time and probably also today, they are
 * using libpcap to collect statistics. Well, bad idea since this
 * will give you false statistics on high I/O load. Therefore, ifpps
 * reads out the 'real' kernel statistics, so things your NIC sees
 * and not some userland library.
 *
 *   He had all the injured air of a liar suspected when for once he
 *   has told the truth, or part of it.
 *
 *     -- The Lord of the Rings, On Gollum,
 *        Chapter 'The Black Gate is Closed'.
 */

/*

=head1 NAME

ifpps - fetch and format kernel network statistics

=head1 SYNOPSIS

ifpps	-d|--dev <netdev> [-t|--interval <sec>][-p|--promisc][-c|--term]
	[-C|--csv][-H|--csv-tablehead][-l|--loop][-v|--version][-h|--help]

=head1 DESCRIPTION

A tiny tool to provide top-like reliable networking statistics.
ifpps reads out the 'real' kernel statistics, so it does not give erroneous
statistics on high I/O load.

=head1 OPTIONS

=over

=item ifpps --dev eth0

Fetch eth0 interface statistics.

=item ifpps --dev eth0 --interval 60 --csv

Output eth0 interface statistics every minute in CSV format.

=back

=head1 OPTIONS

=over

=item -h|--help

Print help text and lists all options.

=item -v|--version

Print version.

=item -d|--dev <netdev>

Device to fetch statistics for i.e., eth0.

=item -p|--promisc

Put the device in promiscuous mode

=item -t|--interval <time>

Refresh time in sec (default 1 sec)

=item -c|--term

Output to terminal

=item -C|--csv

Output in CSV format.
E.g. post-processing with Gnuplot et al.

=item -H|--csv-tablehead

Print CSV table head.

=item -l|--loop

Loop terminal output.

=back

=head1 AUTHOR

Written by Daniel Borkmann <daniel@netsniff-ng.org>

=head1 DOCUMENTATION

Documentation by Emmanuel Roullit <emmanuel@netsniff-ng.org>

=head1 BUGS

Please report bugs to <bugs@netsniff-ng.org>

=cut

*/

#include <stdio.h>
#include <string.h>
#include <curses.h>
#include <getopt.h>
#include <ctype.h>
#include <sys/socket.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "die.h"
#include "xmalloc.h"
#include "xutils.h"
#include "xio.h"
#include "built_in.h"

/*
 * TODO: Cleanups, this got quite a hack over time.
 */

#define TERM_MODE_NORMAL  1
#define TERM_MODE_CSV     2
#define TERM_MODE_CSV_HDR 4

#define USER_HZ sysconf(_SC_CLK_TCK)

struct ifstat {
	unsigned long rx_bytes;
	unsigned long rx_packets;
	unsigned long rx_drops;
	unsigned long rx_errors;
	unsigned long rx_fifo;
	unsigned long rx_frame;
	unsigned long rx_multi;
	unsigned long tx_bytes;
	unsigned long tx_packets;
	unsigned long tx_drops;
	unsigned long tx_errors;
	unsigned long tx_fifo;
	unsigned long tx_colls;
	unsigned long tx_carrier;
	unsigned long irq_nr;
	unsigned long *irqs;
	unsigned long *irqs_srx;
	unsigned long *irqs_stx;
	unsigned long *cpu_user;
	unsigned long *cpu_nice;
	unsigned long *cpu_sys;
	unsigned long *cpu_idle;
	unsigned long *cpu_iow;
	unsigned long ctxt;
	unsigned long forks;
	unsigned long procs_run;
	unsigned long procs_iow;
	size_t irqs_len;
	float mem_used;
	int wifi_bitrate;
	int wifi_link_qual;
	int wifi_link_qual_max;
	int wifi_signal_level;
	int wifi_noise_level;
};

static int mode = 0;
static int loop = 0;

volatile sig_atomic_t sigint = 0;

static const char *short_options = "d:t:vhcCHlp";

static struct option long_options[] = {
	{"dev", required_argument, 0, 'd'},
	{"interval", required_argument, 0, 't'},
	{"loop", no_argument, 0, 'l'},
	{"term", no_argument, 0, 'c'},
	{"promisc", no_argument, 0, 'p'},
	{"csv", no_argument, 0, 'C'},
	{"csv-tablehead", no_argument, 0, 'H'},
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

static int rxtx_stats(const char *ifname, struct ifstat *s)
{
	int ret, found = -1;
	char *ptr;
	char buf[1024];

	FILE *fp = fopen("/proc/net/dev", "r");
	if (!fp) {
		whine("Cannot open /proc/net/dev!\n");
		return -ENOENT;
	}

	/* Omit header */
	ptr = fgets(buf, sizeof(buf), fp);
	ptr = fgets(buf, sizeof(buf), fp);

	memset(buf, 0, sizeof(buf));
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		buf[sizeof(buf) -1] = 0;

		if (strstr(buf, ifname) == NULL)
			continue;

		ptr = buf;
		while (*ptr != ':')
			ptr++;
		ptr++;

		ret = sscanf(ptr, "%lu%lu%lu%lu%lu%lu%lu%*u%lu%lu%lu%lu%lu%lu%lu",
			     &s->rx_bytes, &s->rx_packets, &s->rx_errors,
			     &s->rx_drops, &s->rx_fifo, &s->rx_frame,
			     &s->rx_multi,
			     &s->tx_bytes, &s->tx_packets, &s->tx_errors,
			     &s->tx_drops, &s->tx_fifo, &s->tx_colls,
			     &s->tx_carrier);
		if (ret == 14) {
			found = 0;
			break;
		}

		memset(buf, 0, sizeof(buf));
	}

	fclose(fp);

	return found;
}

static int wifi_stats(const char *ifname, struct ifstat *s)
{
	int ret;
	struct iw_statistics ws;

	ret = wireless_sigqual(ifname, &ws);
	if (ret != 0) {
		/* We don't want to trouble in case of eth* */
		s->wifi_bitrate = 0;
		return 0;
	}

	s->wifi_bitrate = wireless_bitrate(ifname);
	s->wifi_signal_level = adjust_dbm_level(ws.qual.updated & IW_QUAL_DBM,
						ws.qual.level);
	s->wifi_noise_level = adjust_dbm_level(ws.qual.updated & IW_QUAL_DBM,
					       ws.qual.noise);
	s->wifi_link_qual = ws.qual.qual;
	s->wifi_link_qual_max = wireless_rangemax_sigqual(ifname);

	return ret;
}

static void stats_check_alloc(struct ifstat *s)
{
	int cpus = get_number_cpus();

	if (s->irqs_len != get_number_cpus()) {
		if (s->irqs) xfree(s->irqs);
		if (s->irqs_srx) xfree(s->irqs_srx);
		if (s->irqs_stx) xfree(s->irqs_stx);
		if (s->cpu_user) xfree(s->cpu_user);
		if (s->cpu_nice) xfree(s->cpu_nice);
		if (s->cpu_sys) xfree(s->cpu_sys);
		if (s->cpu_idle) xfree(s->cpu_idle);
		if (s->cpu_iow) xfree(s->cpu_iow);

		s->irqs_srx = xzmalloc(sizeof(*(s->irqs_srx)) * cpus);
		s->irqs_stx = xzmalloc(sizeof(*(s->irqs_stx)) * cpus);
		s->irqs = xzmalloc(sizeof(*(s->irqs)) * cpus);
		s->cpu_user = xzmalloc(sizeof(*(s->cpu_user)) * cpus);
		s->cpu_nice = xzmalloc(sizeof(*(s->cpu_nice)) * cpus);
		s->cpu_sys = xzmalloc(sizeof(*(s->cpu_sys)) * cpus);
		s->cpu_idle = xzmalloc(sizeof(*(s->cpu_idle)) * cpus);
		s->cpu_iow = xzmalloc(sizeof(*(s->cpu_iow)) * cpus);
		s->irqs_len = cpus;
	}
}

static int irq_sstats(struct ifstat *s)
{
	int i, rx = 0;
	char *ptr, *ptr2;
	char buff[4096];

	FILE *fp = fopen("/proc/softirqs", "r");
	if (!fp) {
		whine("Cannot open /proc/softirqs!\n");
		return -ENOENT;
	}

	stats_check_alloc(s);

	memset(buff, 0, sizeof(buff));
	while (fgets(buff, sizeof(buff), fp) != NULL) {
		buff[sizeof(buff) - 1] = 0;

		if ((ptr = strstr(buff, "NET_TX:")) == NULL) {
			ptr = strstr(buff, "NET_RX:");

			if (ptr == NULL)
				continue;
			rx = 1;
		} else {
			rx = 0;
		}

		ptr += strlen("NET_TX:");

		for (i = 0; i < s->irqs_len; ++i) {
			ptr++;
			while (*ptr == ' ')
				ptr++;
			ptr2 = ptr;
			while (*ptr != ' ' && *ptr != 0)
				ptr++;
			*ptr = 0;
			if (rx)
				s->irqs_srx[i] = atoi(ptr2);
			else
				s->irqs_stx[i] = atoi(ptr2);
		}

		memset(buff, 0, sizeof(buff));
	}

	fclose(fp);

	return 0;
}

static int mem_stats(struct ifstat *s)
{
	int ret;
	unsigned long total, free;
	char *ptr;
	char buff[4096];

	FILE *fp = fopen("/proc/meminfo", "r");
	if (!fp) {
		whine("Cannot open /proc/meminfo!\n");
		return -ENOENT;
	}

	memset(buff, 0, sizeof(buff));
	while (fgets(buff, sizeof(buff), fp) != NULL) {
		buff[sizeof(buff) - 1] = 0;

		if ((ptr = strstr(buff, "MemTotal:")) != NULL) {
			ptr += strlen("MemTotal:");
			ptr++;

			while (*ptr == ' ')
				ptr++;

			ret = sscanf(ptr, "%lu", &total);
			if (ret != 1)
				total = 0;
		} else if ((ptr = strstr(buff, "MemFree:")) != NULL) {
			ptr += strlen("MemFree:");
			ptr++;

			while (*ptr == ' ')
				ptr++;

			ret = sscanf(ptr, "%lu", &free);
			if (ret != 1)
				free = 0;
		}

		memset(buff, 0, sizeof(buff));
	}

	if (total > 0)
		s->mem_used = 100.f * (total - free) / total;
	else
		s->mem_used = 0.f;

	fclose(fp);

	return 0;
}

static int sys_stats(struct ifstat *s)
{
	int ret, cpu;
	char *ptr, *ptr2;
	char buff[4096];

	FILE *fp = fopen("/proc/stat", "r");
	if (!fp) {
		whine("Cannot open /proc/stat!\n");
		return -ENOENT;
	}

	stats_check_alloc(s);

	memset(buff, 0, sizeof(buff));
	while (fgets(buff, sizeof(buff), fp) != NULL) {
		buff[sizeof(buff) - 1] = 0;

		if ((ptr = strstr(buff, "cpu")) != NULL) {
			ptr += strlen("cpu");
			if (*ptr == ' ')
				goto next;
			ptr2 = ptr;

			while (*ptr != ' ' && *ptr != 0)
				ptr++;
			*ptr = 0;

			cpu = atoi(ptr2);
			if (cpu < 0 || cpu >= s->irqs_len)
				goto next;
			ptr++;

			ret = sscanf(ptr, "%lu%lu%lu%lu%lu", &s->cpu_user[cpu],
				     &s->cpu_nice[cpu], &s->cpu_sys[cpu],
				     &s->cpu_idle[cpu], &s->cpu_iow[cpu]);
			if (ret != 5)
				goto next;
		} else if ((ptr = strstr(buff, "ctxt")) != NULL) {
			ptr += strlen("ctxt");
			ptr++;

			while (*ptr == ' ')
				ptr++;

			ret = sscanf(ptr, "%lu", &s->ctxt);
			if (ret != 1)
				s->ctxt = 0;
		} else if ((ptr = strstr(buff, "processes")) != NULL) {
			ptr += strlen("processes");
			ptr++;

			while (*ptr == ' ')
				ptr++;

			ret = sscanf(ptr, "%lu", &s->forks);
			if (ret != 1)
				s->forks = 0;
		} else if ((ptr = strstr(buff, "procs_running")) != NULL) {
			ptr += strlen("procs_running");
			ptr++;

			while (*ptr == ' ')
				ptr++;

			ret = sscanf(ptr, "%lu", &s->procs_run);
			if (ret != 1)
				s->procs_run = 0;
		} else if ((ptr = strstr(buff, "procs_blocked")) != NULL) {
			ptr += strlen("procs_blocked");
			ptr++;

			while (*ptr == ' ')
				ptr++;

			ret = sscanf(ptr, "%lu", &s->procs_iow);
			if (ret != 1)
				s->procs_iow = 0;
		}
next:
		memset(buff, 0, sizeof(buff));
	}

	fclose(fp);

	return 0;
}

static int irq_stats(const char *ifname, struct ifstat *s)
{
	int i;
	char *ptr, *ptr2;
	char buff[4096];

	/* We exclude lo! */
	if (!strncmp("lo", ifname, strlen("lo")))
		return 0;

	FILE *fp = fopen("/proc/interrupts", "r");
	if (!fp) {
		whine("Cannot open /proc/interrupts!\n");
		return -ENOENT;
	}

	stats_check_alloc(s);

	memset(buff, 0, sizeof(buff));
	while (fgets(buff, sizeof(buff), fp) != NULL) {
		buff[sizeof(buff) - 1] = 0;

		if (strstr(buff, ifname) == NULL)
			continue;

		ptr = buff;
		while (*ptr != ':')
			ptr++;
		*ptr = 0;
		s->irq_nr = atoi(buff);

		bug_on(s->irq_nr == 0);

		for (i = 0; i < s->irqs_len; ++i) {
			ptr++;
			ptr2 = ptr;
			while (*ptr == ' ')
				ptr++;
			while (*ptr != ' '  && *ptr != 0)
				ptr++;
			*ptr = 0;
			s->irqs[i] = atoi(ptr2);
		}

		memset(buff, 0, sizeof(buff));
	}

	fclose(fp);

	return 0;
}

static void diff_stats(struct ifstat *old, struct ifstat *new,
		       struct ifstat *diff)
{
	int i;

	if(old->irqs_len != new->irqs_len)
		return; /* Refetch stats and take old diff! */

	diff->rx_bytes = new->rx_bytes - old->rx_bytes;
	diff->rx_packets = new->rx_packets - old->rx_packets;
	diff->rx_drops = new->rx_drops - old->rx_drops;
	diff->rx_errors = new->rx_errors - old->rx_errors;
	diff->rx_fifo = new->rx_fifo - old->rx_fifo;
	diff->rx_frame = new->rx_frame - old->rx_frame;
	diff->rx_multi = new->rx_multi - old->rx_multi;
	diff->tx_bytes = new->tx_bytes - old->tx_bytes;
	diff->tx_packets = new->tx_packets - old->tx_packets;
	diff->tx_drops = new->tx_drops - old->tx_drops;
	diff->tx_errors = new->tx_errors - old->tx_errors;
	diff->tx_fifo = new->tx_fifo - old->tx_fifo;
	diff->tx_colls = new->tx_colls - old->tx_colls;
	diff->tx_carrier = new->tx_carrier - old->tx_carrier;
	diff->wifi_signal_level = new->wifi_signal_level - old->wifi_signal_level;
	diff->wifi_noise_level = new->wifi_noise_level - old->wifi_noise_level;
	diff->wifi_link_qual = new->wifi_link_qual - old->wifi_link_qual;
	diff->ctxt = new->ctxt - old->ctxt;
	diff->forks = new->forks - old->forks;
	diff->procs_run = new->procs_run - old->procs_run;
	diff->procs_iow = new->procs_iow - old->procs_iow;

	stats_check_alloc(diff);

	diff->irq_nr = new->irq_nr;

	for (i = 0; i < diff->irqs_len; ++i) {
		diff->irqs[i] = new->irqs[i] - old->irqs[i];
		diff->irqs_srx[i] = new->irqs_srx[i] - old->irqs_srx[i];
		diff->irqs_stx[i] = new->irqs_stx[i] - old->irqs_stx[i];
		diff->cpu_user[i] = new->cpu_user[i] - old->cpu_user[i];
		diff->cpu_nice[i] = new->cpu_nice[i] - old->cpu_nice[i];
		diff->cpu_sys[i] = new->cpu_sys[i] - old->cpu_sys[i];
		diff->cpu_idle[i] = new->cpu_idle[i] - old->cpu_idle[i];
		diff->cpu_iow[i] = new->cpu_iow[i] - old->cpu_iow[i];
	}
}

static char *snr_to_str(int level)
{
	// empirical values
	if (level > 40)
		return "very good signal";
	if (level > 25 && level <= 40)
		return "good signal";
	if (level > 15 && level <= 25)
		return "poor signal";
	if (level > 10 && level <= 15)
		return "very poor signal";
	if (level <= 10)
		return "no signal";
	/* unreachable */
	return "unknown";
}

static void screen_init(WINDOW **screen)
{
	(*screen) = initscr();
	noecho();
	cbreak();
	nodelay((*screen), TRUE);
	refresh();
	wrefresh((*screen));
}

static void screen_update(WINDOW *screen, const char *ifname,
			  struct ifstat *s, struct ifstat *t,
			  int *first, double interval)
{
	int i, j = 0;

	curs_set(0);
	mvwprintw(screen, 1, 2, "Kernel net/sys statistics for %s, t=%.2lfs",
		  ifname, interval);
	attron(A_REVERSE);
	mvwprintw(screen, 3, 0,
		  "  RX: %16.3f MiB/t %10lu pkts/t %10lu drops/t %10lu errors/t  ",
		  1.f * s->rx_bytes / (1 << 20), s->rx_packets, s->rx_drops,
		  s->rx_errors);
	mvwprintw(screen, 4, 0,
		  "  TX: %16.3f MiB/t %10lu pkts/t %10lu drops/t %10lu errors/t  ",
		  1.f * s->tx_bytes / (1 << 20), s->tx_packets, s->tx_drops,
		  s->tx_errors);
	attroff(A_REVERSE);
	mvwprintw(screen, 6, 2,
		  "RX: %16.3f MiB   %10lu pkts   %10lu drops   %10lu errors",
		  1.f * t->rx_bytes / (1 << 20), t->rx_packets, t->rx_drops,
		  t->rx_errors);
	mvwprintw(screen, 7, 2,
		  "TX: %16.3f MiB   %10lu pkts   %10lu drops   %10lu errors",
		  1.f * t->tx_bytes / (1 << 20), t->tx_packets, t->tx_drops,
		  t->tx_errors);
	j = 9;
	mvwprintw(screen, j++, 2, "SYS:  %14ld cs/t %10.1f%% mem "
		  "%13ld running %10ld iowait",
		  s->ctxt, t->mem_used, t->procs_run, t->procs_iow);
	j++;
	if (s->irq_nr != 0) {
		for(i = 0; i < s->irqs_len; ++i) {
			unsigned long all = s->cpu_user[i] + s->cpu_nice[i] +
					    s->cpu_sys[i] + s->cpu_idle[i] +
					    s->cpu_iow[i];
			mvwprintw(screen, j++, 2, "CPU%d: %13.1f%% usr/t "
				  "%9.1f%% sys/t %10.1f%% idl/t %11.1f%% iow/t  ",
				  i,
				  100.f * (s->cpu_user[i] + s->cpu_nice[i]) / all,
				  100.f * s->cpu_sys[i] / all,
				  100.f * s->cpu_idle[i] /all,
				  100.f * s->cpu_iow[i] / all);
		}
		j++;
		for(i = 0; i < s->irqs_len; ++i)
			mvwprintw(screen, j++, 2, "CPU%d: %14ld irqs/t   "
				  "%15ld soirq RX/t   %15ld soirq TX/t      ",
				  i, s->irqs[i], s->irqs_srx[i], s->irqs_stx[i]);
		j++;
		for(i = 0; i < s->irqs_len; ++i)
			mvwprintw(screen, j++, 2, "CPU%d: %14ld irqs",
				  i, t->irqs[i]);
		j++;
	}
	if (t->wifi_bitrate > 0) {
		mvwprintw(screen, j++, 2, "LinkQual: %7d/%d (%d/t)          ",
			  t->wifi_link_qual, t->wifi_link_qual_max,
			  s->wifi_link_qual);
		mvwprintw(screen, j++, 2, "Signal: %8d dBm (%d dBm/t)       ",
			  t->wifi_signal_level, s->wifi_signal_level);
		mvwprintw(screen, j++, 2, "Noise:  %8d dBm (%d dBm/t)       ",
			  t->wifi_noise_level, s->wifi_noise_level);
		mvwprintw(screen, j++, 2, "SNR:    %8d dBm (%s)             ",
			  t->wifi_signal_level - t->wifi_noise_level,
			  snr_to_str(t->wifi_signal_level - t->wifi_noise_level));
		j++;
	}
	if (*first) {
		mvwprintw(screen, 2, 2, "Collecting data ...");
		*first = 0;
	} else
		mvwprintw(screen, 2, 2, "                   ");

	wrefresh(screen);
	refresh();
}

static void screen_end(void)
{
	endwin();
}

static void print_update(const char *ifname, struct ifstat *s,
			 struct ifstat *t, double interval)
{
	int i;

	printf("RX: %16.3f MiB/t %10lu Pkts/t %10lu Drops/t %10lu Errors/t\n",
	       1.f * s->rx_bytes / (1 << 20), s->rx_packets, s->rx_drops,
	       s->rx_errors);
	printf("TX: %16.3f MiB/t %10lu Pkts/t %10lu Drops/t %10lu Errors/t\n",
	       1.f * s->tx_bytes / (1 << 20), s->tx_packets, s->tx_drops,
	       s->tx_errors);
	if (s->irq_nr != 0)
		for(i = 0; i < s->irqs_len; ++i)
			printf("CPU%d: %10ld IRQs/t   "
			       "%10ld SoIRQ RX/t   "
			       "%10ld SoIRQ TX/t\n", i,
			       s->irqs[i], s->irqs_srx[i], s->irqs_stx[i]);
	if (t->wifi_bitrate > 0) {
		printf("LinkQual: %6d/%d (%d/t)\n", t->wifi_link_qual,
		       t->wifi_link_qual_max, s->wifi_link_qual);
		printf("Signal: %8d dBm (%d dBm/t)\n", t->wifi_signal_level,
		       s->wifi_signal_level);
		printf("Noise:  %8d dBm (%d dBm/t)\n", t->wifi_noise_level,
		       s->wifi_noise_level);
	}
}

static void print_update_csv(const char *ifname, struct ifstat *s,
			     struct ifstat *t, double interval)
{
	int i;

	printf("%ld,%lu,%lu,%lu,%lu,", time(0), s->rx_bytes, s->rx_packets,
	       s->rx_drops, s->rx_errors);
	printf("%lu,%lu,%lu,%lu", s->tx_bytes, s->tx_packets, s->tx_drops,
	       s->tx_errors);
	if (s->irq_nr != 0)
		for(i = 0; i < s->irqs_len; ++i)
			printf(",%ld,%ld,%ld", s->irqs[i], s->irqs_srx[i],
			       s->irqs_stx[i]);
	if (t->wifi_bitrate > 0) {
		printf(",%d,%d", t->wifi_link_qual, t->wifi_link_qual_max);
		printf(",%d", t->wifi_signal_level);
		printf(",%d", t->wifi_noise_level);
	}
	printf("\n");
}

static void print_update_csv_hdr(const char *ifname, struct ifstat *s,
				 struct ifstat *t, double interval)
{
	int i;

	printf("Unixtime,RX Byte/t,RX Pkts/t,RX Drops/t,RX Errors/t,");
	printf("TX Byte/t,TX Pkts/t,TX Drops/t,TX Errors/t");
	if (s->irq_nr != 0)
		for(i = 0; i < s->irqs_len; ++i)
			printf(",CPU%d IRQs/t,CPU%d SoIRQ RX/t,"
			       "CPU%d SoIRQ TX/t", i, i, i);
	if (t->wifi_bitrate > 0)
		printf(",LinkQual,LinkQualMax,Signal Level,Noise Level");
	printf("\n");
}

static inline int do_stats(const char *ifname, struct ifstat *s)
{
	int ret = 0;

	ret += rxtx_stats(ifname, s);
	ret += irq_stats(ifname, s);
	ret += irq_sstats(s);
	ret += sys_stats(s);
	ret += mem_stats(s);
	ret += wifi_stats(ifname, s);

	return ret;
}

static int screen_loop(const char *ifname, uint32_t interval)
{
	int ret = 0, first = 1;
	struct ifstat old, new, curr;
	WINDOW *screen = NULL;

	memset(&old, 0, sizeof(old));
	memset(&new, 0, sizeof(new));
	memset(&curr, 0, sizeof(curr));

	screen_init(&screen);

	while (!sigint) {
		if (getch() == 'q')
			goto out;

		screen_update(screen, ifname, &curr, &new, &first, interval);

		ret = do_stats(ifname, &old);
		if (ret != 0)
			goto out;

		sleep(interval);

		ret = do_stats(ifname, &new);
		if (ret != 0)
			goto out;

		diff_stats(&old, &new, &curr);
	}
out:
	screen_end();

	if (ret != 0)
		whine("Error fetching stats!\n");
	if (old.irqs)
		xfree(old.irqs);
	if (new.irqs)
		xfree(new.irqs);
	if (curr.irqs)
		xfree(curr.irqs);

	return 0;
}

static int print_loop(const char *ifname, uint32_t interval)
{
	int ret, first = 1;
	struct ifstat old, new, curr;

	memset(&old, 0, sizeof(old));
	memset(&new, 0, sizeof(new));
	memset(&curr, 0, sizeof(curr));
	do {
		ret = do_stats(ifname, &old);
		if (ret != 0)
			goto out;

		sleep(interval);

		ret = do_stats(ifname, &new);
		if (ret != 0)
			goto out;

		diff_stats(&old, &new, &curr);

		if (first && (mode & TERM_MODE_CSV_HDR) ==
		    TERM_MODE_CSV_HDR) {
			print_update_csv_hdr(ifname, &curr, &new, interval);
			first = 0;
		}

		if ((mode & TERM_MODE_CSV) == TERM_MODE_CSV)
			print_update_csv(ifname, &curr, &new, interval);
		else if ((mode & TERM_MODE_NORMAL) == TERM_MODE_NORMAL)
			print_update(ifname, &curr, &new, interval);
	} while (loop && !sigint);
out:
	if (ret != 0)
		whine("Error fetching stats!\n");
	if (old.irqs)
		xfree(old.irqs);
	if (new.irqs)
		xfree(new.irqs);
	if (curr.irqs)
		xfree(curr.irqs);

	return 0;
}

static void help(void)
{
	printf("\nifpps %s, kernel networking and system statistics\n",
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Usage: ifpps [options] || ifpps <netdev>\n");
	printf("Options:\n");
	printf("  -d|--dev <netdev>      Device to fetch statistics for i.e., eth0\n");
	printf("  -p|--promisc           Promiscuous mode\n");
	printf("  -t|--interval <time>   Refresh time in sec (default 1 s)\n");
	printf("  -c|--term              Output to terminal\n");
	printf("  -C|--csv               Output to terminal as CSV\n");
	printf("                         E.g. post-processing with Gnuplot et al.\n");
	printf("  -H|--csv-tablehead     Print CSV table head\n");
	printf("  -l|--loop              Loop terminal output\n");
	printf("  -v|--version           Print version\n");
	printf("  -h|--help              Print this help\n");
	printf("\n");
	printf("Examples:\n");
	printf("  ifpps --dev eth0\n");
	printf("  ifpps --dev eth0 --interval 60 --csv\n\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2009-2012 Daniel Borkmann <daniel@netsniff-ng.org>\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");
	die();
}

static void version(void)
{
	printf("\nifpps %s, kernel networking statistics per sec\n",
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2009-2012 Daniel Borkmann <daniel@netsniff-ng.org>\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");
	die();
}

int main(int argc, char **argv)
{
	short ifflags = 0;
	int c, opt_index, ret;
	unsigned int promisc = 0;
	char *ifname = NULL;
	uint32_t interval = 1;
	int (*main_loop)(const char *ifname, uint32_t interval) = screen_loop;

	while ((c = getopt_long(argc, argv, short_options, long_options,
	       &opt_index)) != EOF) {
		switch (c) {
		case 'h':
			help();
			break;
		case 'v':
			version();
			break;
		case 'd':
			ifname = xstrndup(optarg, IFNAMSIZ);
			break;
		case 't':
			interval = atoi(optarg);
			break;
		case 'c':
			mode |= TERM_MODE_NORMAL;
			main_loop = print_loop;
			break;
		case 'l':
			loop = 1;
			break;
		case 'p':
			promisc = 1;
			break;
		case 'C':
			mode |= TERM_MODE_CSV;
			main_loop = print_loop;
			break;
		case 'H':
			mode |= TERM_MODE_CSV_HDR;
			main_loop = print_loop;
			break;
		case '?':
			switch (optopt) {
			case 'd':
			case 't':
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

	if (argc == 1)
		help();
	if (argc == 2)
		ifname = xstrndup(argv[1], IFNAMSIZ);
	if (ifname == NULL)
		panic("No networking device given!\n");
	if (!strncmp("lo", ifname, IFNAMSIZ))
		panic("lo is not supported!\n");
	if (device_mtu(ifname) == 0)
		panic("This is no networking device!\n");
	register_signal(SIGINT, signal_handler);
	register_signal(SIGHUP, signal_handler);
	if (promisc) {
		check_for_root_maybe_die();
		ifflags = enter_promiscuous_mode(ifname);
	}
	ret = main_loop(ifname, interval);
	if (promisc)
		leave_promiscuous_mode(ifname, ifflags);
	xfree(ifname);

	return ret;
}


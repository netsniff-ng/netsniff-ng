/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
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
#include <assert.h>

#include "error_and_die.h"
#include "xmalloc.h"
#include "system.h"
#include "timespec.h"
#include "tty.h"
#include "version.h"
#include "netdev.h"
#include "signals.h"

/*
 * TODO: Maybe interesting ethtool -S stats, too?
 *       Approximation for longer intervals.
 */

#define TERM_MODE_NORMAL  1
#define TERM_MODE_CSV     2
#define TERM_MODE_CSV_HDR 4

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
	size_t irqs_len;
	int wifi_bitrate;
	int wifi_link_qual;
	int wifi_link_qual_max;
	int wifi_signal_level;
	int wifi_noise_level;
};

static int mode = 0;
static int loop = 0;

static sig_atomic_t sigint = 0;

static const char *short_options = "d:t:vhcCHl";

static struct option long_options[] = {
	{"dev", required_argument, 0, 'd'},
	{"interval", required_argument, 0, 't'},
	{"loop", no_argument, 0, 'l'},
	{"term", no_argument, 0, 'c'},
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
	s->wifi_signal_level = adjust_dbm_level(ws.qual.level);
	s->wifi_noise_level = adjust_dbm_level(ws.qual.noise);
	s->wifi_link_qual = ws.qual.qual;
	s->wifi_link_qual_max = wireless_rangemax_sigqual(ifname);

	return ret;
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

	if (s->irqs_len != NR_CPUS) {
		if (s->irqs)
			xfree(s->irqs);
		s->irqs = xzmalloc(sizeof(*(s->irqs)) * NR_CPUS);
		s->irqs_len = NR_CPUS;
	}

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
		for (i = 0; i < s->irqs_len; ++i) {
			ptr++;
			ptr2 = ptr;
			while (*ptr == ' ')
				ptr++;
			while (*ptr != ' ')
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

	if (diff->irqs_len != NR_CPUS) {
		if (diff->irqs)
			xfree(diff->irqs);
		diff->irqs = xzmalloc(sizeof(*(diff->irqs)) * NR_CPUS);
		diff->irqs_len = NR_CPUS;
		diff->irq_nr = new->irq_nr;
	}

	for (i = 0; i < diff->irqs_len; ++i)
		diff->irqs[i] = new->irqs[i] - old->irqs[i];
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
			  struct ifstat *s, struct ifstat *t, int *first)
{
	int i, j = 0;

	curs_set(0);
	mvwprintw(screen, 1, 2, "Kernel networking statistics for %s",
		  ifname);

	mvwprintw(screen, 3, 2,
		  "RX: %16.3f MB/t %10lu Pkts/t %10lu Drops/t %10lu Errors/t",
		  1.f * s->rx_bytes / (1 << 20), s->rx_packets, s->rx_drops,
		  s->rx_errors);
	mvwprintw(screen, 4, 2,
		  "TX: %16.3f MB/t %10lu Pkts/t %10lu Drops/t %10lu Errors/t",
		  1.f * s->tx_bytes / (1 << 20), s->tx_packets, s->tx_drops,
		  s->tx_errors);

	mvwprintw(screen, 6, 2,
		  "RX: %16.3f MB   %10lu Pkts   %10lu Drops   %10lu Errors",
		  1.f * t->rx_bytes / (1 << 20), t->rx_packets, t->rx_drops,
		  t->rx_errors);
	mvwprintw(screen, 7, 2,
		  "TX: %16.3f MB   %10lu Pkts   %10lu Drops   %10lu Errors",
		  1.f * t->tx_bytes / (1 << 20), t->tx_packets, t->tx_drops,
		  t->tx_errors);
	j = 9;

	if (s->irq_nr != 0) {
		/* IRQ statistics */
		for(i = 0; i < s->irqs_len; ++i)
			mvwprintw(screen, j++, 2, "CPU%d: %10ld IRQs/t", i,
				  s->irqs[i]);
		j++;
		for(i = 0; i < s->irqs_len; ++i)
			mvwprintw(screen, j++, 2, "CPU%d: %10ld IRQs",
				  i, t->irqs[i]);
		j++;
	}

	if (t->wifi_bitrate > 0) {
		/* WiFi statistics */
		mvwprintw(screen, j++, 2, "LinkQual: %6d/%d (%d/t)           ",
			  t->wifi_link_qual, t->wifi_link_qual_max,
			  s->wifi_link_qual);
		mvwprintw(screen, j++, 2, "Signal: %8d dBm (%d dBm/t)       ",
			  t->wifi_signal_level, s->wifi_signal_level);
		mvwprintw(screen, j++, 2, "Noise:  %8d dBm (%d dBm/t)       ",
			  t->wifi_noise_level, s->wifi_noise_level);
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
			 struct ifstat *t)
{
	int i;

	printf("RX: %16.3f MB/t %10lu Pkts/t %10lu Drops/t %10lu Errors/t\n",
	       1.f * s->rx_bytes / (1 << 20), s->rx_packets, s->rx_drops,
	       s->rx_errors);
	printf("TX: %16.3f MB/t %10lu Pkts/t %10lu Drops/t %10lu Errors/t\n",
	       1.f * s->tx_bytes / (1 << 20), s->tx_packets, s->tx_drops,
	       s->tx_errors);

	if (s->irq_nr != 0)
		for(i = 0; i < s->irqs_len; ++i)
			printf("CPU%d: %10ld IRQs/t\n", i, s->irqs[i]);
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
			     struct ifstat *t)
{
	int i;

	printf("%lu,%lu,%lu,%lu,", s->rx_bytes, s->rx_packets, s->rx_drops,
	       s->rx_errors);
	printf("%lu,%lu,%lu,%lu", s->tx_bytes, s->tx_packets, s->tx_drops,
	       s->tx_errors);

	if (s->irq_nr != 0)
		for(i = 0; i < s->irqs_len; ++i)
			printf(",%ld", s->irqs[i]);
	if (t->wifi_bitrate > 0) {
		printf(",%d,%d", t->wifi_link_qual, t->wifi_link_qual_max);
		printf(",%d", t->wifi_signal_level);
		printf(",%d", t->wifi_noise_level);
	}

	printf("\n");
}

static void print_update_csv_hdr(const char *ifname, struct ifstat *s,
				 struct ifstat *t)
{
	int i;

	printf("RX Byte/t,RX Pkts/t,RX Drops/t,RX Errors/t,");
	printf("TX Byte/t,TX Pkts/t,TX Drops/t,TX Errors/t");

	if (s->irq_nr != 0)
		for(i = 0; i < s->irqs_len; ++i)
			printf(",CPU%d IRQs/t", i);
	if (t->wifi_bitrate > 0)
		printf(",LinkQual,LinkQualMax,Signal Level,Noise Level");

	printf("\n");
}

static inline int do_stats(const char *ifname, struct ifstat *s)
{
	int ret = 0;

	ret += rxtx_stats(ifname, s);
	ret += irq_stats(ifname, s);
	ret += wifi_stats(ifname, s);

	return ret;
}

static int screen_loop(const char *ifname, double interval)
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

		screen_update(screen, ifname, &curr, &new, &first);

		ret = do_stats(ifname, &old);
		if (ret != 0)
			goto out;
		xnanosleep(interval);
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

static int print_loop(const char *ifname, double interval)
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
		xnanosleep(interval);
		ret = do_stats(ifname, &new);
		if (ret != 0)
			goto out;

		diff_stats(&old, &new, &curr);

		if (first && (mode & TERM_MODE_CSV_HDR) ==
		    TERM_MODE_CSV_HDR) {
			print_update_csv_hdr(ifname, &curr, &new);
			first = 0;
		}

		if ((mode & TERM_MODE_CSV) == TERM_MODE_CSV)
			print_update_csv(ifname, &curr, &new);
		else if ((mode & TERM_MODE_NORMAL) == TERM_MODE_NORMAL)
			print_update(ifname, &curr, &new);
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
	printf("\nifpps %s, kernel networking statistics per sec\n",
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Usage: ifpps [options] || ifpps <netdev>\n");
	printf("Options:\n");
	printf("  -d|--dev <netdev>      Device to fetch statistics for\n");
	printf("  -t|--interval <time>   Refresh time in seconds as float (default 1.0)\n");
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
	printf("  ifpps --dev eth0 --interval 60 --csv\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2009, 2010 Daniel Borkmann and Emmanuel Roullit\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");

	exit(EXIT_SUCCESS);
}

static void version(void)
{
	printf("\nifpps %s, kernel networking statistics per sec\n",
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2009, 2010 Daniel Borkmann and Emmanuel Roullit\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");

	exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	int c, opt_index, ret;
	char *ifname = NULL;
	double interval = 1.0;
	int (*main_loop)(const char *ifname, double interval) = screen_loop;

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
			interval = atof(optarg);
			break;
		case 'c':
			mode |= TERM_MODE_NORMAL;
			main_loop = print_loop;
			break;
		case 'l':
			loop = 1;
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

	if (argc == 1)
		help();
	if (argc == 2)
		ifname = xstrndup(argv[1], IFNAMSIZ);
	if (ifname == NULL)
		error_and_die(EXIT_FAILURE, "No networking device given!\n");
	if (!strncmp("lo", ifname, IFNAMSIZ))
		error_and_die(EXIT_FAILURE, "lo is not supported!\n");
	if (device_mtu(ifname) == 0)
		error_and_die(EXIT_FAILURE, "This is no networking device!\n");

	register_signal(SIGINT, signal_handler);
	register_signal(SIGHUP, signal_handler);
	register_signal(SIGSEGV, muntrace_handler);

	ret = main_loop(ifname, interval);

	xfree(ifname);
	return ret;
}


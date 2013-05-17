/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009 - 2013 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <string.h>
#include <curses.h>
#include <getopt.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/fsuid.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "die.h"
#include "xmalloc.h"
#include "xutils.h"
#include "xio.h"
#include "built_in.h"

struct wifi_stat {
	uint32_t bitrate;
	int16_t link_qual, link_qual_max;
	int signal_level /*, noise_level*/;
};

struct ifstat {
	long long unsigned int rx_bytes, rx_packets, rx_drops, rx_errors;
	long long unsigned int rx_fifo, rx_frame, rx_multi;
	long long unsigned int tx_bytes, tx_packets, tx_drops, tx_errors;
	long long unsigned int tx_fifo, tx_colls, tx_carrier;
	long long unsigned int irqs[MAX_CPUS], irqs_srx[MAX_CPUS], irqs_stx[MAX_CPUS];
	int64_t cpu_user[MAX_CPUS], cpu_nice[MAX_CPUS], cpu_sys[MAX_CPUS];
	int64_t cpu_idle[MAX_CPUS], cpu_iow[MAX_CPUS], mem_free, mem_total;
	uint32_t irq_nr, procs_run, procs_iow, cswitch, forks;
	struct wifi_stat wifi;
};

volatile sig_atomic_t sigint = 0;

static struct ifstat stats_old, stats_new, stats_delta;

static int stats_loop = 0;

static WINDOW *stats_screen = NULL;

static const char *short_options = "d:t:vhclp";
static const struct option long_options[] = {
	{"dev",			required_argument,	NULL, 'd'},
	{"interval",		required_argument,	NULL, 't'},
	{"promisc",		no_argument,		NULL, 'p'},
	{"csv",			no_argument,		NULL, 'c'},
	{"loop",		no_argument,		NULL, 'l'},
	{"version",		no_argument,		NULL, 'v'},
	{"help",		no_argument,		NULL, 'h'},
	{NULL, 0, NULL, 0}
};

static void signal_handler(int number)
{
	switch (number) {
	case SIGINT:
		sigint = 1;
		break;
	case SIGHUP:
	default:
		break;
	}
}

static inline char *snr_to_str(int level)
{
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

	return "unknown";
}

static inline int iswireless(const struct ifstat *stats)
{
	return stats->wifi.bitrate > 0;
}

static void __noreturn help(void)
{
	printf("\nifpps %s, top-like kernel networking and system statistics\n",
	       VERSION_STRING);
	puts("http://www.netsniff-ng.org\n\n"
	     "Usage: ifpps [options] || ifpps <netdev>\n"
	     "Options:\n"
	     "  -d|--dev <netdev>      Device to fetch statistics for e.g., eth0\n"
	     "  -t|--interval <time>   Refresh time in ms (default 1000 ms)\n"
	     "  -p|--promisc           Promiscuous mode\n"
	     "  -c|--csv               Output to terminal as Gnuplot-ready data\n"
	     "  -l|--loop              Continuous CSV output\n"
	     "  -v|--version           Print version and exit\n"
	     "  -h|--help              Print this help and exit\n\n"
	     "Examples:\n"
	     "  ifpps eth0\n"
	     "  ifpps -pd eth0\n"
	     "  ifpps -lpcd wlan0 > plot.dat\n\n"
	     "Note:\n"
	     "  On 10G cards, RX/TX statistics are usually accumulated each > 1sec.\n"
	     "  Thus, in those situations, it's good to use a -t of 10sec.\n\n"
	     "Please report bugs to <bugs@netsniff-ng.org>\n"
	     "Copyright (C) 2009-2013 Daniel Borkmann <dborkma@tik.ee.ethz.ch>\n"
	     "Swiss federal institute of technology (ETH Zurich)\n"
	     "License: GNU GPL version 2.0\n"
	     "This is free software: you are free to change and redistribute it.\n"
	     "There is NO WARRANTY, to the extent permitted by law.\n");
	die();
}

static void __noreturn version(void)
{
	printf("\nifpps %s, top-like kernel networking and system statistics\n",
	       VERSION_STRING);
	puts("http://www.netsniff-ng.org\n\n"
	     "Please report bugs to <bugs@netsniff-ng.org>\n"
	     "Copyright (C) 2009-2013 Daniel Borkmann <dborkma@tik.ee.ethz.ch>\n"
	     "Swiss federal institute of technology (ETH Zurich)\n"
	     "License: GNU GPL version 2.0\n"
	     "This is free software: you are free to change and redistribute it.\n"
	     "There is NO WARRANTY, to the extent permitted by law.\n");
	die();
}

static int stats_proc_net_dev(const char *ifname, struct ifstat *stats)
{
	int ret = -EINVAL;
	char buff[256];
	FILE *fp;

	fp = fopen("/proc/net/dev", "r");
	if (!fp)
		panic("Cannot open /proc/net/dev!\n");

	if (fgets(buff, sizeof(buff), fp)) { ; }
	if (fgets(buff, sizeof(buff), fp)) { ; }

	memset(buff, 0, sizeof(buff));

	while (fgets(buff, sizeof(buff), fp) != NULL) {
		buff[sizeof(buff) -1] = 0;

		if (strstr(buff, ifname) == NULL)
			continue;

		if (sscanf(buff, "%*[a-z0-9 .-]:%llu%llu%llu%llu%llu%llu"
			   "%llu%*u%llu%llu%llu%llu%llu%llu%llu",
			   &stats->rx_bytes, &stats->rx_packets,
			   &stats->rx_errors, &stats->rx_drops,
			   &stats->rx_fifo, &stats->rx_frame,
			   &stats->rx_multi, &stats->tx_bytes,
			   &stats->tx_packets, &stats->tx_errors,
			   &stats->tx_drops, &stats->tx_fifo,
			   &stats->tx_colls, &stats->tx_carrier) == 14) {
			ret = 0;
			break;
		}

		memset(buff, 0, sizeof(buff));
	}

	fclose(fp);
	return ret;
}

static int stats_proc_interrupts(char *ifname, struct ifstat *stats)
{
	int ret = -EINVAL, i, cpus, try = 0;
	char *ptr, buff[256];
	struct ethtool_drvinfo drvinf;
	FILE *fp;

	fp = fopen("/proc/interrupts", "r");
	if (!fp)
		panic("Cannot open /proc/interrupts!\n");

	cpus = get_number_cpus();
	bug_on(cpus > MAX_CPUS);
retry:
	fseek(fp, 0, SEEK_SET);
	memset(buff, 0, sizeof(buff));

	while (fgets(buff, sizeof(buff), fp) != NULL) {
		buff[sizeof(buff) - 1] = 0;
		ptr = buff;

		if (strstr(buff, ifname) == NULL)
			continue;

		stats->irq_nr = strtol(ptr, &ptr, 10);
		bug_on(stats->irq_nr == 0);

		if (ptr)
			ptr++;
		for (i = 0; i < cpus && ptr; ++i) {
			stats->irqs[i] = strtol(ptr, &ptr, 10);
			if (i == cpus - 1) {
				ret = 0;
				goto done;
			}
		}

		memset(buff, 0, sizeof(buff));
	}

	if (ret == -EINVAL && try == 0) {
		memset(&drvinf, 0, sizeof(drvinf));
		if (ethtool_drvinf(ifname, &drvinf) < 0)
			goto done;

		ifname = drvinf.driver;
		try++;

		goto retry;
	}
done:
	fclose(fp);
	return ret;
}

static int stats_proc_softirqs(struct ifstat *stats)
{
	int i, cpus;
	char *ptr, buff[256];
	FILE *fp;
	enum {
		softirqs_net_rx,
		softirqs_net_tx,
	} net_type;

	fp = fopen("/proc/softirqs", "r");
	if (!fp)
		panic("Cannot open /proc/softirqs!\n");

	cpus = get_number_cpus();
	bug_on(cpus > MAX_CPUS);

	memset(buff, 0, sizeof(buff));

	while (fgets(buff, sizeof(buff), fp) != NULL) {
		buff[sizeof(buff) - 1] = 0;

		if ((ptr = strstr(buff, "NET_TX:")))
			net_type = softirqs_net_tx;
		else if ((ptr = strstr(buff, "NET_RX:")))
			net_type = softirqs_net_rx;
		else
			continue;

		for (ptr += strlen("NET_xX:"), i = 0; i < cpus; ++i) {
			switch (net_type) {
			case softirqs_net_tx:
				stats->irqs_stx[i] = strtol(ptr, &ptr, 10);
				break;
			case softirqs_net_rx:
				stats->irqs_srx[i] = strtol(ptr, &ptr, 10);
				break;
			}
		}

		memset(buff, 0, sizeof(buff));
	}

	fclose(fp);
	return 0;
}

static int stats_proc_memory(struct ifstat *stats)
{
	char *ptr, buff[256];
	FILE *fp;

	fp = fopen("/proc/meminfo", "r");
	if (!fp)
		panic("Cannot open /proc/meminfo!\n");

	memset(buff, 0, sizeof(buff));

	while (fgets(buff, sizeof(buff), fp) != NULL) {
		buff[sizeof(buff) - 1] = 0;

		if ((ptr = strstr(buff, "MemTotal:"))) {
			ptr += strlen("MemTotal:");
			stats->mem_total = strtol(ptr, &ptr, 10);
		} else if ((ptr = strstr(buff, "MemFree:"))) {
			ptr += strlen("MemFree:");
			stats->mem_free = strtol(ptr, &ptr, 10);
		}

		memset(buff, 0, sizeof(buff));
	}

	fclose(fp);
	return 0;
}

static int stats_proc_system(struct ifstat *stats)
{
	int cpu, cpus;
	char *ptr, buff[256];
	FILE *fp;

	fp = fopen("/proc/stat", "r");
	if (!fp)
		panic("Cannot open /proc/stat!\n");

	cpus = get_number_cpus();
	bug_on(cpus > MAX_CPUS);

	memset(buff, 0, sizeof(buff));

	while (fgets(buff, sizeof(buff), fp) != NULL) {
		buff[sizeof(buff) - 1] = 0;

		if ((ptr = strstr(buff, "cpu"))) {
			ptr += strlen("cpu");
			if (isblank(*ptr))
				goto next;

			cpu = strtol(ptr, &ptr, 10);
			bug_on(cpu > cpus);

			if (sscanf(ptr, "%lu%lu%lu%lu%lu",
				   &stats->cpu_user[cpu],
				   &stats->cpu_nice[cpu],
				   &stats->cpu_sys[cpu],
				   &stats->cpu_idle[cpu],
				   &stats->cpu_iow[cpu]) != 5)
				goto next;
		} else if ((ptr = strstr(buff, "ctxt"))) {
			ptr += strlen("ctxt");
			stats->cswitch = strtoul(ptr, &ptr, 10);
		} else if ((ptr = strstr(buff, "processes"))) {
			ptr += strlen("processes");
			stats->forks = strtoul(ptr, &ptr, 10);
		} else if ((ptr = strstr(buff, "procs_running"))) {
			ptr += strlen("procs_running");
			stats->procs_run = strtoul(ptr, &ptr, 10);
		} else if ((ptr = strstr(buff, "procs_blocked"))) {
			ptr += strlen("procs_blocked");
			stats->procs_iow = strtoul(ptr, &ptr, 10);
		}
next:
		memset(buff, 0, sizeof(buff));
	}

	fclose(fp);
	return 0;
}

static int adjust_dbm_level(int in_dbm, int dbm_val)
{
	if (!in_dbm)
		return dbm_val;

	return dbm_val - 0x100;
}

static int stats_wireless(const char *ifname, struct ifstat *stats)
{
	int ret;
	struct iw_statistics ws;

	ret = wireless_sigqual(ifname, &ws);
	if (ret != 0) {
		stats->wifi.bitrate = 0;
		return -EINVAL;
	}

	stats->wifi.bitrate = wireless_bitrate(ifname);

	stats->wifi.signal_level =
		adjust_dbm_level(ws.qual.updated & IW_QUAL_DBM, ws.qual.level);

	stats->wifi.link_qual = ws.qual.qual;
	stats->wifi.link_qual_max = wireless_rangemax_sigqual(ifname);

	return ret;
}

#define DIFF1(member)	do { diff->member = new->member - old->member; } while (0)
#define DIFF(member)	do { \
		if (sizeof(diff->member) != sizeof(new->member) || \
		    sizeof(diff->member) != sizeof(old->member)) \
			bug(); \
		bug_on((new->member - old->member) > (new->member)); \
		DIFF1(member); \
	} while (0)

static void stats_diff(struct ifstat *old, struct ifstat *new,
		       struct ifstat *diff)
{
	int cpus, i;

	DIFF(rx_bytes);
	DIFF(rx_packets);
	DIFF(rx_drops);
	DIFF(rx_errors);
	DIFF(rx_fifo);
	DIFF(rx_frame);
	DIFF(rx_multi);

	DIFF(tx_bytes);
	DIFF(tx_bytes);
	DIFF(tx_packets);
	DIFF(tx_drops);
	DIFF(tx_errors);
	DIFF(tx_fifo);
	DIFF(tx_colls);
	DIFF(tx_carrier);

	DIFF1(procs_run);
	DIFF1(procs_iow);

	DIFF1(wifi.signal_level);
	DIFF1(wifi.link_qual);

	DIFF1(cswitch);
	DIFF1(forks);

	cpus = get_number_cpus();
	bug_on(cpus > MAX_CPUS);

	for (i = 0; i < cpus; ++i) {
		DIFF(irqs[i]);
		DIFF(irqs_srx[i]);
		DIFF(irqs_stx[i]);

		DIFF1(cpu_user[i]);
		DIFF1(cpu_nice[i]);
		DIFF1(cpu_sys[i]);
		DIFF1(cpu_idle[i]);
		DIFF1(cpu_iow[i]);
	}
}

static void stats_fetch(const char *ifname, struct ifstat *stats)
{
	if (stats_proc_net_dev(ifname, stats) < 0)
		panic("Cannot fetch device stats!\n");
	if (stats_proc_softirqs(stats) < 0)
		panic("Cannot fetch software interrupts!\n");
	if (stats_proc_memory(stats) < 0)
		panic("Cannot fetch memory stats!\n");
	if (stats_proc_system(stats) < 0)
		panic("Cannot fetch system stats!\n");

	stats_proc_interrupts((char *) ifname, stats);

	stats_wireless(ifname, stats);
}

static void stats_sample_generic(const char *ifname, uint64_t ms_interval)
{
	memset(&stats_old, 0, sizeof(stats_old));
	memset(&stats_new, 0, sizeof(stats_new));
	memset(&stats_delta, 0, sizeof(stats_delta));

	stats_fetch(ifname, &stats_old);
	usleep(ms_interval * 1000);
	stats_fetch(ifname, &stats_new);

	stats_diff(&stats_old, &stats_new, &stats_delta);
}

static void screen_init(WINDOW **screen)
{
	(*screen) = initscr();

	raw();
	noecho();
	cbreak();
	nodelay((*screen), TRUE);

	keypad(stdscr, TRUE);

	refresh();
	wrefresh((*screen));
}

static void screen_header(WINDOW *screen, const char *ifname, int *voff,
			  uint64_t ms_interval)
{
	size_t len = 0;
	char buff[64];
	struct ethtool_drvinfo drvinf;
	u32 rate = device_bitrate(ifname);
	int link = ethtool_link(ifname);

	memset(&drvinf, 0, sizeof(drvinf));
	ethtool_drvinf(ifname, &drvinf);

	memset(buff, 0, sizeof(buff));
	if (rate)
		len += snprintf(buff + len, sizeof(buff) - len, " %uMbit/s", rate);
	if (link >= 0)
		len += snprintf(buff + len, sizeof(buff) - len, " link:%s",
				link == 0 ? "no" : "yes");

	mvwprintw(screen, (*voff)++, 2,
		  "Kernel net/sys statistics for %s (%s%s), t=%lums"
		  "               ",
		  ifname, drvinf.driver, buff, ms_interval);
}

static void screen_net_dev_rel(WINDOW *screen, const struct ifstat *rel,
			       int *voff)
{
	attron(A_REVERSE);

	mvwprintw(screen, (*voff)++, 0,
		  "  RX: %16.3llf MiB/t "
		        "%10llu pkts/t "
			"%10llu drops/t "
			"%10llu errors/t  ",
		  ((long double) rel->rx_bytes) / (1LLU << 20),
		  rel->rx_packets, rel->rx_drops, rel->rx_errors);

	mvwprintw(screen, (*voff)++, 0,
		  "  TX: %16.3llf MiB/t "
			"%10llu pkts/t "
			"%10llu drops/t "
			"%10llu errors/t  ",
		  ((long double) rel->tx_bytes) / (1LLU << 20),
		  rel->tx_packets, rel->tx_drops, rel->tx_errors);

	attroff(A_REVERSE);
}

static void screen_net_dev_abs(WINDOW *screen, const struct ifstat *abs,
			       int *voff)
{
	mvwprintw(screen, (*voff)++, 2,
		  "RX: %16.3llf MiB   "
		      "%10llu pkts   "
		      "%10llu drops   "
		      "%10llu errors",
		  ((long double) abs->rx_bytes) / (1LLU << 20),
		  abs->rx_packets, abs->rx_drops, abs->rx_errors);

	mvwprintw(screen, (*voff)++, 2,
		  "TX: %16.3llf MiB   "
		      "%10llu pkts   "
		      "%10llu drops   "
		      "%10llu errors",
		  ((long double) abs->tx_bytes) / (1LLU << 20),
		  abs->tx_packets, abs->tx_drops, abs->tx_errors);
}

static void screen_sys_mem(WINDOW *screen, const struct ifstat *rel,
			   const struct ifstat *abs, int *voff)
{
	mvwprintw(screen, (*voff)++, 2,
		  "SYS:  %14u cs/t "
			"%10.1lf%% mem "
			"%13u running "
			"%10u iowait",
		  rel->cswitch,
		  (100.0 * (abs->mem_total - abs->mem_free)) / abs->mem_total,
		  abs->procs_run, abs->procs_iow);
}

static void screen_percpu_states(WINDOW *screen, const struct ifstat *rel,
				 int cpus, int *voff)
{
	int i;
	uint64_t all;

	for (i = 0; i < cpus; ++i) {
		all = rel->cpu_user[i] + rel->cpu_nice[i] + rel->cpu_sys[i] +
		      rel->cpu_idle[i] + rel->cpu_iow[i];

		mvwprintw(screen, (*voff)++, 2,
			  "CPU%d: %13.1lf%% usr/t "
				 "%9.1lf%% sys/t "
				 "%10.1lf%% idl/t "
				 "%11.1lf%% iow/t  ", i,
			  100.0 * (rel->cpu_user[i] + rel->cpu_nice[i]) / all,
			  100.0 * rel->cpu_sys[i] / all,
			  100.0 * rel->cpu_idle[i] / all,
			  100.0 * rel->cpu_iow[i] / all);
	}
}

static void screen_percpu_irqs_rel(WINDOW *screen, const struct ifstat *rel,
				   int cpus, int *voff)
{
	int i;

	for (i = 0; i < cpus; ++i) {
		mvwprintw(screen, (*voff)++, 2,
			  "CPU%d: %14llu irqs/t   "
				 "%15llu soirq RX/t   "
				 "%15llu soirq TX/t      ", i,
			  rel->irqs[i],
			  rel->irqs_srx[i],
			  rel->irqs_stx[i]);
	}
}

static void screen_percpu_irqs_abs(WINDOW *screen, const struct ifstat *abs,
				   int cpus, int *voff)
{
	int i;

	for (i = 0; i < cpus; ++i) {
		mvwprintw(screen, (*voff)++, 2,
			  "CPU%d: %14llu irqs", i,
			  abs->irqs[i]);
	}
}

static void screen_wireless(WINDOW *screen, const struct ifstat *rel,
			    const struct ifstat *abs, int *voff)
{
	if (iswireless(abs)) {
		mvwprintw(screen, (*voff)++, 2,
			  "LinkQual: %7d/%d (%d/t)          ",
			  abs->wifi.link_qual,
			  abs->wifi.link_qual_max,
			  rel->wifi.link_qual);

		mvwprintw(screen, (*voff)++, 2,
			  "Signal: %8d dBm (%d dBm/t)       ",
			  abs->wifi.signal_level,
			  rel->wifi.signal_level);
	}
}

static void screen_update(WINDOW *screen, const char *ifname, const struct ifstat *rel,
			  const struct ifstat *abs, int *first, uint64_t ms_interval)
{
	int cpus, voff = 1, cvoff = 2;

	curs_set(0);

	cpus = get_number_cpus();
	bug_on(cpus > MAX_CPUS);

	screen_header(screen, ifname, &voff, ms_interval);

	voff++;
	screen_net_dev_rel(screen, rel, &voff);

	voff++;
	screen_net_dev_abs(screen, abs, &voff);

	voff++;
	screen_sys_mem(screen, rel, abs, &voff);

	voff++;
	screen_percpu_states(screen, rel, cpus, &voff);

	voff++;
	screen_percpu_irqs_rel(screen, rel, cpus, &voff);

	voff++;
	screen_percpu_irqs_abs(screen, abs, cpus, &voff);

	voff++;
	screen_wireless(screen, rel, abs, &voff);

	if (*first) {
		mvwprintw(screen, cvoff, 2, "Collecting data ...");
		*first = 0;
	} else {
		mvwprintw(screen, cvoff, 2, "                   ");
	}

	wrefresh(screen);
	refresh();
}

static void screen_end(void)
{
	endwin();
}

static int screen_main(const char *ifname, uint64_t ms_interval)
{
	int first = 1, key;

	screen_init(&stats_screen);

	while (!sigint) {
		key = getch();
		if (key == 'q' || key == 0x1b || key == KEY_F(10))
			break;

		screen_update(stats_screen, ifname, &stats_delta, &stats_new,
			      &first, ms_interval);

		stats_sample_generic(ifname, ms_interval);
	}

	screen_end();

	return 0;
}

static void term_csv(const char *ifname, const struct ifstat *rel,
		     const struct ifstat *abs, uint64_t ms_interval)
{
	int cpus, i;

	printf("%ld ", time(0));

	printf("%llu ", rel->rx_bytes);
	printf("%llu ", rel->rx_packets);
	printf("%llu ", rel->rx_drops);
	printf("%llu ", rel->rx_errors);

	printf("%llu ", abs->rx_bytes);
	printf("%llu ", abs->rx_packets);
	printf("%llu ", abs->rx_drops);
	printf("%llu ", abs->rx_errors);

	printf("%llu ", rel->tx_bytes);
	printf("%llu ", rel->tx_packets);
	printf("%llu ", rel->tx_drops);
	printf("%llu ", rel->tx_errors);

	printf("%llu ", abs->tx_bytes);
	printf("%llu ", abs->tx_packets);
	printf("%llu ", abs->tx_drops);
	printf("%llu ", abs->tx_errors);

	printf("%u ",  rel->cswitch);
	printf("%lu ", abs->mem_free);
	printf("%lu ", abs->mem_total - abs->mem_free);
	printf("%lu ", abs->mem_total);
	printf("%u ",  abs->procs_run);
	printf("%u ",  abs->procs_iow);

	cpus = get_number_cpus();
	bug_on(cpus > MAX_CPUS);

	for (i = 0; i < cpus; ++i) {
		printf("%lu ", rel->cpu_user[i]);
		printf("%lu ", rel->cpu_nice[i]);
		printf("%lu ", rel->cpu_sys[i]);
		printf("%lu ", rel->cpu_idle[i]);
		printf("%lu ", rel->cpu_iow[i]);

		printf("%llu ", rel->irqs[i]);
		printf("%llu ", abs->irqs[i]);

		printf("%llu ", rel->irqs_srx[i]);
		printf("%llu ", abs->irqs_srx[i]);

		printf("%llu ", rel->irqs_stx[i]);
		printf("%llu ", abs->irqs_stx[i]);
	}

	if (iswireless(abs)) {
		printf("%u ", rel->wifi.link_qual);
		printf("%u ", abs->wifi.link_qual);
		printf("%u ", abs->wifi.link_qual_max);

		printf("%d ", rel->wifi.signal_level);
		printf("%d ", abs->wifi.signal_level);
	}

	puts("");
	fflush(stdout);
}

static void term_csv_header(const char *ifname, const struct ifstat *abs,
			    uint64_t ms_interval)
{
	int cpus, i, j = 1;

	printf("# gnuplot dump (#col:description)\n");
	printf("# networking interface: %s\n", ifname);
	printf("# sampling interval (t): %lu ms\n", ms_interval);
	printf("# %d:unixtime ", j++);

	printf("%d:rx-bytes-per-t ", j++);
	printf("%d:rx-pkts-per-t ", j++);
	printf("%d:rx-drops-per-t ", j++);
	printf("%d:rx-errors-per-t ", j++);

	printf("%d:rx-bytes ", j++);
	printf("%d:rx-pkts ", j++);
	printf("%d:rx-drops ", j++);
	printf("%d:rx-errors ", j++);

	printf("%d:tx-bytes-per-t ", j++);
	printf("%d:tx-pkts-per-t ", j++);
	printf("%d:tx-drops-per-t ", j++);
	printf("%d:tx-errors-per-t ", j++);

	printf("%d:tx-bytes ", j++);
	printf("%d:tx-pkts ", j++);
	printf("%d:tx-drops ", j++);
	printf("%d:tx-errors ", j++);

	printf("%d:context-switches-per-t ", j++);
	printf("%d:mem-free ", j++);
	printf("%d:mem-used ", j++);
	printf("%d:mem-total ", j++);
	printf("%d:procs-in-run ", j++);
	printf("%d:procs-in-iow ", j++);

	cpus = get_number_cpus();
	bug_on(cpus > MAX_CPUS);

	for (i = 0, j = 22; i < cpus; ++i) {
		printf("%d:cpu%i-usr-per-t ", j++, i);
		printf("%d:cpu%i-nice-per-t ", j++, i);
		printf("%d:cpu%i-sys-per-t ", j++, i);
		printf("%d:cpu%i-idle-per-t ", j++, i);
		printf("%d:cpu%i-iow-per-t ", j++, i);

		printf("%d:cpu%i-net-irqs-per-t ", j++, i);
		printf("%d:cpu%i-net-irqs ", j++, i);

		printf("%d:cpu%i-net-rx-soft-irqs-per-t ", j++, i);
		printf("%d:cpu%i-net-rx-soft-irqs ", j++, i);
		printf("%d:cpu%i-net-tx-soft-irqs-per-t ", j++, i);
		printf("%d:cpu%i-net-tx-soft-irqs ", j++, i);
	}

	if (iswireless(abs)) {
		printf("%d:wifi-link-qual-per-t ", j++);
		printf("%d:wifi-link-qual ", j++);
		printf("%d:wifi-link-qual-max ", j++);

		printf("%d:wifi-signal-dbm-per-t ", j++);
		printf("%d:wifi-signal-dbm ", j++);
	}

	puts("");
	printf("# data:\n");
	fflush(stdout);
}

static int term_main(const char *ifname, uint64_t ms_interval)
{
	int first = 1;

	do {
		stats_sample_generic(ifname, ms_interval);

		if (first) {
			first = 0;
			term_csv_header(ifname, &stats_new, ms_interval);
		}

		term_csv(ifname, &stats_delta, &stats_new, ms_interval);
	} while (stats_loop && !sigint);

	return 0;
}

int main(int argc, char **argv)
{
	short ifflags = 0;
	int c, opt_index, ret, promisc = 0;
	uint64_t interval = 1000;
	char *ifname = NULL;
	int (*func_main)(const char *ifname, uint64_t ms_interval) = screen_main;

	setfsuid(getuid());
	setfsgid(getgid());

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
			interval = strtol(optarg, NULL, 10);
			break;
		case 'l':
			stats_loop = 1;
			break;
		case 'p':
			promisc = 1;
			break;
		case 'c':
			func_main = term_main;
			break;
		case '?':
			switch (optopt) {
			case 'd':
			case 't':
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

	if (promisc)
		ifflags = enter_promiscuous_mode(ifname);
	ret = func_main(ifname, interval);
	if (promisc)
		leave_promiscuous_mode(ifname, ifflags);

	xfree(ifname);
	return ret;
}

/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009 - 2013 Daniel Borkmann.
 * Copyright 2013 Tobias Klauser
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
#include "dev.h"
#include "sig.h"
#include "link.h"
#include "xmalloc.h"
#include "ioops.h"
#include "promisc.h"
#include "cpus.h"
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
	uint64_t mem_free, mem_total;
	uint32_t irq_nr, procs_run, procs_iow, cswitch, forks;
	struct wifi_stat wifi;
	/*
	 * Pointer members need to be last in order for stats_zero() to work
	 * properly.
	 */
	long long unsigned int *irqs, *irqs_srx, *irqs_stx;
	uint64_t *cpu_user, *cpu_sys, *cpu_nice, *cpu_idle, *cpu_iow;
};

struct cpu_hit {
	unsigned int idx;
	uint64_t hit;
	long long unsigned int irqs_rel, irqs_abs;
};

static volatile sig_atomic_t sigint = 0;
static struct ifstat stats_old, stats_new, stats_delta;
static struct cpu_hit *cpu_hits;
static int stats_loop = 0;
static WINDOW *stats_screen = NULL;

static const char *short_options = "d:t:n:vhclp";
static const struct option long_options[] = {
	{"dev",			required_argument,	NULL, 'd'},
	{"interval",		required_argument,	NULL, 't'},
	{"num-cpus",		required_argument,	NULL, 'n'},
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
	     "  -n|--num-cpus <num>    Number of top hitter CPUs to display\n"
	     "                         in ncurses mode (default 10)\n"
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
	     "Copyright (C) 2013 Tobias Klauser <tklauser@distanz.ch>\n"
	     "License: GNU GPL version 2.0\n"
	     "This is free software: you are free to change and redistribute it.\n"
	     "There is NO WARRANTY, to the extent permitted by law.\n");
	die();
}

static void __noreturn version(void)
{
	printf("\nifpps %s, top-like kernel networking and system statistics\n",
	       VERSION_LONG);
	puts("http://www.netsniff-ng.org\n\n"
	     "Please report bugs to <bugs@netsniff-ng.org>\n"
	     "Copyright (C) 2009-2013 Daniel Borkmann <dborkma@tik.ee.ethz.ch>\n"
	     "Swiss federal institute of technology (ETH Zurich)\n"
	     "Copyright (C) 2013 Tobias Klauser <tklauser@distanz.ch>\n"
	     "License: GNU GPL version 2.0\n"
	     "This is free software: you are free to change and redistribute it.\n"
	     "There is NO WARRANTY, to the extent permitted by law.\n");
	die();
}

static inline int padding_from_num(int n)
{
	int i = 0;
	do i++;
	while ((n /= 10) > 0);
	return i;
}

#define STATS_ALLOC1(member)	\
	do { stats->member = xzmalloc(cpus * sizeof(*(stats->member))); } while (0)

static void stats_alloc(struct ifstat *stats, int cpus)
{
	STATS_ALLOC1(irqs);
	STATS_ALLOC1(irqs_srx);
	STATS_ALLOC1(irqs_stx);

	STATS_ALLOC1(cpu_user);
	STATS_ALLOC1(cpu_sys);
	STATS_ALLOC1(cpu_nice);
	STATS_ALLOC1(cpu_idle);
	STATS_ALLOC1(cpu_iow);
}

#define STATS_ZERO1(member)	\
	do { memset(stats->member, 0, cpus * sizeof(*(stats->member))); } while (0)

static void stats_zero(struct ifstat *stats, int cpus)
{
	/* Only clear the non-pointer members */
	memset(stats, 0, offsetof(struct ifstat, irqs));

	STATS_ZERO1(irqs);
	STATS_ZERO1(irqs_srx);
	STATS_ZERO1(irqs_stx);

	STATS_ZERO1(cpu_user);
	STATS_ZERO1(cpu_sys);
	STATS_ZERO1(cpu_nice);
	STATS_ZERO1(cpu_idle);
	STATS_ZERO1(cpu_iow);
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
	char *ptr, *buff;
	bool seen = false;
	size_t buff_len;
	struct ethtool_drvinfo drvinf;
	FILE *fp;

	fp = fopen("/proc/interrupts", "r");
	if (!fp)
		panic("Cannot open /proc/interrupts!\n");

	cpus = get_number_cpus();
	buff_len = cpus * 128;
	buff = xmalloc(buff_len);
retry:
	fseek(fp, 0, SEEK_SET);
	memset(buff, 0, buff_len);

	while (fgets(buff, buff_len, fp) != NULL) {
		buff[buff_len - 1] = 0;
		ptr = buff;

		if (strstr(buff, ifname) == NULL)
			continue;

		/* XXX: remove this one here */
		stats->irq_nr = strtol(ptr, &ptr, 10);
		bug_on(stats->irq_nr == 0);

		if (ptr)
			ptr++;
		for (i = 0; i < cpus && ptr; ++i) {
			if (seen)
				stats->irqs[i] += strtol(ptr, &ptr, 10);
			else
				stats->irqs[i] = strtol(ptr, &ptr, 10);
			if (i == cpus - 1) {
				ret = 0;
				seen = true;
			}
		}

		memset(buff, 0, buff_len);
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
	xfree(buff);
	fclose(fp);
	return ret;
}

static int stats_proc_softirqs(struct ifstat *stats)
{
	int i, cpus;
	char *ptr, *buff;
	size_t buff_len;
	FILE *fp;
	enum {
		softirqs_net_rx,
		softirqs_net_tx,
	} net_type;

	fp = fopen("/proc/softirqs", "r");
	if (!fp)
		panic("Cannot open /proc/softirqs!\n");

	cpus = get_number_cpus();
	buff_len = cpus * 128;
	buff = xmalloc(buff_len);

	memset(buff, 0, buff_len);

	while (fgets(buff, buff_len, fp) != NULL) {
		buff[buff_len - 1] = 0;

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

		memset(buff, 0, buff_len);
	}

	xfree(buff);
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
			stats->mem_total = strtoul(ptr, &ptr, 10);
		} else if ((ptr = strstr(buff, "MemFree:"))) {
			ptr += strlen("MemFree:");
			stats->mem_free = strtoul(ptr, &ptr, 10);
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
	int cpus = get_number_cpus();

	stats_zero(&stats_old, cpus);
	stats_zero(&stats_new, cpus);
	stats_zero(&stats_delta, cpus);

	stats_fetch(ifname, &stats_old);
	usleep(ms_interval * 1000);
	stats_fetch(ifname, &stats_new);

	stats_diff(&stats_old, &stats_new, &stats_delta);
}

static int cmp_hits(const void *p1, const void *p2)
{
	const struct cpu_hit *h1 = p1, *h2 = p2;

	/*
	 * We want the hits sorted in descending order, thus reverse the return
	 * values.
	 */
	if (h1->hit == h2->hit)
		return 0;
	else if (h1->hit < h2->hit)
		return 1;
	else
		return -1;
}

static int cmp_irqs_rel(const void *p1, const void *p2)
{
	const struct cpu_hit *h1 = p1, *h2 = p2;

	/*
	 * We want the hits sorted in descending order, thus reverse the return
	 * values.
	 */
	if (h1->irqs_rel == h2->irqs_rel)
		return 0;
	else if (h1->irqs_rel < h2->irqs_rel)
		return 1;
	else
		return -1;
}

static int cmp_irqs_abs(const void *p1, const void *p2)
{
	const struct cpu_hit *h1 = p1, *h2 = p2;

	/*
	 * We want the hits sorted in descending order, thus reverse the return
	 * values.
	 */
	if (h1->irqs_abs == h2->irqs_abs)
		return 0;
	else if (h1->irqs_abs < h2->irqs_abs)
		return 1;
	else
		return -1;
}

static void stats_top(const struct ifstat *rel, const struct ifstat *abs,
		      int top_cpus)
{
	int i;

	for (i = 0; i < top_cpus; ++i) {
		cpu_hits[i].idx = i;
		cpu_hits[i].hit = rel->cpu_user[i] + rel->cpu_nice[i] + rel->cpu_sys[i];
		cpu_hits[i].irqs_rel = rel->irqs[i];
		cpu_hits[i].irqs_abs = abs->irqs[i];
	}
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
			  uint64_t ms_interval, unsigned int top_cpus)
{
	size_t len = 0;
	char buff[64];
	struct ethtool_drvinfo drvinf;
	u32 rate = device_bitrate(ifname);
	int link = ethtool_link(ifname);
	unsigned int cpus = get_number_cpus();

	memset(&drvinf, 0, sizeof(drvinf));
	ethtool_drvinf(ifname, &drvinf);

	memset(buff, 0, sizeof(buff));
	if (rate)
		len += snprintf(buff + len, sizeof(buff) - len, " %uMbit/s", rate);
	if (link >= 0)
		len += snprintf(buff + len, sizeof(buff) - len, " link:%s",
				link == 0 ? "no" : "yes");

	mvwprintw(screen, (*voff)++, 2,
		  "Kernel net/sys statistics for %s (%s%s), t=%lums, cpus=%u%s/%u"
		  "               ",
		  ifname, drvinf.driver, buff, ms_interval, top_cpus,
		  top_cpus > 0 && top_cpus < cpus ? "+1" : "", cpus);
}

static void screen_net_dev_rel(WINDOW *screen, const struct ifstat *rel,
			       int *voff)
{
	attron(A_REVERSE);

	mvwprintw(screen, (*voff)++, 0,
		  "  rx: %16.3llf MiB/t "
		        "%10llu pkts/t "
			"%10llu drops/t "
			"%10llu errors/t  ",
		  ((long double) rel->rx_bytes) / (1LLU << 20),
		  rel->rx_packets, rel->rx_drops, rel->rx_errors);

	mvwprintw(screen, (*voff)++, 0,
		  "  tx: %16.3llf MiB/t "
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
		  "rx: %16.3llf MiB   "
		      "%10llu pkts   "
		      "%10llu drops   "
		      "%10llu errors",
		  ((long double) abs->rx_bytes) / (1LLU << 20),
		  abs->rx_packets, abs->rx_drops, abs->rx_errors);

	mvwprintw(screen, (*voff)++, 2,
		  "tx: %16.3llf MiB   "
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
		  "sys:  %14u cs/t "
			"%10.1lf%% mem "
			"%13u running "
			"%10u iowait",
		  rel->cswitch,
		  (100.0 * (abs->mem_total - abs->mem_free)) / abs->mem_total,
		  abs->procs_run, abs->procs_iow);
}

static void screen_percpu_states_one(WINDOW *screen, const struct ifstat *rel,
				     int *voff, unsigned int idx, char *tag)
{
	int max_padd = padding_from_num(get_number_cpus());
	uint64_t all = rel->cpu_user[idx] + rel->cpu_nice[idx] + rel->cpu_sys[idx] +
		       rel->cpu_idle[idx] + rel->cpu_iow[idx];

	mvwprintw(screen, (*voff)++, 2,
		  "cpu%*d%s:%s %13.1lf%% usr/t "
			  "%9.1lf%% sys/t "
			  "%10.1lf%% idl/t "
			  "%11.1lf%% iow/t  ", max_padd, idx,
		  tag, strlen(tag) == 0 ? " " : "",
		  100.0 * (rel->cpu_user[idx] + rel->cpu_nice[idx]) / all,
		  100.0 * rel->cpu_sys[idx] / all,
		  100.0 * rel->cpu_idle[idx] / all,
		  100.0 * rel->cpu_iow[idx] / all);
}

static void screen_percpu_states(WINDOW *screen, const struct ifstat *rel,
				 int top_cpus, int *voff)
{
	int i;
	int cpus = get_number_cpus();

	if (top_cpus == 0)
		return;

	/* Display top hitter */
	screen_percpu_states_one(screen, rel, voff, cpu_hits[0].idx, "+");

	/* Make sure we don't display the min. hitter twice */
	if (top_cpus == cpus)
		top_cpus--;

	for (i = 1; i < top_cpus; ++i)
		screen_percpu_states_one(screen, rel, voff, cpu_hits[i].idx, "");

	/* Display minimum hitter */
	if (cpus != 1)
		screen_percpu_states_one(screen, rel, voff, cpu_hits[cpus - 1].idx, "-");
}

static void screen_percpu_irqs_rel_one(WINDOW *screen, const struct ifstat *rel,
				       int *voff, unsigned int idx, char *tag)
{
	int max_padd = padding_from_num(get_number_cpus());

	mvwprintw(screen, (*voff)++, 2,
		  "cpu%*d%s:%s %14llu irqs/t   "
			  "%15llu sirq rx/t   "
			  "%15llu sirq tx/t      ", max_padd, idx,
		  tag, strlen(tag) == 0 ? " " : "",
		  rel->irqs[idx],
		  rel->irqs_srx[idx],
		  rel->irqs_stx[idx]);
}

static void screen_percpu_irqs_rel(WINDOW *screen, const struct ifstat *rel,
				   int top_cpus, int *voff)
{
	int i;
	int cpus = get_number_cpus();

	screen_percpu_irqs_rel_one(screen, rel, voff, cpu_hits[0].idx, "+");

	if (top_cpus == cpus)
		top_cpus--;

	for (i = 1; i < top_cpus; ++i)
		screen_percpu_irqs_rel_one(screen, rel, voff, cpu_hits[i].idx, "");

	if (cpus != 1)
		screen_percpu_irqs_rel_one(screen, rel, voff, cpu_hits[cpus - 1].idx, "-");
}

static void screen_percpu_irqs_abs_one(WINDOW *screen, const struct ifstat *abs,
				       int *voff, unsigned int idx, char *tag)
{
	int max_padd = padding_from_num(get_number_cpus());

	mvwprintw(screen, (*voff)++, 2,
		  "cpu%*d%s:%s %14llu irqs", max_padd, idx,
		  tag, strlen(tag) == 0 ? " " : "",
		  abs->irqs[idx]);
}

static void screen_percpu_irqs_abs(WINDOW *screen, const struct ifstat *abs,
				   int top_cpus, int *voff)
{
	int i;
	int cpus = get_number_cpus();

	screen_percpu_irqs_abs_one(screen, abs, voff, cpu_hits[0].idx, "+");

	if (top_cpus == cpus)
		top_cpus--;

	for (i = 1; i < top_cpus; ++i)
		screen_percpu_irqs_abs_one(screen, abs, voff, cpu_hits[i].idx, "");

	if (cpus != 1)
		screen_percpu_irqs_abs_one(screen, abs, voff, cpu_hits[cpus - 1].idx, "-");
}

static void screen_wireless(WINDOW *screen, const struct ifstat *rel,
			    const struct ifstat *abs, int *voff)
{
	if (iswireless(abs)) {
		mvwprintw(screen, (*voff)++, 2,
			  "linkqual: %7d/%d (%d/t)          ",
			  abs->wifi.link_qual,
			  abs->wifi.link_qual_max,
			  rel->wifi.link_qual);

		mvwprintw(screen, (*voff)++, 2,
			  "signal: %8d dBm (%d dBm/t)       ",
			  abs->wifi.signal_level,
			  rel->wifi.signal_level);
	}
}

static void screen_update(WINDOW *screen, const char *ifname, const struct ifstat *rel,
			  const struct ifstat *abs, int *first, uint64_t ms_interval,
			  unsigned int top_cpus)
{
	int cpus, top, voff = 1, cvoff = 2;

	curs_set(0);

	cpus = get_number_cpus();
	top = min(cpus, top_cpus);

	stats_top(rel, abs, cpus);

	qsort(cpu_hits, cpus, sizeof(*cpu_hits), cmp_hits);

	screen_header(screen, ifname, &voff, ms_interval, top_cpus);

	voff++;
	screen_net_dev_rel(screen, rel, &voff);

	voff++;
	screen_net_dev_abs(screen, abs, &voff);

	voff++;
	screen_sys_mem(screen, rel, abs, &voff);

	voff++;
	screen_percpu_states(screen, rel, top, &voff);

	qsort(cpu_hits, cpus, sizeof(*cpu_hits), cmp_irqs_rel);

	voff++;
	screen_percpu_irqs_rel(screen, rel, top, &voff);

	qsort(cpu_hits, cpus, sizeof(*cpu_hits), cmp_irqs_abs);

	voff++;
	screen_percpu_irqs_abs(screen, abs, top, &voff);

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

static int screen_main(const char *ifname, uint64_t ms_interval,
		       unsigned int top_cpus)
{
	int first = 1, key;

	screen_init(&stats_screen);

	while (!sigint) {
		key = getch();
		if (key == 'q' || key == 0x1b || key == KEY_F(10))
			break;

		screen_update(stats_screen, ifname, &stats_delta, &stats_new,
			      &first, ms_interval, top_cpus);

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

static int term_main(const char *ifname, uint64_t ms_interval,
		     unsigned int top_cpus __maybe_unused)
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
	int c, opt_index, ret, cpus, promisc = 0;
	unsigned int top_cpus = 10;
	uint64_t interval = 1000;
	char *ifname = NULL;
	int (*func_main)(const char *ifname, uint64_t ms_interval,
			 unsigned int top_cpus) = screen_main;

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
			interval = strtoul(optarg, NULL, 10);
			break;
		case 'n':
			top_cpus = strtoul(optarg, NULL, 10);
			if (top_cpus < 1)
				panic("Number of top hitter CPUs must be greater than 0");
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

	cpus = get_number_cpus();
	top_cpus = min(top_cpus, cpus);

	stats_alloc(&stats_old, cpus);
	stats_alloc(&stats_new, cpus);
	stats_alloc(&stats_delta, cpus);

	cpu_hits = xzmalloc(cpus * sizeof(*cpu_hits));

	if (promisc)
		ifflags = enter_promiscuous_mode(ifname);
	ret = func_main(ifname, interval, top_cpus);
	if (promisc)
		leave_promiscuous_mode(ifname, ifflags);

	xfree(ifname);
	return ret;
}

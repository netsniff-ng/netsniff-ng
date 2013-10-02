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
#include <sys/types.h>
#include <sys/utsname.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <dirent.h>

#include "die.h"
#include "dev.h"
#include "sig.h"
#include "str.h"
#include "link.h"
#include "xmalloc.h"
#include "ioops.h"
#include "cpus.h"
#include "config.h"
#include "built_in.h"
#include "screen.h"

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
	uint64_t mem_free, mem_total, mem_active, mem_inactive;
	uint64_t swap_total, swap_free, swap_cached;
	uint32_t procs_total, procs_run, procs_iow, cswitch;
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

struct avg_stat {
	uint64_t cpu_user, cpu_sys, cpu_nice, cpu_idle, cpu_iow;
	long double irqs_abs, irqs_rel, irqs_srx_rel, irqs_stx_rel;
};

static volatile sig_atomic_t sigint = 0;
static struct ifstat stats_old, stats_new, stats_delta;
static struct cpu_hit *cpu_hits;
static struct avg_stat stats_avg;
static int stats_loop = 0;
static int show_median = 0, show_percentage = 0;
static WINDOW *stats_screen = NULL;
static struct utsname uts;

static const char *short_options = "d:n:t:clmopPWvh";
static const struct option long_options[] = {
	{"dev",			required_argument,	NULL, 'd'},
	{"num-cpus",		required_argument,	NULL, 'n'},
	{"interval",		required_argument,	NULL, 't'},
	{"csv",			no_argument,		NULL, 'c'},
	{"loop",		no_argument,		NULL, 'l'},
	{"median",		no_argument,		NULL, 'm'},
	{"omit-header",		no_argument,		NULL, 'o'},
	{"promisc",		no_argument,		NULL, 'p'},
	{"percentage",		no_argument,		NULL, 'P'},
	{"no-warn",		no_argument,		NULL, 'W'},
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
	     "  -n|--num-cpus <num>    Number of top hitter CPUs in ncurses mode (def: 5)\n"
	     "  -t|--interval <time>   Refresh time in ms (default 1000 ms)\n"
	     "  -c|--csv               Output to terminal as Gnuplot-ready data\n"
	     "  -l|--loop              Continuous CSV output\n"
	     "  -m|--median            Display median values\n"
	     "  -o|--omit-header       Do not print the CSV header\n"
	     "  -p|--promisc           Promiscuous mode\n"
	     "  -P|--percentage        Show percentage of theoretical line rate\n"
	     "  -W|--no-warn           Suppress warnings\n"
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
	printf("\nifpps %s, Git id: %s\n", VERSION_LONG, GITVERSION);
	puts("top-like kernel networking and system statistics\n"
	     "http://www.netsniff-ng.org\n\n"
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
	do {
		i++;
	} while ((n /= 10) > 0);
	return i;
}

#define STATS_ALLOC1(member)	\
	do { stats->member = xzmalloc(cpus * sizeof(*(stats->member))); } while (0)

static void stats_alloc(struct ifstat *stats, unsigned int cpus)
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

static void stats_zero(struct ifstat *stats, unsigned int cpus)
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

#define STATS_RELEASE(member)	\
	do { xfree(stats->member); } while (0)

static void stats_release(struct ifstat *stats)
{
	STATS_RELEASE(irqs);
	STATS_RELEASE(irqs_srx);
	STATS_RELEASE(irqs_stx);

	STATS_RELEASE(cpu_user);
	STATS_RELEASE(cpu_sys);
	STATS_RELEASE(cpu_nice);
	STATS_RELEASE(cpu_idle);
	STATS_RELEASE(cpu_iow);
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
	int ret = -EINVAL, try = 0;
	unsigned int i, cpus;
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

		if (strstr(buff, ifname) == NULL)
			continue;

		ptr = strchr(buff, ':');
		if (!ptr)
			continue;
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
	unsigned int i, cpus;
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
		} else if ((ptr = strstr(buff, "Active:"))) {
			ptr += strlen("Active:");
			stats->mem_active = strtoul(ptr, &ptr, 10);
		} else if ((ptr = strstr(buff, "Inactive:"))) {
			ptr += strlen("Inactive:");
			stats->mem_inactive = strtoul(ptr, &ptr, 10);
		} else if ((ptr = strstr(buff, "SwapTotal:"))) {
			ptr += strlen("SwapTotal:");
			stats->swap_total = strtoul(ptr, &ptr, 10);
		} else if ((ptr = strstr(buff, "SwapFree:"))) {
			ptr += strlen("SwapFree:");
			stats->swap_free = strtoul(ptr, &ptr, 10);
		} else if ((ptr = strstr(buff, "SwapCached:"))) {
			ptr += strlen("SwapCached:");
			stats->swap_cached = strtoul(ptr, &ptr, 10);
		}

		memset(buff, 0, sizeof(buff));
	}

	fclose(fp);
	return 0;
}

static int stats_proc_system(struct ifstat *stats)
{
	unsigned int cpu, cpus;
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

static int stats_proc_procs(struct ifstat *stats)
{
	DIR *dir;
	struct dirent *e;

	dir = opendir("/proc");
	if (!dir)
		panic("Cannot open /proc\n");

	stats->procs_total = 0;

	while ((e = readdir(dir)) != NULL) {
		const char *name = e->d_name;
		char *end;
		unsigned int pid = strtoul(name, &end, 10);

		/* not a number */
		if (pid == 0 && end == name)
			continue;

		stats->procs_total++;
	}

	closedir(dir);

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
		if ((new->member - old->member) > (new->member)) { \
			diff->member = 0; \
		} else { \
			DIFF1(member); \
		} \
	} while (0)

static void stats_diff(struct ifstat *old, struct ifstat *new,
		       struct ifstat *diff)
{
	unsigned int cpus, i;

	DIFF(rx_bytes);
	DIFF(rx_packets);
	DIFF(rx_drops);
	DIFF(rx_errors);
	DIFF(rx_fifo);
	DIFF(rx_frame);
	DIFF(rx_multi);

	DIFF(tx_bytes);
	DIFF(tx_packets);
	DIFF(tx_drops);
	DIFF(tx_errors);
	DIFF(tx_fifo);
	DIFF(tx_colls);
	DIFF(tx_carrier);

	DIFF1(wifi.signal_level);
	DIFF1(wifi.link_qual);

	DIFF1(cswitch);

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
	if (stats_proc_procs(stats) < 0)
		panic("Cannot fetch process stats!\n");

	stats_proc_interrupts((char *) ifname, stats);

	stats_wireless(ifname, stats);
}

static void stats_sample_generic(const char *ifname, uint64_t ms_interval)
{
	unsigned int cpus = get_number_cpus();

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
		      unsigned int cpus)
{
	unsigned int i;

	memset(&stats_avg, 0, sizeof(stats_avg));

	for (i = 0; i < cpus; ++i) {
		cpu_hits[i].idx = i;
		cpu_hits[i].hit = rel->cpu_user[i] + rel->cpu_nice[i] + rel->cpu_sys[i];
		cpu_hits[i].irqs_rel = rel->irqs[i];
		cpu_hits[i].irqs_abs = abs->irqs[i];

		stats_avg.cpu_user += rel->cpu_user[i];
		stats_avg.cpu_sys += rel->cpu_sys[i];
		stats_avg.cpu_nice += rel->cpu_nice[i];
		stats_avg.cpu_idle += rel->cpu_idle[i];
		stats_avg.cpu_iow += rel->cpu_iow[i];

		stats_avg.irqs_abs += abs->irqs[i];
		stats_avg.irqs_rel += rel->irqs[i];
		stats_avg.irqs_srx_rel += rel->irqs_srx[i];
		stats_avg.irqs_stx_rel += rel->irqs_stx[i];
	}

	stats_avg.cpu_user /= cpus;
	stats_avg.cpu_sys /= cpus;
	stats_avg.cpu_nice /= cpus;
	stats_avg.cpu_idle /= cpus;
	stats_avg.cpu_iow /= cpus;
	stats_avg.irqs_abs /= cpus;
	stats_avg.irqs_rel /= cpus;
	stats_avg.irqs_srx_rel /= cpus;
	stats_avg.irqs_stx_rel /= cpus;
}

static void screen_header(WINDOW *screen, const char *ifname, int *voff,
			  u32 rate, uint64_t ms_interval, unsigned int top_cpus)
{
	size_t len = 0;
	char buff[64], machine[64];
	struct ethtool_drvinfo drvinf;
	int link = ethtool_link(ifname);
	unsigned int cpus = get_number_cpus();

	memset(&drvinf, 0, sizeof(drvinf));
	ethtool_drvinf(ifname, &drvinf);

	memset(buff, 0, sizeof(buff));
	memset(machine, 0, sizeof(machine));

	if (rate)
		len += snprintf(buff + len, sizeof(buff) - len, " %uMbit/s", rate);
	if (link >= 0)
		len += snprintf(buff + len, sizeof(buff) - len, " link:%s",
				link == 0 ? "no" : "yes");

	if (!strstr(uts.release, uts.machine))
		slprintf(machine, sizeof(machine), " %s,", uts.machine);

	mvwprintw(screen, (*voff)++, 2,
		  "%s,%s %s (%s%s), t=%lums, cpus=%u%s/%u"
		  "               ", uts.release, machine,
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

static void screen_net_dev_percentage(WINDOW *screen, const struct ifstat *rel,
				      int *voff, u32 rate)
{
	mvwprintw(screen, (*voff)++, 0,
		  "  rx: %15.2llf%% of line rate  "
		  "                                                  ",
		  rate ? ((((long double) rel->rx_bytes) / 125000) / rate) * 100.0 : 0.0);

	mvwprintw(screen, (*voff)++, 0,
		  "  tx: %15.2llf%% of line rate  "
		  "                                                  ",
		  rate ? ((((long double) rel->tx_bytes) / 125000) / rate) * 100.0 : 0.0);
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

static void screen_sys(WINDOW *screen, const struct ifstat *rel,
		       const struct ifstat *abs, int *voff)
{
	mvwprintw(screen, (*voff)++, 2,
		  "sys:  %14u cs/t "
			"%11u procs "
			"%11u running "
			"%10u iowait",
		  rel->cswitch, abs->procs_total, abs->procs_run, abs->procs_iow);
}

static void screen_mem_swap(WINDOW *screen, const struct ifstat *abs, int *voff)
{
	mvwprintw(screen, (*voff)++, 2,
		  "mem:  %13uM total "
			 "%9uM used "
			"%11uM active "
			"%10uM inactive",
			abs->mem_total / 1024,
			(abs->mem_total - abs->mem_free) / 1024,
			abs->mem_active / 1024,
			abs->mem_inactive / 1024);

	mvwprintw(screen, (*voff)++, 2,
		  "swap:  %12uM total "
			  "%9uM used "
			 "%11uM cached",
		  abs->swap_total / 1024,
		  (abs->swap_total - abs->swap_free) / 1024,
		  abs->swap_cached / 1024);
}

static void screen_percpu_states_one(WINDOW *screen, const struct ifstat *rel,
				     int *voff, unsigned int idx, char *tag)
{
	int max_padd = padding_from_num(get_number_cpus());
	uint64_t all = rel->cpu_user[idx] + rel->cpu_nice[idx] + rel->cpu_sys[idx] +
		       rel->cpu_idle[idx] + rel->cpu_iow[idx];

	mvwprintw(screen, (*voff)++, 2,
		  "cpu%*d %s: %11.1lf%% usr/t "
			      "%9.1lf%% sys/t "
			     "%10.1lf%% idl/t "
			     "%11.1lf%% iow/t",
		  max_padd, idx, tag,
		  100.0 * (rel->cpu_user[idx] + rel->cpu_nice[idx]) / all,
		  100.0 * rel->cpu_sys[idx] / all,
		  100.0 * rel->cpu_idle[idx] / all,
		  100.0 * rel->cpu_iow[idx] / all);
}

#define MEDIAN_EVEN(member)	do { \
	m_##member = (rel->member[i] + rel->member[j]) / 2.0; \
} while (0)

#define MEDIAN_ODD(member)	do { \
	m_##member = rel->member[i]; \
} while (0)

static void screen_percpu_states(WINDOW *screen, const struct ifstat *rel,
				 const struct avg_stat *avg,
				 unsigned int top_cpus, int *voff)
{
	unsigned int i;
	unsigned int cpus = get_number_cpus();
	int max_padd = padding_from_num(cpus);
	uint64_t all;

	if (top_cpus == 0)
		return;

	/* Display top hitter */
	screen_percpu_states_one(screen, rel, voff, cpu_hits[0].idx, "+");

	/* Make sure we don't display the min. hitter twice */
	if (top_cpus == cpus)
		top_cpus--;

	for (i = 1; i < top_cpus; ++i)
		screen_percpu_states_one(screen, rel, voff, cpu_hits[i].idx, "|");

	/* Display minimum hitter */
	if (cpus != 1)
		screen_percpu_states_one(screen, rel, voff, cpu_hits[cpus - 1].idx, "-");

	all = avg->cpu_user + avg->cpu_sys + avg->cpu_nice + avg->cpu_idle + avg->cpu_iow;
	mvwprintw(screen, (*voff)++, 2,
		  "avg:%*s%14.1lf%%       "
			"%9.1lf%%       "
		       "%10.1lf%%       "
		       "%11.1lf%%", max_padd, "",
		 100.0 * (avg->cpu_user + avg->cpu_nice) / all,
		 100.0 * avg->cpu_sys / all,
		 100.0 * avg->cpu_idle /all,
		 100.0 * avg->cpu_iow / all);

	if (show_median) {
		long double m_cpu_user, m_cpu_nice, m_cpu_sys, m_cpu_idle, m_cpu_iow;
		long double m_all;

		i = cpu_hits[cpus / 2].idx;
		if (cpus % 2 == 0) {
			/* take the mean of the 2 middle entries */
			int j = cpu_hits[(cpus / 2) - 1].idx;

			MEDIAN_EVEN(cpu_user);
			MEDIAN_EVEN(cpu_nice);
			MEDIAN_EVEN(cpu_sys);
			MEDIAN_EVEN(cpu_idle);
			MEDIAN_EVEN(cpu_iow);
		} else {
			/* take the middle entry as is */
			MEDIAN_ODD(cpu_user);
			MEDIAN_ODD(cpu_nice);
			MEDIAN_ODD(cpu_sys);
			MEDIAN_ODD(cpu_idle);
			MEDIAN_ODD(cpu_iow);
		}

		m_all = m_cpu_user + m_cpu_sys + m_cpu_nice + m_cpu_idle + m_cpu_iow;
		mvwprintw(screen, (*voff)++, 2,
			  "med:%*s%14.1Lf%%       "
				"%9.1Lf%%       "
			       "%10.1Lf%%       "
			       "%11.1Lf%%", max_padd, "",
			 100.0 * (m_cpu_user + m_cpu_nice) / m_all,
			 100.0 * m_cpu_sys / m_all,
			 100.0 * m_cpu_idle /m_all,
			 100.0 * m_cpu_iow / m_all);
	}
}

static void screen_percpu_irqs_rel_one(WINDOW *screen, const struct ifstat *rel,
				       int *voff, unsigned int idx, char *tag)
{
	int max_padd = padding_from_num(get_number_cpus());

	mvwprintw(screen, (*voff)++, 2,
		  "cpu%*d %s: %12llu irqs/t "
			     "%17llu sirq rx/t "
			     "%17llu sirq tx/t",
		  max_padd, idx, tag,
		  rel->irqs[idx],
		  rel->irqs_srx[idx],
		  rel->irqs_stx[idx]);
}

static void screen_percpu_irqs_rel(WINDOW *screen, const struct ifstat *rel,
				   const struct avg_stat *avg,
				   unsigned int top_cpus, int *voff)
{
	unsigned int i;
	unsigned int cpus = get_number_cpus();
	int max_padd = padding_from_num(cpus);

	screen_percpu_irqs_rel_one(screen, rel, voff, cpu_hits[0].idx, "+");

	if (top_cpus == cpus)
		top_cpus--;

	for (i = 1; i < top_cpus; ++i)
		screen_percpu_irqs_rel_one(screen, rel, voff, cpu_hits[i].idx, "|");

	if (cpus != 1)
		screen_percpu_irqs_rel_one(screen, rel, voff, cpu_hits[cpus - 1].idx, "-");

	mvwprintw(screen, (*voff)++, 2,
		 "avg:%*s%17.1Lf        "
		      "%17.1Lf           "
		      "%17.1Lf", max_padd, "",
		 avg->irqs_rel, avg->irqs_srx_rel, avg->irqs_stx_rel);

	if (show_median) {
		long double m_irqs, m_irqs_srx, m_irqs_stx;

		i = cpu_hits[cpus / 2].idx;
		if (cpus % 2 == 0) {
			/* take the mean of the 2 middle entries */
			int j = cpu_hits[(cpus / 2) - 1].idx;

			MEDIAN_EVEN(irqs);
			MEDIAN_EVEN(irqs_srx);
			MEDIAN_EVEN(irqs_stx);
		} else {
			/* take the middle entry as is */
			MEDIAN_ODD(irqs);
			MEDIAN_ODD(irqs_srx);
			MEDIAN_ODD(irqs_stx);
		}

		mvwprintw(screen, (*voff)++, 2,
			 "med:%*s%17.1Lf        "
			      "%17.1Lf           "
			      "%17.1Lf", max_padd, "",
			 m_irqs, m_irqs_srx, m_irqs_stx);
	}
}

static void screen_percpu_irqs_abs_one(WINDOW *screen, const struct ifstat *abs,
				       int *voff, unsigned int idx, char *tag)
{
	int max_padd = padding_from_num(get_number_cpus());

	mvwprintw(screen, (*voff)++, 2,
		  "cpu%*d %s: %12llu irqs",
		  max_padd, idx, tag, abs->irqs[idx]);
}

static void screen_percpu_irqs_abs(WINDOW *screen, const struct ifstat *abs,
				   const struct avg_stat *avg,
				   unsigned int top_cpus, int *voff)
{
	unsigned int i;
	unsigned int cpus = get_number_cpus();
	int max_padd = padding_from_num(cpus);

	screen_percpu_irqs_abs_one(screen, abs, voff, cpu_hits[0].idx, "+");

	if (top_cpus == cpus)
		top_cpus--;

	for (i = 1; i < top_cpus; ++i)
		screen_percpu_irqs_abs_one(screen, abs, voff, cpu_hits[i].idx, "|");

	if (cpus != 1)
		screen_percpu_irqs_abs_one(screen, abs, voff, cpu_hits[cpus - 1].idx, "-");

	mvwprintw(screen, (*voff)++, 2,
		 "avg:%*s%17.1Lf", max_padd, "", avg->irqs_abs);

	if (show_median) {
		long double m_irqs;

		i = cpu_hits[cpus / 2].idx;
		if (cpus % 2 == 0) {
			/* take the mean of the 2 middle entries */
			int j = cpu_hits[(cpus / 2) - 1].idx;

			m_irqs = (abs->irqs[i] + abs->irqs[j]) / 2;
		} else {
			/* take the middle entry as is */
			m_irqs = abs->irqs[i];
		}

		mvwprintw(screen, (*voff)++, 2,
			  "med:%*s%17.1Lf", max_padd, "", m_irqs);
	}
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
			  const struct ifstat *abs, const struct avg_stat *avg,
			  int *first, uint64_t ms_interval, unsigned int top_cpus,
			  bool need_info)
{
	unsigned int cpus, top;
	int voff = 1, cvoff = 2;
	u32 rate = device_bitrate(ifname);

	curs_set(0);

	cpus = get_number_cpus();
	top = min(cpus, top_cpus);

	stats_top(rel, abs, cpus);

	qsort(cpu_hits, cpus, sizeof(*cpu_hits), cmp_hits);

	screen_header(screen, ifname, &voff, rate, ms_interval, top_cpus);

	voff++;
	screen_net_dev_rel(screen, rel, &voff);

	if (show_percentage) {
		voff++;
		screen_net_dev_percentage(screen, rel, &voff, rate);
	}

	voff++;
	screen_net_dev_abs(screen, abs, &voff);

	voff++;
	screen_sys(screen, rel, abs, &voff);

	voff++;
	screen_mem_swap(screen, abs, &voff);

	voff++;
	screen_percpu_states(screen, rel, avg, top, &voff);

	qsort(cpu_hits, cpus, sizeof(*cpu_hits), cmp_irqs_rel);

	voff++;
	screen_percpu_irqs_rel(screen, rel, avg, top, &voff);

	qsort(cpu_hits, cpus, sizeof(*cpu_hits), cmp_irqs_abs);

	voff++;
	screen_percpu_irqs_abs(screen, abs, avg, top, &voff);

	voff++;
	screen_wireless(screen, rel, abs, &voff);

	if (*first) {
		mvwprintw(screen, cvoff, 2, "Collecting data ...");
		*first = 0;
	} else {
		if (need_info)
			mvwprintw(screen, cvoff, 2, "(consider to increase "
				  "your sampling interval, e.g. -t %d)",
			rate > SPEED_1000 ? 10000 : 1000);
		else
			mvwprintw(screen, cvoff, 2, "                      "
				  "                                      ");
	}

	wrefresh(screen);
	refresh();
}

static int screen_main(const char *ifname, uint64_t ms_interval,
		       unsigned int top_cpus, bool suppress_warnings,
		       bool omit_header __maybe_unused)
{
	int first = 1, key;
	u32 rate = device_bitrate(ifname);
	bool need_info = false;

	stats_screen = screen_init(true);

	if (((rate > SPEED_1000 && ms_interval <= 1000) ||
	     (rate = SPEED_1000 && ms_interval <  1000)) &&
	     !suppress_warnings)
		need_info = true;

	while (!sigint) {
		key = getch();
		if (key == 'q' || key == 0x1b || key == KEY_F(10))
			break;

		screen_update(stats_screen, ifname, &stats_delta, &stats_new, &stats_avg,
			      &first, ms_interval, top_cpus, need_info);

		stats_sample_generic(ifname, ms_interval);
	}

	screen_end();

	return 0;
}

static void term_csv(const struct ifstat *rel, const struct ifstat *abs)
{
	unsigned int cpus, i;

	printf("%ld ", time(NULL));

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
	printf("%lu ", abs->swap_free);
	printf("%lu ", abs->swap_total - abs->swap_free);
	printf("%lu ", abs->swap_total);
	printf("%u ",  abs->procs_total);
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
	unsigned int cpus, i, j = 1;

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
	printf("%d:swap-free ", j++);
	printf("%d:swap-used ", j++);
	printf("%d:swap-total ", j++);
	printf("%d:procs-total ", j++);
	printf("%d:procs-in-run ", j++);
	printf("%d:procs-in-iow ", j++);

	cpus = get_number_cpus();

	for (i = 0; i < cpus; ++i) {
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
		     unsigned int top_cpus __maybe_unused,
		     bool suppress_warnings __maybe_unused,
		     bool omit_header)
{
	do {
		stats_sample_generic(ifname, ms_interval);

		if (!omit_header) {
			omit_header = true;
			term_csv_header(ifname, &stats_new, ms_interval);
		}

		term_csv(&stats_delta, &stats_new);
	} while (stats_loop && !sigint);

	return 0;
}

int main(int argc, char **argv)
{
	short ifflags = 0;
	int c, opt_index, ret, promisc = 0;
	unsigned int cpus, top_cpus = 5;
	uint64_t interval = 1000;
	char *ifname = NULL;
	bool suppress_warnings = false;
	bool omit_header = false;
	int (*func_main)(const char *ifname, uint64_t ms_interval,
			 unsigned int top_cpus, bool suppress_warnings,
			 bool omit_header);

	func_main = screen_main;

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
		case 'W':
			suppress_warnings = true;
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
		case 'P':
			show_percentage = 1;
			break;
		case 'm':
			show_median = 1;
			break;
		case 'c':
			func_main = term_main;
			break;
		case 'o':
			omit_header = true;
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
	if (uname(&uts) < 0)
		panic("Cannot execute uname!\n");

	stats_alloc(&stats_old, cpus);
	stats_alloc(&stats_new, cpus);
	stats_alloc(&stats_delta, cpus);

	cpu_hits = xzmalloc(cpus * sizeof(*cpu_hits));

	if (promisc)
		ifflags = device_enter_promiscuous_mode(ifname);
	ret = func_main(ifname, interval, top_cpus, suppress_warnings, omit_header);
	if (promisc)
		device_leave_promiscuous_mode(ifname, ifflags);

	stats_release(&stats_old);
	stats_release(&stats_new);
	stats_release(&stats_delta);

	xfree(ifname);
	return ret;
}

/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009-2011 Daniel Borkmann.
 * Subject to the GPL.
 */

#include <stdio.h>
#include <string.h>
#include <curses.h>
#include <getopt.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <fcntl.h>

#include "xmalloc.h"
#include "strlcpy.h"
#include "error_and_die.h"
#include "netdev.h"
#include "system.h"
#include "tty.h"
#include "version.h"
#include "signals.h"

struct counter {
	uint16_t id;
	uint8_t min;
	uint8_t max;
	uint8_t inc;
	uint8_t val;
	off_t off;
};

struct randomizer {
	uint8_t val;
	off_t off;
};

struct packet {
	uint8_t *payload;
	size_t plen;
	struct counter *cnt;
	size_t clen;
	struct randomizer *rnd;
	size_t rlen;
};

struct pktconf {
	unsigned long num;
	unsigned long gap;
	struct packet *pkts;
	size_t len;
	size_t curr;
};

static sig_atomic_t sigint = 0;

static const char *short_options = "d:c:n:t:vh";

static struct option long_options[] = {
	{"dev", required_argument, 0, 'd'},
	{"conf", required_argument, 0, 'c'},
	{"num", required_argument, 0, 'n'},
	{"gap", required_argument, 0, 't'},
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};

static inline uint8_t lcrand(uint8_t val)
{
	return (3 * val + 11) && 0xFF;
}

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

static void header(void)
{
	printf("%s%s%s\n", colorize_start(bold), "trafgen "
	       VERSION_STRING, colorize_end());
}

static void help(void)
{
	printf("\ntrafgen %s, network packet generator\n",
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Usage: trafgen [options]\n");
	printf("Options:\n");
	printf("  -d|--dev <netdev>      TX Device\n");
	printf("  -c|--conf <file>       Packet configuration txf-file\n");
	printf("  -n|--num <uint>        TX mode\n");
	printf("  `--     0              Loop until interrupt (default)\n");
	printf("   `-     n              Send n packets and done\n");
	printf("  -t|--gap <interval>    Packet interval in msecs, def: 0\n");
	printf("  -v|--version           Print version\n");
	printf("  -h|--help              Print this help\n");
	printf("\n");
	printf("Example:\n");
	printf("  See trafgen.txf for configuration file examples.\n");
	printf("  trafgen --dev eth0 --conf trafgen.txf\n");
	printf("  trafgen --dev eth0 --conf trafgen.txf --num 100 --gap 5\n");
	printf("\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2011 Daniel Borkmann\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");

	die();
}

static void version(void)
{
	printf("\ntrafgen %s, network packet generator\n",
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2011 Daniel Borkmann\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");

	die();
}

static void tx_fire_or_die(char *ifname, struct pktconf *cfg)
{
	if (!ifname || !cfg)
		panic("Panic over invalid args for TX trigger!\n");
}

static inline char *getuint(char *in, uint32_t *out)
{
	char *pt = in, tmp;
	while (*in && (isdigit(*in) || isxdigit(*in) || *in == 'x'))
		in++;
	if (!*in)
		panic("Syntax error!\n");
	tmp = *in;
	*in = 0;
	*out = strtol(pt, NULL, 0);
	if (errno == EINVAL) {
		*out = strtol(pt, NULL, 16);
		if (errno == EINVAL)
			panic("Syntax error!\n");
	}
	*in = tmp;
	return in;
}

#define TYPE_NUM 0
#define TYPE_CNT 1
#define TYPE_RND 2
#define TYPE_EOL 3

static inline char *getuint_or_obj(char *in, uint32_t *out, int *type)
{
	if (*in == '\n') {
		*type = TYPE_EOL;
	} else if (*in == '$') {
		in++;
		if (!strncmp("II", in, strlen("II"))) {
			in += 2;
			in = getuint(in, out);
			*type = TYPE_CNT;
		} else if (!strncmp("PRB", in, strlen("PRB"))) {
			*type = TYPE_RND;
			in += 3;
		} else
			panic("Syntax error!\n");
	} else {
		in = getuint(in, out);
		*type = TYPE_NUM;
	}

	return in;
}

static inline char *skipchar(char *in, char c)
{
	if (*in != c)
		panic("Syntax error!\n");
	return ++in;
}

static inline char *skipchar_s(char *in, char c)
{
	in = skips(in);
	if (*in == '\n')
		return in;
	in = skipchar(in, c);
	in = skips(in);

	return in;
}

static void dump_conf(struct pktconf *cfg)
{
	size_t i, j;

	info("n %lu, gap %lu ms, pkts %zu\n", cfg->num, cfg->gap, cfg->len);
	if (cfg->len == 0)
		return;

	for (i = 0; i < cfg->len; ++i) {
		info("[%zu] pkt\n", i);
		info("      len %zu\n", cfg->pkts[i].plen);
		info("      cnts %zu\n", cfg->pkts[i].clen);
		info("      rnds %zu\n", cfg->pkts[i].rlen);
		info("      payload ");
		for (j = 0; j < cfg->pkts[i].plen; ++j)
			info("0x%02x ", cfg->pkts[i].payload[j]);
		info("\n");
		for (j = 0; j < cfg->pkts[i].clen; ++j)
			info("      cnt%zu %u <= x <= %u, %u, o %zu\n",
			     j, cfg->pkts[i].cnt[j].min,
			     cfg->pkts[i].cnt[j].max,
			     cfg->pkts[i].cnt[j].inc,
			     cfg->pkts[i].cnt[j].off);
		for (j = 0; j < cfg->pkts[i].rlen; ++j)
			info("      rnd%zu o %zu\n",
			     cfg->pkts[i].rnd[j].off);
	}
}

static void parse_conf_or_die(char *file, struct pktconf *cfg)
{
	int withinpkt = 0;
	unsigned long line = 0;
	char *pb, buff[1024];
	FILE *fp;
	struct counter *cnts = NULL;
	size_t l = 0;

	if (!file || !cfg)
		panic("Panic over invalid args for the parser!\n");

	fp = fopen(file, "r");
	if (!fp)
		panic("Cannot open config file!\n");
	memset(buff, 0, sizeof(buff));

	header();
	info("CFG:\n");
	while (fgets(buff, sizeof(buff), fp) != NULL) {
		line++;
		buff[sizeof(buff) - 1] = 0;
		pb = skips(buff);

		/* A comment or junk. Skip this line */
		if (*pb == '#' || *pb == '\n') {
			memset(buff, 0, sizeof(buff));
			continue;
		}

		if (!withinpkt && *pb == '$') {
			pb++;
			if (!strncmp("II", pb, strlen("II"))) {
				uint32_t id, min = 0, max = 0xFF, inc = 1;
				pb += 2;
				pb = getuint(pb, &id);
				pb = skipchar(pb, ':');
				pb = skips(pb);
				pb = getuint(pb, &min);
				pb = skipchar(pb, ',');
				pb = getuint(pb, &max);
				pb = skipchar(pb, ',');
				pb = getuint(pb, &inc);
				cnts = xrealloc(cnts, 1, ++l * sizeof(*cnts));
				cnts[l - 1].id = (uint8_t) id;
				cnts[l - 1].min = (uint8_t) min;
				cnts[l - 1].max = (uint8_t) max;
				cnts[l - 1].inc = (uint8_t) inc;
				cnts[l - 1].val = 0;
				cnts[l - 1].off = 0;
			} else if (!strncmp("P", pb, strlen("P"))) {
				uint32_t id;
				pb++;
				pb = getuint(pb, &id);
				pb = skips(pb);
				pb = skipchar(pb, '{');
				withinpkt = 1;
				cfg->len++;
				cfg->pkts = xrealloc(cfg->pkts, 1,
						     cfg->len * sizeof(*cfg->pkts));
				cfg->pkts[cfg->len - 1].plen = 0;
				cfg->pkts[cfg->len - 1].clen = 0;
				cfg->pkts[cfg->len - 1].rlen = 0;
				cfg->pkts[cfg->len - 1].payload = NULL;
			} else 
				panic("Unknown instruction! Syntax error "
				      "on line %lu!\n", line);
		} else if (withinpkt && *pb == '}')
				withinpkt = 0;
		else if (withinpkt) {
			int type;
			uint32_t val;
			while (1) {
				pb = getuint_or_obj(pb, &val, &type);
				if (type == TYPE_EOL)
					break;
				if (type == TYPE_CNT) {
//					info("cnt %u - ", val);
				} else if (type == TYPE_RND) {
//					info("rnd - ");
				}

				cfg->pkts[cfg->len - 1].plen++;
				cfg->pkts[cfg->len - 1].payload =
					xrealloc(cfg->pkts[cfg->len - 1].payload,
						 1, cfg->pkts[cfg->len - 1].plen);
				cfg->pkts[cfg->len - 1].payload[cfg->pkts[cfg->len - 1].plen - 1] =
					(uint8_t) val;
				pb = skipchar_s(pb, ',');
			}
		} else
			panic("Syntax error!\n");
		memset(buff, 0, sizeof(buff));
	}

	fclose(fp);
	xfree(cnts);

	dump_conf(cfg);
}

static int main_loop(char *ifname, char *confname, unsigned long pkts,
		     unsigned long gap)
{
	struct pktconf cfg = {
		.num = pkts,
		.gap = gap,
		.len = 0,
	};

	parse_conf_or_die(confname, &cfg);
	tx_fire_or_die(ifname, &cfg);

	return 0;
}

int main(int argc, char **argv)
{
	int c, opt_index, ret;
	char *ifname = NULL, *confname = NULL;
	unsigned long pkts = 0, gap = 0;

	check_for_root_maybe_die();

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
		case 'c':
			confname = xstrdup(optarg);
			break;
		case 'n':
			pkts = atol(optarg);
			break;
		case 't':
			gap = atol(optarg);
			break;
		case '?':
			switch (optopt) {
			case 'd':
			case 'c':
			case 'n':
			case 't':
				error_and_die(EXIT_FAILURE, "Option -%c "
					      "requires an argument!\n",
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

	if (argc < 5)
		help();
	if (ifname == NULL)
		error_and_die(EXIT_FAILURE, "No networking device given!\n");
	if (confname == NULL)
		error_and_die(EXIT_FAILURE, "No configuration file given!\n");
	if (device_mtu(ifname) == 0)
		error_and_die(EXIT_FAILURE, "This is no networking device!\n");

	register_signal(SIGINT, signal_handler);
	register_signal(SIGHUP, signal_handler);
	register_signal(SIGSEGV, muntrace_handler);

	ret = main_loop(ifname, confname, pkts, gap);

	xfree(ifname);
	xfree(confname);
	return ret;
}


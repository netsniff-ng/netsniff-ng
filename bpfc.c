/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL, version 2.
 *
 * This is a tiny Berkeley Packet Filter compiler that understands the
 * Syntax / Semantic from the USENIX paper {"The BSD Packet Filter: A New
 * Architecture for User-level Packet Capture", McCanne, Steven and
 * Jacobson, Van, Lawrence Berkeley Laboratory}. With this, BPFs can be
 * written the good old way and understood by the Linux kernel and *BSD
 * kernels where Berkeley Packet Filters are used.
 *
 *   The one small garden of a free gardener was all his need and due, not
 *   a garden swollen to a realm; his own hands to use, not the hands of
 *   others to command.
 *
 *     -- The Lord of the Rings, Sam, Chapter 'The Tower of Cirith Ungol'.
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/fsuid.h>

#include "xmalloc.h"
#include "xutils.h"
#include "die.h"
#include "bpf.h"

static const char *short_options = "vhi:Vdb";
static const struct option long_options[] = {
	{"input",	required_argument,	NULL, 'i'},
	{"verbose",	no_argument,		NULL, 'V'},
	{"bypass",	no_argument,		NULL, 'b'},
	{"dump",	no_argument,		NULL, 'd'},
	{"version",	no_argument,		NULL, 'v'},
	{"help",	no_argument,		NULL, 'h'},
	{NULL, 0, NULL, 0}
};

extern int compile_filter(char *file, int verbose, int bypass);

static void help(void)
{
	printf("\nbpfc %s, a tiny BPF compiler\n", VERSION_STRING);
	puts("http://www.netsniff-ng.org\n\n"
	     "Usage: bpfc [options] || bpfc <program>\n"
	     "Options:\n"
	     "  -i|--input <program/->  Berkeley Packet Filter file/stdin\n"
	     "  -V|--verbose            Be more verbose\n"
	     "  -b|--bypass             Bypass filter validation (e.g. for bug testing)\n"
	     "  -d|--dump               Dump supported instruction table\n"
	     "  -v|--version            Print version\n"
	     "  -h|--help               Print this help\n\n"
	     "Examples:\n"
	     "  bpfc fubar\n"
	     "  bpfc -bi fubar\n"
	     "  bpfc -   (read from stdin)\n\n"
	     "Please report bugs to <bugs@netsniff-ng.org>\n"
	     "Copyright (C) 2011-2013 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,\n"
	     "Swiss federal institute of technology (ETH Zurich)\n"
	     "License: GNU GPL version 2.0\n"
	     "This is free software: you are free to change and redistribute it.\n"
	     "There is NO WARRANTY, to the extent permitted by law.\n");
	die();
}

static void version(void)
{
	printf("\nbpfc %s, a tiny BPF compiler\n", VERSION_STRING);
	puts("http://www.netsniff-ng.org\n\n"
	     "Please report bugs to <bugs@netsniff-ng.org>\n"
	     "Copyright (C) 2011-2013 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,\n"
	     "Swiss federal institute of technology (ETH Zurich)\n"
	     "License: GNU GPL version 2.0\n"
	     "This is free software: you are free to change and redistribute it.\n"
	     "There is NO WARRANTY, to the extent permitted by law.\n");
	die();
}

int main(int argc, char **argv)
{
	int ret, verbose = 0, c, opt_index, bypass = 0;
	char *file = NULL;

	setfsuid(getuid());
	setfsgid(getgid());

	if (argc == 1)
		help();

	while ((c = getopt_long(argc, argv, short_options,
			        long_options, &opt_index)) != EOF) {
		switch (c) {
		case 'h':
			help();
			break;
		case 'v':
			version();
			break;
		case 'V':
			verbose = 1;
			break;
		case 'b':
			bypass = 1;
			break;
		case 'd':
			bpf_dump_op_table();
			die();
		case 'i':
			file = xstrdup(optarg);
			break;
		case '?':
			switch (optopt) {
			case 'i':
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

	if (argc == 2)
		file = xstrdup(argv[1]);
	if (!file)
		panic("No Berkeley Packet Filter program specified!\n");

	ret = compile_filter(file, verbose, bypass);

	xfree(file);
	return ret;
}

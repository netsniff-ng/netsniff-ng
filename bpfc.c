/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/fsuid.h>

#include "xmalloc.h"
#include "die.h"
#include "bpf.h"
#include "config.h"

static const char *short_options = "vhi:Vdbf:p";
static const struct option long_options[] = {
	{"input",	required_argument,	NULL, 'i'},
	{"format",	required_argument,	NULL, 'f'},
	{"cpp",		no_argument,		NULL, 'p'},
	{"verbose",	no_argument,		NULL, 'V'},
	{"bypass",	no_argument,		NULL, 'b'},
	{"dump",	no_argument,		NULL, 'd'},
	{"version",	no_argument,		NULL, 'v'},
	{"help",	no_argument,		NULL, 'h'},
	{NULL, 0, NULL, 0}
};

static const char *copyright = "Please report bugs to <bugs@netsniff-ng.org>\n"
	"Copyright (C) 2011-2013 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,\n"
	"Swiss federal institute of technology (ETH Zurich)\n"
	"License: GNU GPL version 2.0\n"
	"This is free software: you are free to change and redistribute it.\n"
	"There is NO WARRANTY, to the extent permitted by law.";

extern int compile_filter(char *file, int verbose, int bypass, int format,
			  bool invoke_cpp);

static void __noreturn help(void)
{
	printf("bpfc %s, a tiny BPF compiler\n", VERSION_STRING);
	puts("http://www.netsniff-ng.org\n\n"
	     "Usage: bpfc [options] || bpfc <program>\n"
	     "Options:\n"
	     "  -i|--input <program/->  Berkeley Packet Filter file/stdin\n"
	     "  -p|--cpp                Run bpf program through C preprocessor\n"
	     "  -f|--format <format>    Output format: C|netsniff-ng|xt_bpf|tcpdump\n"
	     "  -b|--bypass             Bypass filter validation (e.g. for bug testing)\n"
	     "  -V|--verbose            Be more verbose\n"
	     "  -d|--dump               Dump supported instruction table\n"
	     "  -v|--version            Print version and exit\n"
	     "  -h|--help               Print this help and exit\n\n"
	     "Examples:\n"
	     "  bpfc fubar\n"
	     "  bpfc fubar > foo (bpfc -f C -i fubar > foo) -->  netsniff-ng -f foo ...\n"
	     "  bpfc -f tcpdump -i fubar > foo -->  tcpdump -ddd like ...\n"
	     "  bpfc -f xt_bpf -b -p -i fubar\n"
	     "  iptables -A INPUT -m bpf --bytecode \"`./bpfc -f xt_bpf -i fubar`\" -j LOG\n"
	     "  bpfc -   (read from stdin)\n"
	     "Note:\n"
	     "  Generation of seccomp-BPF filters are fully supported as well.\n");
	puts(copyright);
	die();
}

static void __noreturn version(void)
{
	printf("bpfc %s, Git id: %s\n", VERSION_LONG, GITVERSION);
	puts("a tiny BPF compiler\n"
	     "http://www.netsniff-ng.org\n");
	puts(copyright);
	die();
}

int main(int argc, char **argv)
{
	int ret, verbose = 0, c, opt_index, bypass = 0, format = 0;
	bool invoke_cpp = false;
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
		case 'p':
			invoke_cpp = true;
			break;
		case 'f':
			if (!strncmp(optarg, "C", 1) ||
			    !strncmp(optarg, "netsniff-ng", 11))
				format = 0;
			else if (!strncmp(optarg, "tcpdump", 7))
				format = 2;
			else if (!strncmp(optarg, "xt_bpf", 6) ||
				 !strncmp(optarg, "tc", 2))
				format = 1;
			else
				help();
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
			case 'f':
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

	ret = compile_filter(file, verbose, bypass, format, invoke_cpp);

	xfree(file);
	return ret;
}

/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
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

/*

=head1 NAME

bpfc - compile a BPF expression into BPF opcode

=head1 SYNOPSIS

bpfc -i|--input <program> [-V|--verbose][-v|--version][-h|--help]

=head1 DESCRIPTION

bpfc is a tool to generate BPF opcode from a literal expression.
The generated BPF opcode then can be used to filter out the
corresponding traffic.

=head1 EXAMPLES

=over

=item bpfc --input example.bpf

Transform the literal expression in example.bpf into BPF opcodes

=back

=head1 OPTIONS

=over

=item -i|--input <program>

Path to Berkeley Packet Filter file.

=item -V|--verbose

Increase program verbosity

=item -v|--version

Print version.

=item -h|--help

Print help text and lists all options.

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
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>

#include "xmalloc.h"
#include "die.h"

static const char *short_options = "vhi:V";

static struct option long_options[] = {
	{"input", required_argument, 0, 'i'},
	{"verbose", no_argument, 0, 'V'},
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};

extern int compile_filter(char *file, int verbose);

static void help(void)
{
	printf("\nbpfc %s, a tiny BPF compiler\n", VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Usage: bpfc [options] || bpfc <program>\n");
	printf("Options:\n");
	printf("  -i|--input <program>   Berkeley Packet Filter file\n");
	printf("  -V|--verbose           Be more verbose\n");
	printf("  -v|--version           Print version\n");
	printf("  -h|--help              Print this help\n");
	printf("\n");
	printf("Examples:\n");
	printf("  bpfc -i fubar.bpf\n\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2011-2012 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,\n");
	printf("Swiss federal institute of technology (ETH Zurich)\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");
	die();
}

static void version(void)
{
	printf("\nbpfc %s, a tiny BPF compiler\n", VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2011-2012 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,\n");
	printf("Swiss federal institute of technology (ETH Zurich)\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");
	die();
}

int main(int argc, char **argv)
{
	int ret, verbose = 0, c, opt_index;
	char *file = NULL;

	if (argc == 1)
		help();

	while (argc > 2 && (c = getopt_long(argc, argv, short_options,
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
					whine("Unknown option character "
					      "`0x%X\'!\n", optopt);
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

	ret = compile_filter(file, verbose);

	xfree(file);

	return ret;
}

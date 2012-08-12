/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2012 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <ctype.h>

#include "xmalloc.h"
#include "die.h"

static const char *short_options = "vhm:b:";

static struct option long_options[] = {
	{"mgmt", required_argument, 0, 'm'},
	{"batch", required_argument, 0, 'b'},
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};

static void help(void)
{
	printf("\ngremlin %s, a threaded packet beast with Cisco-cli\n",
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Usage: gremlin [options]\n");
	printf("Options:\n");
	printf("  -m|--mgmt <dev>        Bound management netdev\n");
	printf("  -b|--batch <file>      Batch file to process\n");
	printf("  -v|--version           Print version\n");
	printf("  -h|--help              Print this help\n");
	printf("\n");
	printf("Examples:\n");
	printf("  gremlin --mgmt eth5\n");
	printf("  gremlin --batch cli-test.batch\n");
	printf("\n");
	printf("Note:\n");
	printf("  gremlin uses parts of Herbert Haas' legendary Mausezahn\n");
	printf("  traffic generator. Its backend was replaced for reasons of\n");
	printf("  better performance and its functionality was extended.\n");
	printf("\n");
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
	printf("\ngremlin %s, a threaded packet beast with Cisco-cli\n",
	       VERSION_STRING);
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
	int ret, c, opt_index;
	char *file = NULL;
	char *netdev = NULL;

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
		case 'b':
			file = xstrdup(optarg);
			break;
		case 'm':
			netdev = xstrdup(optarg);
			break;
		case '?':
			switch (optopt) {
			case 'b':
			case 'm':
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

	if (!file && !netdev)
		help();

	/* XXX do stuff */

	free(file);
	free(netdev);

	return ret;
}

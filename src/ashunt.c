/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 *
 * An Autonomous System trace route utility based on TCP instead of ICMP for
 * (hopefully) passing firewalls. Supports IPv4 and IPv6. Based on the
 * idea of tcptraceroute (http://michael.toren.net/code/tcptraceroute/).
 */

#include <stdio.h>
#include <stdlib.h>

#include "die.h"
#include "version.h"

static void help(void)
{

	printf("\nashunt %s, AS trace route utility\n",
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Usage: ashunt [options]\n");
	printf("Options:\n");
	printf(" -H|--host <host>     Host/IPv4/IPv6 to lookup AS route to\n");
	printf(" -p|--port <port>     Hosts port to lookup AS route to\n");
	printf(" -w|--whois <server>  Use a different AS whois DB server\n");
	printf("                      default from /etc/ashunt is whois.cymru.com\n");
	printf(" -W|--wport <port>    Use a different port to AS whois server\n");
	printf("                      default: 49\n");
	printf(" -v|--version         Print version\n");
	printf(" -h|--help            Print this help\n");
	printf("\n");
	printf("Examples:\n");
	printf(" ashunt -H netsniff-ng.org -p 80\n");
	printf("\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,\n");
	printf("Swiss federal institute of technology (ETH Zurich)\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");

	die();
}

static void version(void)
{
	printf("\nashunt %s, AS trace route utility\n",
	       VERSION_STRING);
	printf("http://www.netsniff-ng.org\n\n");
	printf("Please report bugs to <bugs@netsniff-ng.org>\n");
	printf("Copyright (C) 2011 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,\n");
	printf("Swiss federal institute of technology (ETH Zurich)\n");
	printf("License: GNU GPL version 2\n");
	printf("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n\n");

	die();
}

int main(int argc, char **argv)
{
	help();
	return 0;
}


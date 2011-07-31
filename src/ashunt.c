/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 *
 * An Autonomous System trace route utility based on TCP instead of ICMP for
 * (hopefully) passing firewalls. Supports IPv4 and IPv6. Based on the
 * idea of tcptraceroute (http://michael.toren.net/code/tcptraceroute/), but
 * hacked for Autonomous Systems.
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
	printf(" -H|--host <host>        Host/IPv4/IPv6 to lookup AS route to\n");
	printf(" -p|--port <port>        Hosts port to lookup AS route to\n");
	printf(" -n|--num                Do not do reverse DNS lookup for hops\n");
	printf(" -N|--dns                Do a reverse DNS lookup for hops\n");
	printf(" -f|--init-ttl <ttl>     Set initial TTL\n");
	printf(" -m|--max-ttl <ttl>      Set maximum TTL (default: 30)\n");
	printf(" -P|--src-port <port>    Specify local source port (default: bind(2))\n");
	printf(" -s|--src-addr <addr>    Specify local source addr\n");
	printf(" -i|--dev <device>       Networking device, i.e. eth0\n");
	printf(" -q|--num-probes <num>   Number of probes for each hop (default: 3)\n");
	printf(" -x|--timeout <sec>      Probe response timeout in sec (default: 3)\n");
	printf(" -S|--syn                Set TCP SYN flag in packets\n");
	printf(" -A|--ack                Set TCP ACK flag in packets\n");
	printf(" -E|--ecn-syn            Send ECN SYN packets\n");
	printf(" -t|--tos <tos>          Set the IP TOS field\n");
	printf(" -F|--nofrag             Set do not fragment bit\n");
	printf(" -l|--totlen <len>       Specify total packet len\n");
	printf(" -w|--whois <server>     Use a different AS whois DB server\n");
	printf("                         (default: /etc/netsniff-ng/whois.conf)\n");
	printf(" -W|--wport <port>       Use a different port to AS whois server\n");
	printf("                         (default: 49, /etc/netsniff-ng/whois.conf)\n");
	printf(" -v|--version            Print version\n");
	printf(" -h|--help               Print this help\n");
	printf("\n");
	printf("Examples:\n");
	printf("  trace AS up to netsniff-ng.org:80:\n");
	printf("  ashunt -i eth0 -H netsniff-ng.org -p 80\n");
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


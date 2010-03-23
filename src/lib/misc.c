/*
 * Copyright (C) 2009, 2010  Daniel Borkmann <daniel@netsniff-ng.org> and 
 *                           Emmanuel Roullit <emmanuel@netsniff-ng.org>
 *
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation; either version 2 of the License, or (at 
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License 
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
 */

/*
 * Contains: 
 *    Some miscellaneous stuff
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netsniff-ng/macros.h>
#include <netsniff-ng/system.h>
#include <netsniff-ng/misc.h>
#include <netsniff-ng/netdev.h>
#include <netsniff-ng/tx_ring.h>

/**
 * help - Prints help
 */
void help(void)
{
	info("%s %s\n\n", PROGNAME_STRING, VERSION_STRING);
	info("%s is a high performance network sniffer for packet\n", PROGNAME_STRING);
	info("inspection that acts as a raw socket sniffer with kernelspace\n");
	info("bpf and a \"zero-copy\" mode receive/transmit ring.\n");
	info("\n");
	info("Options for net dev:\n");
	info("  -d|--dev <arg>         Use device <arg> for capturing packets, e.g. `eth0`\n");
	info("\n");
	info("Options for packet dumping/replaying:\n");
	info("  -p|--dump <arg>        Dump all matching packets in a pcap file,\n");
	info("                         for a better performance combine with -s|--silent\n");
	info("  -r|--replay <arg>      Replay all packets from a pcap file\n");
	info("\n");
	info("Options for packet filtering:\n");
	info("  -f|--filter <arg>      Use file <arg> as packet filter\n");
	info("  -t|--type <arg>        Only show packets of type <arg> (slower than BPF)\n");
/*	info("                           `host`      - to us\n");
	info("                           `broadcast` - to all\n");
	info("                           `multicast` - to group\n");
	info("                           `others`    - to others\n");
	info("                           `outgoing`  - from us\n");  */
	info("  -g|--generate <arg>    Generate packet filter code for <arg>\n");
	info("\n");
	info("Options for system scheduler/process:\n");
	info("  -b|--bind-cpu <arg>    Bind process to specific CPU/CPU-range\n");
	info("  -B|--unbind-cpu <arg>  Forbid process to use specific CPU/CPU-range\n");
	info("  -H|--prio-norm         Do not high priorize process\n");
	info("  -n|--non-block         Non-blocking packet capturing mode\n");
	info("\n");
	info("Options for packet printing:\n");
	info("  -s|--silent            Do not print captured packets (silent mode)\n");
	info("  -q|--less              Print less-verbose packet information\n");
	info("  -l|--payload           Only print human-readable payload\n");
	info("  -x|--payload-hex       Only print payload in hex format\n");
	info("  -X|--all-hex           Print packets in hex format\n");
	info("  -N|--no-payload        Only print packet header\n");
	info("  -e|--regex <arg>       Only print package that matches regex <arg>\n");
	info("\n");
	info("Options for system daemon:\n");
	info("  -D|--daemonize         Run as sys daemon\n");
	info("  -P|--pidfile <arg>     Use file <arg> as pidfile (required if -D)\n");
	info("  -p|--dump <arg>        Dump all matching packets in a pcap file\n");
	info("                         (required if -D)\n");
	info("\n");
	info("Options, misc:\n");
	info("  -v|--version           Print version\n");
	info("  -h|--help              Print this help\n");
	info("\n");
	info("Note:\n");
	info("  - Sending a SIGUSR1 will show current packet statistics\n");
	info("  - For more help try \'man netsniff-ng\'\n");
	info("\n");
	info("Please report bugs to <daniel@netsniff-ng.org>\n");
	info("Copyright (C) 2009, 2010 Daniel Borkmann and Emmanuel Roullit\n");
	info("License: GNU GPL version 2\n");
	info("This is free software: you are free to change and redistribute it.\n");
	info("There is NO WARRANTY, to the extent permitted by law.\n");

	exit(EXIT_SUCCESS);
}

/**
 * version - Prints version
 */
void version(void)
{
	info("%s %s\n\n", PROGNAME_STRING, VERSION_STRING);
	info("%s is a high performance network sniffer for packet\n", PROGNAME_STRING);
	info("inspection that acts as a raw socket sniffer with kernelspace\n");
	info("bpf and a \"zero-copy\" mode receive/transmit ring.\n\n");
#ifdef __HAVE_TX_RING__
	info("Compiled with transmit ring functionality :)\n\n");
#else
	info("Compiled without transmit ring functionality :(\n\n");
#endif
	info("%s", MOOH);	/* ;) */
	info("\n");
	info("%s can be used for protocol analysis and\n"
	     "reverse engineering, network debugging, measurement of\n"
	     "performance throughput or network statistics creation of\nincoming packets.\n", PROGNAME_STRING);
	info("\n");
	info("Please report bugs to <daniel@netsniff-ng.org>\n");
	info("Copyright (C) 2009, 2010 Daniel Borkmann and Emmanuel Roullit\n");
	info("License: GNU GPL version 2\n");
	info("This is free software: you are free to change and redistribute it.\n");
	info("There is NO WARRANTY, to the extent permitted by law.\n");

	exit(EXIT_SUCCESS);
}

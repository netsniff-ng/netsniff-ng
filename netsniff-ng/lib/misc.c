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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <netsniff-ng/macros.h>
#include <netsniff-ng/version.h>
#include <netsniff-ng/system.h>
#include <netsniff-ng/misc.h>
#include <netsniff-ng/netdev.h>
#include <netsniff-ng/tx_ring.h>

/**
 * help - Prints help
 */
void help(void)
{
	info("\n%s %s, the packet sniffing beast\n", PROGNAME_STRING, VERSION_STRING);
	info("http://www.netsniff-ng.org\n\n");
	info("Usage: netsniff-ng [options]\n");
	info("\n");
	info("Options for net dev:\n");
	info("  -d|--dev <netdev>      Use device for capturing packets\n");
	info("  -I|--info              Print network device information\n");
	info("  -M|--no-promisc        No promiscuous mode for device\n");
	info("\n");
	info("Options for packet dumping/replaying:\n");
	info("  -p|--dump <file>       Dump packets in a pcap file\n");
	info("                         for a better performance combine\n");
	info("                         with -s|--silent\n");
	info("  -r|--replay <file>     Replay all packets from a pcap file\n");
	info("  -i|--read <file>       Display packets from a pcap file\n");
	info("\n");
	info("Options for packet filtering:\n");
	info("  -f|--filter <file>     Use BPF filter from file\n");
	info("  -t|--type <type>       Only show packets of defined type\n");
	info("                         this is slower than BPF, types are\n");
	info("                         host|broadcast|multicast|others|outgoing\n");
	info("  -g|--generate <filter> Generate BPF code for expression\n");
	info("\n");
	info("Options for system scheduler/process:\n");
	info("  -b|--bind-cpu <cpu>    Bind to specific CPU/CPU-range,\n");
	info("                         for a better performance bind to a\n");
	info("                         single CPU reserved for netsniff-ng\n");
	info("  -B|--unbind-cpu <cpu>  Forbid to use specific CPU/CPU-range\n");
	info("  -H|--prio-norm         Do not high priorize process\n");
	info("  -Q|--notouch-irq       Do not touch IRQ CPU affinity of NIC\n");
	info("  -n|--non-block         Non-blocking packet capturing mode\n");
	info("\n");
	info("Options for receive and transmit ring:\n");
	info("  -S|--ring-size <size>  Manually set ring size to <arg>,\n");
	info("                         mmap space in KB/MB/GB, e.g. `100MB`\n");
	info("\n");
	info("Options for packet printing:\n");
	info("  -s|--silent            Do not print captured packets\n");
	info("  -q|--less              Print less-verbose packet information\n");
	info("  -l|--payload           Only print human-readable payload\n");
	info("  -x|--payload-hex       Only print payload in hex format\n");
	info("  -C|--c-style           Print full packet in C style hex format\n");
	info("  -X|--all-hex           Print packets in hex format\n");
	info("  -N|--no-payload        Only print packet header\n");
	info("  -e|--regex <expr>      Only print package that matches regex\n");
	info("\n");
	info("Options for system daemon:\n");
	info("  -D|--daemonize         Run as system daemon\n");
	info("  -P|--pidfile <file>    Specify a pidfile for the daemon\n");
	info("\n");
	info("Options, misc:\n");
	info("  -c|--compatibility-mode Activate compatibility mode to receive/send packets\n");
	info("  -v|--version           Print version\n");
	info("  -h|--help              Print this help\n");
	info("\n");
	info("Note:\n");
	info("  - Sending a SIGUSR1 will show current packet statistics\n");
	info("  - For more help try \'man netsniff-ng\'\n");
	info("  - Binding netsniff-ng to a specific CPU increases performance\n");
	info("    since NIC RX/TX interrupts will be bound to that CPU, too\n");
	info("\n");
	info("Examples:\n");
	info("  netsniff-ng --dev eth0 --dump out.pcap --silent --bind-cpu 0\n");
	info("  netsniff-ng --dev eth0 --replay out.pcap --bind-cpu 0\n");
	info("  netsniff-ng --read out.pcap --no-payload\n");
	info("  netsniff-ng --filter /etc/netsniff-ng/rules/icq.bpf\n");
	info("  netsniff-ng --regex \"user.*pass\"\n");
	info("  netsniff-ng --prio-norm --dev wlan0 --all-hex --type outgoing\n");
	info("\n");
	info("Please report bugs to <bugs@netsniff-ng.org>\n");
	info("Copyright (C) 2009, 2010 Daniel Borkmann and Emmanuel Roullit\n");
	info("License: GNU GPL version 2\n");
	info("This is free software: you are free to change and redistribute it.\n");
	info("There is NO WARRANTY, to the extent permitted by law.\n\n");

	exit(EXIT_SUCCESS);
}

/**
 * version - Prints version
 */
void version(void)
{
	info("\n%s %s, the packet sniffing beast\n", PROGNAME_STRING, VERSION_STRING);
	info("http://www.netsniff-ng.org\n\n");
#ifdef __HAVE_TX_RING__
	info("Compiled with transmit ring functionality :)\n\n");
#endif
	info("Please report bugs to <bugs@netsniff-ng.org>\n");
	info("Copyright (C) 2009, 2010 Daniel Borkmann and Emmanuel Roullit\n");
	info("License: GNU GPL version 2\n");
	info("This is free software: you are free to change and redistribute it.\n");
	info("There is NO WARRANTY, to the extent permitted by law.\n\n");

	exit(EXIT_SUCCESS);
}

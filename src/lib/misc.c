/* XXX: Coding Style - use the tool indent with the following (Linux kernel
 *                     code indents)
 *
 * indent -nbad -bap -nbc -bbo -hnl -br -brs -c33 -cd33 -ncdb -ce -ci4   \
 *        -cli0 -d0 -di1 -nfc1 -i8 -ip0 -l120 -lp -npcs -nprs -npsl -sai \
 *        -saf -saw -ncs -nsc -sob -nfca -cp33 -ss -ts8 -il1
 *
 *
 * netsniff-ng
 *
 * High performance network sniffer for packet inspection
 *
 * Copyright (C) 2009, 2010  Daniel Borkmann <danborkmann@googlemail.com> and 
 *                           Emmanuel Roullit <emmanuel.roullit@googlemail.com>
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
 *
 * Note: Your kernel has to be compiled with CONFIG_PACKET_MMAP=y option in 
 *       order to use this.
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
	info("  -d|--dev <arg>         use device <arg> for capturing packets, e.g. `eth0`\n");
	info("\n");
	info("Options for packet dumping/replaying:\n");
	info("  -p|--dump <arg>        dump all matching packets in a pcap file\n");
	info("                         for a better performance, combine with -s|--silent\n");
	info("  -r|--replay <arg>      replay all packets from a pcap dump file\n");
	info("  -q|--quit-after <arg>  quit dump/replay after <arg> pckts / <arg> MB\n");
	info("\n");
	info("Options for packet filtering:\n");
	info("  -f|--filter <arg>      use file <arg> as packet filter\n");
	info("  -t|--type <arg>        only show packets of type (slower non-BPF)\n");
/*	info("                           `host`      - to us\n");
	info("                           `broadcast` - to all\n");
	info("                           `multicast` - to group\n");
	info("                           `others`    - to others\n");
	info("                           `outgoing`  - from us\n");  */
	info("  -g|--generate <arg>    generate packet filter code according to <arg>\n");
	info("\n");
	info("Options for system scheduler/process:\n");
	info("  -b|--bind-cpu <arg>    bind process to specific CPU/CPU-range\n");
	info("  -B|--unbind-cpu <arg>  forbid process to use specific CPU/CPU-range\n");
	info("  -H|--prio-norm         do not high priorize process\n");
	info("  -n|--non-block         non-blocking packet capturing mode\n");
	info("\n");
	info("Options for packet printing:\n");
	info("  -s|--silent            do not print captured packets (silent mode)\n");
	info("\n");
	info("Options for system daemon:\n");
	info("  -D|--daemonize         run as sys daemon\n");
	info("  -P|--pidfile <arg>     use file <arg> as pidfile (required if -D)\n");
	info("  -p|--dump <arg>        dump all matching packets in a pcap file (required if -D)\n");
	info("\n");
	info("Options, misc:\n");
	info("  -v|--version           prints out version\n");
	info("  -h|--help              prints out this help\n");
	info("\n");
	info("Note:\n");
	info("  - Sending a SIGUSR1 will show current packet statistics\n");
	info("  - For more help type \'man netsniff-ng\'\n");
	info("\n");
	info("Please report bugs to <danborkmann@googlemail.com>\n");
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
	info("%s", MOOH);	/* ;) */
	info("\n");
	info("%s can be used for protocol analysis and\n"
	     "reverse engineering, network debugging, measurement of\n"
	     "performance throughput or network statistics creation of\nincoming packets.\n", PROGNAME_STRING);
	info("\n");
	info("Please report bugs to <danborkmann@googlemail.com>\n");
	info("Copyright (C) 2009, 2010 Daniel Borkmann and Emmanuel Roullit\n");
	info("License: GNU GPL version 2\n");
	info("This is free software: you are free to change and redistribute it.\n");
	info("There is NO WARRANTY, to the extent permitted by law.\n");

	exit(EXIT_SUCCESS);
}

/**
 * header - Prints program startup header
 */
void header(void)
{
	int ret;
	size_t len;
	char *cpu_string;

	struct sched_param sp;

	len = sysconf(_SC_NPROCESSORS_CONF) + 1;

	cpu_string = malloc(len);
	if (!cpu_string) {
		err("No mem left");
		exit(EXIT_FAILURE);
	}

	ret = sched_getparam(getpid(), &sp);
	if (ret) {
		err("Cannot determine sched prio");
		exit(EXIT_FAILURE);
	}

	info("%s -- pid (%d)\n\n", colorize_full_str(red, white, PROGNAME_STRING " " VERSION_STRING), (int)getpid());

	info("nice (%d), scheduler (%d prio %d)\n",
	     getpriority(PRIO_PROCESS, getpid()), sched_getscheduler(getpid()), sp.sched_priority);

	info("%ld of %ld CPUs online, affinity bitstring (%s)\n\n",
	     sysconf(_SC_NPROCESSORS_ONLN), sysconf(_SC_NPROCESSORS_CONF), get_cpu_affinity(cpu_string, len));

	free(cpu_string);

	print_device_info();

	info("\n");
}

/* XXX: Coding Style - use the tool indent with the following (Linux kernel
 *                     code indents)
 *
 * indent -nbad -bap -nbc -bbo -hnl -br -brs -c33 -cd33 -ncdb -ce -ci4  \
 *        -cli0 -d0 -di1 -nfc1 -i8 -ip0 -l80 -lp -npcs -nprs -npsl -sai \
 *        -saf -saw -ncs -nsc -sob -nfca -cp33 -ss -ts8 -il1
 *
 *
 * netsniff-ng
 *
 * High performance network sniffer for packet inspection
 *
 * Copyright (C) 2009, 2010  Daniel Borkmann <danborkmann@googlemail.com>
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

#include <netsniff-ng/macros.h>
#include <netsniff-ng/system.h>
#include <netsniff-ng/misc.h>

/**
 * help - Prints help
 */
void help(void)
{
	printf("%s %s\n\n", PROGNAME_STRING, VERSION_STRING);
	printf("%s is a high performance network sniffer for packet\n",
	       PROGNAME_STRING);
	printf
	    ("inspection that acts as a raw socket sniffer with kernelspace\n");
	printf("bpf and a \"zero-copy\" mode receive/transmit ring.\n");
	printf("\n");
	printf("Options, mandatory:\n");
	printf
	    ("  -d|--dev <arg>         use device <arg> for capturing packets, e.g. `eth0`\n");
	printf("\n");
	printf("Options for packet dumping/replaying:\n");
	printf
	    ("  -p|--dump <arg>        dump all matching packets in a pcap file\n");
	printf
	    ("  -r|--replay <arg>      replay all packets from a pcap dump file\n");
	printf
	    ("  -q|--quit-after <arg>  quit dump/replay after <arg> pckts / <arg> MB\n");
	printf("\n");
	printf("Options for packet filtering:\n");
	printf("  -f|--filter <arg>      use file <arg> as packet filter\n");
	printf
	    ("  -g|--generate <arg>    generate packet filter code according to <arg>\n");
	printf("\n");
	printf("Options for system scheduler/process:\n");
	printf
	    ("  -b|--bind-cpu <arg>    bind process to specific CPU/CPU-range\n");
	printf
	    ("  -B|--unbind-cpu <arg>  forbid process to use specific CPU/CPU-range\n");
	printf("  -H|--prio-norm         do not high priorize process\n");
	printf("  -n|--non-block         non-blocking packet capturing mode\n");
	printf("\n");
	printf("Options for packet printing:\n");
	printf
	    ("  -N|--no-color          do not colorize captured packet output\n");
	printf
	    ("  -s|--silent            do not print captured packets (silent mode)\n");
	printf("\n");
	printf("Options for system daemon:\n");
	printf("  -D|--daemonize         run as sys daemon\n");
	printf
	    ("  -P|--pidfile <arg>     use file <arg> as pidfile (required if -D)\n");
	printf
	    ("  -L|--logfile <arg>     use file <arg> as logfile (required if -D)\n");
	printf
	    ("  -S|--sockfile <arg>    use file <arg> as uds inode (required if -D)\n");
	printf("\n");
	printf("Options, misc:\n");
	printf("  -v|--version           prints out version\n");
	printf("  -h|--help              prints out this help\n");
	printf("\n");
	printf("Note:\n");
	printf("  - Sending a SIGUSR1 will show current packet statistics\n");
	printf
	    ("  - Sending a SIGUSR2 will toggle silent and packet printing mode\n");
	printf("  - For more help type \'man netsniff-ng\'\n");
	printf("\n");
	printf("Please report bugs to <danborkmann@googlemail.com>\n");
	printf
	    ("Copyright (C) 2009, 2010 Daniel Borkmann and Emmanuel Roullit\n");
	printf("License: GNU GPL version 2\n");
	printf
	    ("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n");

	exit(EXIT_SUCCESS);
}

/**
 * version - Prints version
 */
void version(void)
{
	printf("%s %s\n\n", PROGNAME_STRING, VERSION_STRING);
	printf("%s is a high performance network sniffer for packet\n",
	       PROGNAME_STRING);
	printf
	    ("inspection that acts as a raw socket sniffer with kernelspace\n");
	printf("bpf and a \"zero-copy\" mode receive/transmit ring.\n\n");
	printf("%s", MOOH);	/* ;) */
	printf("\n");
	printf("%s can be used for protocol analysis and\n"
	       "reverse engineering, network debugging, measurement of\n"
	       "performance throughput or network statistics creation of\n"
	       "incoming packets on central network nodes like routers\n"
	       "or firewalls.\n", PROGNAME_STRING);
	printf("\n");
	printf("Please report bugs to <danborkmann@googlemail.com>\n");
	printf
	    ("Copyright (C) 2009, 2010 Daniel Borkmann and Emmanuel Roullit\n");
	printf("License: GNU GPL version 2\n");
	printf
	    ("This is free software: you are free to change and redistribute it.\n");
	printf("There is NO WARRANTY, to the extent permitted by law.\n");

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
		perr("No mem left\n");
		exit(EXIT_FAILURE);
	}

	ret = sched_getparam(getpid(), &sp);
	if (ret) {
		perr("Cannot determine sched prio\n");
		exit(EXIT_FAILURE);
	}

	info("%s %s -- pid (%d)\n\n", PROGNAME_STRING, VERSION_STRING,
	     (int)getpid());

	info("nice (%d), scheduler (%d prio %d)\n",
	     getpriority(PRIO_PROCESS, getpid()),
	     sched_getscheduler(getpid()), sp.sched_priority);

	info("%ld of %ld CPUs online, affinity bitstring (%s)\n\n",
	     sysconf(_SC_NPROCESSORS_ONLN),
	     sysconf(_SC_NPROCESSORS_CONF), get_cpu_affinity(cpu_string, len));

	free(cpu_string);
}

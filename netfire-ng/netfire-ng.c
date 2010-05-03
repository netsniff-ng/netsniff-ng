/*
 * Copyright (C) 2010  Daniel Borkmann <daniel@netsniff-ng.org>
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
 * Specification from kernel.org:
 * 
 * Enable CONFIG_NET_PKTGEN to compile and build pktgen.o either in kernel
 * or as module. Module is preferred. insmod pktgen if needed. Once running
 * pktgen creates a thread on each CPU where each thread has affinity to its CPU.
 * Monitoring and controlling is done via /proc. Easiest to select a suitable 
 * a sample script and configure.
 * 
 * On a dual CPU:
 * 
 * ps aux | grep pkt
 * root       129  0.3  0.0     0    0 ?        SW    2003 523:20 [pktgen/0]
 * root       130  0.3  0.0     0    0 ?        SW    2003 509:50 [pktgen/1]
 * 
 * For monitoring and control pktgen creates:
 * 	/proc/net/pktgen/pgctrl
 * 	/proc/net/pktgen/kpktgend_X
 *         /proc/net/pktgen/ethX
 * 
 * Viewing threads
 * ===============
 * /proc/net/pktgen/kpktgend_0 
 * Name: kpktgend_0  max_before_softirq: 10000
 * Running: 
 * Stopped: eth1 
 * Result: OK: max_before_softirq=10000
 * 
 * Most important the devices assigned to thread. Note! A device can only belong 
 * to one thread.
 * 
 * Viewing devices
 * ===============
 * 
 * Parm section holds configured info. Current hold running stats. 
 * Result is printed after run or after interruption. Example:
 * 
 * /proc/net/pktgen/eth1       
 * 
 * Params: count 10000000  min_pkt_size: 60  max_pkt_size: 60
 *      frags: 0  delay: 0  clone_skb: 1000000  ifname: eth1
 *      flows: 0 flowlen: 0
 *      dst_min: 10.10.11.2  dst_max: 
 *      src_min:   src_max: 
 *      src_mac: 00:00:00:00:00:00  dst_mac: 00:04:23:AC:FD:82
 *      udp_src_min: 9  udp_src_max: 9  udp_dst_min: 9  udp_dst_max: 9
 *      src_mac_count: 0  dst_mac_count: 0 
 *      Flags: 
 * Current:
 *      pkts-sofar: 10000000  errors: 39664
 *      started: 1103053986245187us  stopped: 1103053999346329us idle: 880401us
 *      seq_num: 10000011  cur_dst_mac_offset: 0  cur_src_mac_offset: 0
 *      cur_saddr: 0x10a0a0a  cur_daddr: 0x20b0a0a
 *      cur_udp_dst: 9  cur_udp_src: 9
 *      flows: 0
 * Result: OK: 13101142(c12220741+d880401) usec, 10000000 (60byte,0frags)
 *   763292pps 390Mb/sec (390805504bps) errors: 39664
 * 
 * Configuring threads and devices
 * ================================
 * This is done via the /proc interface easiest done via pgset in the scripts
 * 
 * Examples:
 * 
 *  pgset "clone_skb 1"     sets the number of copies of the same packet
 *  pgset "clone_skb 0"     use single SKB for all transmits
 *  pgset "pkt_size 9014"   sets packet size to 9014
 *  pgset "frags 5"         packet will consist of 5 fragments
 *  pgset "count 200000"    sets number of packets to send, set to zero
 *                          for continuous sends until explicitly stopped.
 * 
 *  pgset "delay 5000"      adds delay to hard_start_xmit(). nanoseconds
 * 
 *  pgset "dst 10.0.0.1"    sets IP destination address
 *                          (BEWARE! This generator is very aggressive!)
 * 
 *  pgset "dst_min 10.0.0.1"            Same as dst
 *  pgset "dst_max 10.0.0.254"          Set the maximum destination IP.
 *  pgset "src_min 10.0.0.1"            Set the minimum (or only) source IP.
 *  pgset "src_max 10.0.0.254"          Set the maximum source IP.
 *  pgset "dst6 fec0::1"     IPV6 destination address
 *  pgset "src6 fec0::2"     IPV6 source address
 *  pgset "dstmac 00:00:00:00:00:00"    sets MAC destination address
 *  pgset "srcmac 00:00:00:00:00:00"    sets MAC source address
 * 
 *  pgset "src_mac_count 1" Sets the number of MACs we'll range through.  
 *                          The 'minimum' MAC is what you set with srcmac.
 * 
 *  pgset "dst_mac_count 1" Sets the number of MACs we'll range through.
 *                          The 'minimum' MAC is what you set with dstmac.
 * 
 *  pgset "flag [name]"     Set a flag to determine behaviour.  Current flags
 *                          are: IPSRC_RND #IP Source is random (between min/max),
 *                               IPDST_RND, UDPSRC_RND,
 *                               UDPDST_RND, MACSRC_RND, MACDST_RND 
 *                               MPLS_RND, VID_RND, SVID_RND
 * 
 *  pgset "udp_src_min 9"   set UDP source port min, If < udp_src_max, then
 *                          cycle through the port range.
 * 
 *  pgset "udp_src_max 9"   set UDP source port max.
 *  pgset "udp_dst_min 9"   set UDP destination port min, If < udp_dst_max, then
 *                          cycle through the port range.
 *  pgset "udp_dst_max 9"   set UDP destination port max.
 * 
 *  pgset "mpls 0001000a,0002000a,0000000a" set MPLS labels (in this example
 *                                          outer label=16,middle label=32,
 * 					 inner label=0 (IPv4 NULL)) Note that
 * 					 there must be no spaces between the
 * 					 arguments. Leading zeros are required.
 * 					 Do not set the bottom of stack bit,
 * 					 that's done automatically. If you do
 * 					 set the bottom of stack bit, that
 * 					 indicates that you want to randomly
 * 					 generate that address and the flag
 * 					 MPLS_RND will be turned on. You
 * 					 can have any mix of random and fixed
 * 					 labels in the label stack.
 * 
 *  pgset "mpls 0"           turn off mpls (or any invalid argument works too!)
 * 
 *  pgset "vlan_id 77"       set VLAN ID 0-4095
 *  pgset "vlan_p 3"         set priority bit 0-7 (default 0)
 *  pgset "vlan_cfi 0"       set canonical format identifier 0-1 (default 0)
 * 
 *  pgset "svlan_id 22"      set SVLAN ID 0-4095
 *  pgset "svlan_p 3"        set priority bit 0-7 (default 0)
 *  pgset "svlan_cfi 0"      set canonical format identifier 0-1 (default 0)
 * 
 *  pgset "vlan_id 9999"     > 4095 remove vlan and svlan tags
 *  pgset "svlan 9999"       > 4095 remove svlan tag
 * 
 * 
 *  pgset "tos XX"           set former IPv4 TOS field (e.g. "tos 28" for AF11 
 *                           no ECN, default 00)
 *  pgset "traffic_class XX" set former IPv6 TRAFFIC CLASS (e.g. 
 *                           "traffic_class B8" for EF no ECN, default 00)
 * 
 *  pgset stop    	          aborts injection. Also, ^C aborts generator.
 * 
 * Interrupt affinity
 * ===================
 * Note when adding devices to a specific CPU there good idea to also assign 
 * /proc/irq/XX/smp_affinity so the TX-interrupts gets bound to the same CPU.
 * as this reduces cache bouncing when freeing skb's.
 * 
 * Current commands and configuration options
 * ==========================================
 * 
 * ** Pgcontrol commands:
 * 
 * start
 * stop
 * 
 * ** Thread commands:
 * 
 * add_device
 * rem_device_all
 * max_before_softirq
 * 
 * ** Device commands:
 * 
 * count
 * clone_skb
 * debug
 * 
 * frags
 * delay
 * 
 * src_mac_count
 * dst_mac_count
 * 
 * pkt_size 
 * min_pkt_size
 * max_pkt_size
 * 
 * mpls
 * 
 * udp_src_min
 * udp_src_max
 * 
 * udp_dst_min
 * udp_dst_max
 * 
 * flag
 *   IPSRC_RND
 *   TXSIZE_RND
 *   IPDST_RND
 *   UDPSRC_RND
 *   UDPDST_RND
 *   MACSRC_RND
 *   MACDST_RND
 * 
 * dst_min
 * dst_max
 * 
 * src_min
 * src_max
 * 
 * dst_mac
 * src_mac
 * 
 * clear_counters
 * 
 * dst6
 * src6
 * 
 * flows
 * flowlen
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <stdarg.h>
#include <getopt.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>

#include <netfire-ng/macros.h>

#define PROGNAME_STRING "netfire-ng"
#define VERSION_STRING  "0.5.5.0"

#define PKTGEN_PATH     "/proc/net/pktgen/"
#define PKTGEN_MODP     "modprobe pktgen"

#define STATE_NET_DEV   1
#define STATE_NUM_PKT   2
#define STATE_MIN_PKT   3
#define STATE_MAX_PKT   4
#define STATE_CLN_SKB   5
#define STATE_NUM_FRA   6
#define STATE_LEN_DEL   7
#define STATE_RND_SIP   8
#define STATE_RND_DIP   9
#define STATE_RND_SUD  10
#define STATE_RND_DUD  11
#define STATE_RND_SMA  12
#define STATE_RND_DMA  13
#define STATE_RND_SIL  14
#define STATE_RND_SIG  15
#define STATE_RND_DIL  16
#define STATE_RND_DIG  17

struct config {
	int dummy;
};

static struct option long_options[] = {
	{"import",  required_argument, 0, 'i'},
	{"guide",   no_argument,       0, 'g'},
	{"version", no_argument,       0, 'v'},
	{"help",    no_argument,       0, 'h'},
	{0, 0, 0, 0}
};

static void help(void)
{
	info("\n%s %s\n", PROGNAME_STRING, VERSION_STRING);
	info("http://www.netsniff-ng.org\n\n");
	info("netfire-ng is a frontend for the high-performance Linux kernel\n");
	info("packet generator (pktgen).\n");
	info("\n");
	info("Usage: netfire-ng [options]\n");
	info("\n");
	info("Options:\n");
	info("  -g|--guide             Interactive configuration mode (default)\n");
	info("  -i|--import <arg>      Parses configuration file <arg> and starts\n");
	info("  -v|--version           Print version\n");
	info("  -h|--help              Print this help\n");
	info("\n");
	info("Note:\n");
	info("  - netfire-ng without any options means interactive mode.\n");
	info("  - For more help try \'man netfire-ng\'\n");
	info("\n");
	info("Please report bugs to <bugs@netsniff-ng.org>\n");
	info("Copyright (C) 2010 Daniel Borkmann\n");
	info("License: GNU GPL version 2\n");
	info("This is free software: you are free to change and redistribute it.\n");
	info("There is NO WARRANTY, to the extent permitted by law.\n");

	exit(EXIT_SUCCESS);
}

static void version(void)
{
	info("\n%s %s\n", PROGNAME_STRING, VERSION_STRING);
	info("http://www.netsniff-ng.org\n\n");
	info("netfire-ng is a frontend for the high-performance Linux kernel\n");
	info("packet generator (pktgen).\n");
	info("\n");
	info("%s", MOOH);	/* ;) */
	info("\n");
	info("netfire-ng can be used to generate high bandwidth and very high\n");
	info("packet rates to load routers, bridges or other networking devices.\n");
	info("netfire-ng is part of the netsniff-ng suite.\n");
	info("\n");
	info("Please report bugs to <bugs@netsniff-ng.org>\n");
	info("Copyright (C) 2010 Daniel Borkmann\n");
	info("License: GNU GPL version 2\n");
	info("This is free software: you are free to change and redistribute it.\n");
	info("There is NO WARRANTY, to the extent permitted by law.\n");

	exit(EXIT_SUCCESS);
}

static void print_header(void)
{
	info("%s -- pid (%u)\n\n", 
	     colorize_full_str(red, white, PROGNAME_STRING " " VERSION_STRING), 
	     getpid());
}

static int dummy(char *user, struct config *c)
{
	uint8_t newstate = 2;
	return newstate;
}

static int perform_question(char *question, char *defans, struct config *c, 
			    int (*callback)(char *user, struct config *c))
{
	uint8_t ret;

	char *user = NULL;
	char answer[256];

	do {
		memset(answer, 0, sizeof(answer));
		printf("%s [%s] ", question, defans);

		fgets(answer, sizeof(answer), stdin);
		answer[sizeof(answer) - 1] = 0;

		if(answer[0] == '\n')
			user = defans;
		else
			user = answer;
	} while((ret = callback(user, c)) < 0);

	return ret;
}

static void set_interactive_configuration(struct config *c)
{
	uint8_t state = STATE_NET_DEV;

	print_header();
	info("Starting interactive mode.\n\n");

	while(state != 0) {
		switch(state) {
		default:
		case STATE_NET_DEV:
			state = 
			perform_question("Networking devices?", 
					 "eth0,eth1", c, dummy);
			break;
		case STATE_NUM_PKT:
			state = 
			perform_question("Number of packets (0 = inf loop)?", 
					 "1000000", c, dummy);
			break;
		case STATE_MIN_PKT:
			state = 
			perform_question("Minimum packet size?", 
					 "60", c, dummy);
			break;
		case STATE_MAX_PKT:
			state = 
			perform_question("Maximum packet size?", 
					 "60", c, dummy);
			break;
		case STATE_CLN_SKB:
			state = 
			perform_question("Clone skbs (0 = single skb)?", 
					 "1000000", c, dummy);
			break;
		case STATE_NUM_FRA:
			state = 
			perform_question("Number fragments per packet?", 
					 "0", c, dummy);
			break;
		case STATE_LEN_DEL:
			state = 
			perform_question("Delay for hard_start_xmit (in ns)?", 
					 "5000", c, dummy);
			break;
		case STATE_RND_SIP:
			state = 
			perform_question("Random source IP (y/n)?", 
					 "Y", c, dummy);
			break;
		case STATE_RND_SIL:
			state = 
			perform_question("Source IP address min?", 
					 "192.168.0.1", c, dummy);
			break;
		case STATE_RND_SIG:
			state = 
			perform_question("Source IP address max?", 
					 "192.168.0.1", c, dummy);
			break;
		case STATE_RND_DIP:
			state = 
			perform_question("Random destination IP (y/n)?", 
					 "Y", c, dummy);
			break;
		case STATE_RND_DIL:
			state = 
			perform_question("Destination IP address min?", 
					 "192.168.0.1", c, dummy);
			break;
		case STATE_RND_DIG:
			state = 
			perform_question("Destination IP address max?", 
					 "192.168.0.1", c, dummy);
			break;
		case STATE_RND_SUD:
			state = 
			perform_question("Random UDP source port (y/n)?", 
					 "Y", c, dummy);
			break;
		case STATE_RND_DUD:
			state = 
			perform_question("Random UDP destination port (y/n)?", 
					 "Y", c, dummy);
			break;
		case STATE_RND_SMA:
			state = 
			perform_question("Random MAC source address (y/n)?", 
					 "Y", c, dummy);
			break;
		case STATE_RND_DMA:
			state = 
			perform_question("Random MAC destination address (y/n)?", 
					 "Y", c, dummy);
			break;

#if 0
	info("IP destination address min? [192.168.0.1] ");
	getchar();

	info("IP destination address max? [192.168.0.1] ");
	getchar();

	info("MAC source address? [00:00:00:00:00:00] ");
	getchar();

	info("Number source MACs to range through? [1] ");
	getchar();

	info("MAC destination address? [00:00:00:00:00:00] ");
	getchar();

	info("Number destination MACs to range through? [1] ");
	getchar();

	info("Which IPv4 TOS? [00] ");
	getchar();

	info("Which IPv6 traffic class? [00] ");
	getchar();

	info("Set up VLAN/SVLAN/MPLS/None? [none] ");
	getchar();

	info("Minimum VLAN id? [1000] ");
	getchar();

	info("Maximum VLAN id? [1000] ");
	getchar();

	info("VLAN priority bit (0-7)? [0] ");
	getchar();

	info("VLAN canonical format identifier (0-1)? [0] ");
	getchar();

	info("Which MPLS labels? [0001000a,0002000a,0000000a] ");
	getchar();
#endif	
		};
	}
}

static void set_file_configuration(char *file, struct config *conf)
{
	print_header();

	info("Parsing file config ... ");
	/* ... */
	info("done!\n");
}

static inline void init_configuration(struct config *conf)
{
	assert(conf);
}

static void set_argv_configuration(int argc, char **argv, struct config *conf)
{
	int c, opt_idx;

	assert(argv);
	assert(conf);

	while ((c = getopt_long(argc, argv, "i:gvh", long_options, 
				&opt_idx)) != EOF) {
		switch (c) {
		case 'h':
			help();
			break;
		case 'v':
			version();
			break;
		case 'i':
			set_file_configuration(optarg, conf);
			return;
		case 'g':
			set_interactive_configuration(conf);
			return;
		case '?':
			switch (optopt) {
			case 'i':
				printf("Option -%c requires an argument!\n", 
				       optopt);
				exit(EXIT_FAILURE);
			default:
				if (isprint(optopt)) {
					printf("Unknown option character "
					       "`0x%X\'!\n", optopt);
				}
				exit(EXIT_FAILURE);
			}

			return;
		default:
			abort();
		}
	}
}

static void check_configuration(struct config *c)
{
	assert(c);
}

static void bind_cpus_to_tx_intr(struct config *conf)
{
}

static void bootstrap_pktgen(struct config *conf)
{
	bind_cpus_to_tx_intr(conf);
}

static void fire_pktgen(void)
{
	info("\n%s\n", colorize_full_str(blue, white,".-+! Fire !+-."));
	info("\n");
}

int main(int argc, char **argv)
{
	struct config conf = {0};

	init_configuration(&conf);
	if(argc > 1)
		set_argv_configuration(argc, argv, &conf);
	else
		set_interactive_configuration(&conf);
	check_configuration(&conf);

	bootstrap_pktgen(&conf);
	fire_pktgen();

	return 0;
}

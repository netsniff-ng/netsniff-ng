/*
 * Mausezahn - A fast versatile traffic generator
 * Copyright (C) 2008-2010 Herbert Haas
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the 
 * Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more 
 * details.
 * 
 * You should have received a copy of the GNU General Public License along with 
 * this program; if not, see http://www.gnu.org/licenses/gpl-2.0.html
 * 
*/



#include "mz.h"
#include "cli.h"
#include "mops.h"
#include "llist.h"

void mz_cli_init()
{
	amp_head = automops_init();
	
	// Initialize default credentials (will be overwritten by mz.cfg)
	strcpy(mz_username, MZ_DEFAULT_USERNAME);
	strcpy(mz_password, MZ_DEFAULT_PASSWORD);
	strcpy(mz_enable, MZ_DEFAULT_ENABLE_PASSWORD);
	
	// read login credentials from config file
	if (cli_read_cfg("mz.cfg")) {
		fprintf(stderr, "mz: Problems opening config file. Will use defaults\n");
	}

	if ((verbose) && (AUTOMOPS_ENABLED)) {
		automops_dump_all(amp_head);
		fprintf(stderr, "------------ MOPS/CLI initialization completed ------------\n");
	}
}




// Read in configuration file
int cli_read_cfg(char *str)
{
	char filename[256];
	char line[256];
	char path[256];
	char *ampfile;
	char dev[256];
	FILE *fd;
	int i, j=0, len, found=0, nonspc=0;
	int user=0, pass=0, ena=0, amp=0, mgmt_only=0, cli=0;
	
	strncpy(filename, str, 255);
	 
	if (getfullpath_cfg(filename)) return 1;

	if (verbose) {
		fprintf(stderr, "Opening config file %s...\n", filename);
	}
	
	fd = fopen (filename, "r");
	if (fd==NULL) return 1;
	
	while (fgets(line, 255, fd) != NULL) {
		len=strnlen(line, 255);
		// Take string left side of # (comments)
		if (len) for(i=0;i<len;i++) if (line[i]=='#') line[i]='\0'; // cut off
		len=strnlen(line, 255); 
		if (len) for(i=0;i<len;i++) if (!isspace(line[i])) nonspc++;
		if (nonspc==0) continue; else nonspc=0;
		if (!user) user = sscanf(line, " user = %s ", mz_username);
		if (!pass) pass = sscanf(line, " password = %s ", mz_password);
		if (!ena) ena  = sscanf(line, " enable = %s ", mz_enable);
		if (!cli) cli  = sscanf(line, " cli-device = %s ", dev);
		if (cli==1) {
			for (i=0; i<device_list_entries; i++) {
				if (strncmp(device_list[i].dev, dev, 16)==0) {
					device_list[i].cli=1;
					found=1;
					break;
				}
			}
			if (!found) { 
				fprintf(stderr, " Warning: [%s] cli device '%s' does not exist!\n", filename, dev);
			 	cli=0; // try again
			}
			found=0;
			cli=0;
		}
		
		if (!mgmt_only) mgmt_only  = sscanf(line, " management-only  = %s ", dev);
		if (mgmt_only==1) {
			for (i=0; i<device_list_entries; i++) {
				if (strncmp(device_list[i].dev, dev, 16)==0) {
					device_list[i].mgmt_only=1;
					found=1;
					break;
				}
			}
			if (!found) fprintf(stderr, " Warning: [%s] management device '%s' does not exist!\n", filename, dev);
			mgmt_only=0;
			found=0;
		}
		
		if (AUTOMOPS_ENABLED) {
			// read-in all protocol definitions
			amp = sscanf(line, " automops = %s ", path);
			if (amp) {
				ampfile = mapfile(path);
				if (ampfile==NULL) fprintf(stderr, " Warning: Cannot read %s\n", path);
				else {
					j = 0;
					j = parse_protocol (ampfile);
					if (j) {
						if (verbose) {
							fprintf(stderr, "  Warning: invalid protocol definitions in %s\n", path);
						}
					}
					free(ampfile);
					amp=0;
				}
			}
		}
	}
	fclose(fd);
	
	if (verbose) {
		if (user!=1)
			fprintf(stderr, "%s: No user name specified - will use default.\n", filename);
		
		if (pass!=1) 
			fprintf(stderr, "%s: No password specified - will use default.\n", filename);
		
		if (ena!=1) 
			fprintf(stderr, "%s: No enable password specified - will use default.\n", filename);
	}
	
	cli_debug = 0;
	return 0;
}





///// TODO ***************************************************************
//
// Process "startup-config" using:
//
//   cli_file (struct cli_def *cli, FILE *f, int privilege, int mode)
//   
//   This reads and processes every line read from f as if it were entered 
//   at the console. The privilege level will be set to privilege and mode 
//   set to mode during the processing of the file.
//   
//  
// Idle timeout or watchdog or whatever:
// 
//    cli_regular (struct cli_def *cli, int(*callback)(struct cli_def *))
//    
//    Adds a callback function which will be called every second that a user 
//    is connected to the cli. This can be used for regular processing such 
//    as debugging, time counting or implementing idle timeouts.
//    
//    Pass NULL as the callback function to disable this at runtime. 
//    
// ************************************************************************


int cli()
{
   struct sockaddr_in servaddr;
   struct cli_command  
     *address,
     *clear,
     *debug, 
     *eth_frame,
     *frame,
     *ip_packet,
     *ip_int,
     *launch,
     *mac_packet,
     *macaddr,
     *mac_int,
     *pld,
     *port,
     *reset,
     *run,
     *show,
     *tag,
     *tcp_packet,
     *udp_packet;
   
   struct cli_def *cli;
   int on = 1, x, s, cnt=0;
   int i;
   char TimeStamp[128];

   (void) signal(SIGINT, clean_up);  // to close and free everything upon SIGINT
   
   // Must be called first to setup data structures
   cli = cli_init();
   gcli = cli; 
   
   // Set the hostname (shown in the the prompt)
   cli_set_hostname(cli, MZ_PROMPT);
   
   // Set the greeting
   cli_set_banner(cli, MZ_BANNER_TEXT);
   
   // Enable usernames and passwords
   cli_allow_user(cli, mz_username, mz_password);
   // cli_allow_user(cli, "herbert", "mops42");    // TODO: REMOVE THIS BACKDOOR :-)
   cli_allow_enable(cli, mz_enable);
   
   
   // Initialize MOPS
   mp_head = mops_init();  // now mp_head points to the head of the doubly linked list 

   // Initialize packet sequences list 
   packet_sequences = mz_ll_create_new_element(NULL); 
	
	
   mops_rx_arp();
   lookupdev();
   for (i=0; i<device_list_entries; i++) {
        get_dev_params(device_list[i].dev);
   }

   // Initialize sequence list
   
	
   // **************** THE MAIN CLI COMMANDS ****************
   
   // ---- DEBUG MODE: ----
   debug = cli_register_command(cli, NULL, "debug", NULL, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Enter debug mode");
   cli_register_command(cli, debug, "packet", debug_packet, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Debug packet processing");
   cli_register_command(cli, debug, "all", debug_all, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Debug all (beware!)");

   // ---- INTERFACE MODE COMMANDS: ---- (these are defaults for the 'device defaults' command)
   cli_register_command(cli, NULL, "interface", enter_interface, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Enter interface configuration mode");
   ip_int = cli_register_command(cli, NULL, "ip", NULL, PRIVILEGE_PRIVILEGED, MZ_MODE_INTERFACE, "Configure interface IP address");
   cli_register_command(cli, ip_int, "address", conf_ip_address, PRIVILEGE_PRIVILEGED, MZ_MODE_INTERFACE, "Configure interface IP address");
   mac_int= cli_register_command(cli, NULL, "mac", NULL, PRIVILEGE_PRIVILEGED, MZ_MODE_INTERFACE, "Configure interface MAC address");
   cli_register_command(cli, mac_int, "address", conf_mac_address, PRIVILEGE_PRIVILEGED, MZ_MODE_INTERFACE, "Configure interface MAC address");
   tag = cli_register_command(cli, NULL, "tag", NULL, PRIVILEGE_PRIVILEGED, MZ_MODE_INTERFACE, "Configure tags");
   cli_register_command(cli, tag, "dot1q", conf_tag_dot1q, PRIVILEGE_PRIVILEGED, MZ_MODE_INTERFACE, "Configure 802.1Q and 802.1P parameters");
   cli_register_command(cli, tag, "mpls", conf_tag_mpls, PRIVILEGE_PRIVILEGED, MZ_MODE_INTERFACE, "Configure mpls label stack");

   // ---- VARIOUS CONFIG MODE COMMANDS : ----
   frame = cli_register_command(cli, NULL, "frame", NULL, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Configure global frame settings");
   cli_register_command(cli, frame, "limit", conf_frame_limit, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Configure frame size limits");
   cli_register_command(cli, NULL, "sequence", conf_sequence, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Configure a sequence of packets");

   // ---- PACKET CONFIG MODE COMMANDS: ----
   cli_register_command(cli, NULL, "packet", enter_packet, PRIVILEGE_PRIVILEGED, MODE_CONFIG, "Enter packet configuration mode");
   cli_register_command(cli, NULL, "clone", cmd_packet_clone, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Clone from another packet");
   cli_register_command(cli, NULL, "name", cmd_packet_name, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Assign a unique name");
   cli_register_command(cli, NULL, "description", cmd_packet_description, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Assign a packet description text");
   cli_register_command(cli, NULL, "bind", cmd_packet_bind, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Select the network interface");
   cli_register_command(cli, NULL, "count", cmd_packet_count, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure the packet count value");
   cli_register_command(cli, NULL, "delay", cmd_packet_delay, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure the inter-packet delay");
   cli_register_command(cli, NULL, "interval", cmd_packet_interval, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure a greater interval");
   cli_register_command(cli, NULL, "type", cmd_packet_type, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Specify packet type");
   mac_packet = cli_register_command(cli, NULL, "mac", NULL, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure packet's MAC addresses");
   address = cli_register_command(cli, mac_packet, "address", NULL, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure packet's source IP address");
   cli_register_command(cli, address, "source", cmd_packet_mac_address_source, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure packet's source MAC addresses");
   cli_register_command(cli, address, "destination", cmd_packet_mac_address_destination, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure packet's destination MAC addresses");
   tag = cli_register_command(cli, NULL, "tag", NULL, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure tags");
   cli_register_command(cli, tag, "dot1q", cmd_packet_dot1q, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure 802.1Q (and 802.1P) parameters");
   cli_register_command(cli, tag, "mpls", cmd_packet_mpls, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure MPLS label stack");
   pld = cli_register_command(cli, NULL, "payload", NULL, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure a payload");
   cli_register_command(cli, pld, "hex", cmd_packet_payload_hex, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure a payload in hexadecimal format");
   cli_register_command(cli, pld, "ascii", cmd_packet_payload_ascii, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure a payload in ascii format");
   cli_register_command(cli, pld, "raw", cmd_packet_payload_raw, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure a raw payload (whole file as it is)");
   port = cli_register_command(cli, NULL, "port", NULL, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure packet's port numbers");
   cli_register_command(cli, port, "source", cmd_port_source, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure packet's source port number");
   cli_register_command(cli, port, "destination", cmd_port_destination, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure packet's destination port number");
   cli_register_command(cli, NULL, "end", cmd_packet_end, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "End packet configuration mode");

   // ---------- Ethernet related (for all packets that have Ethernet or LLC/SNAP as link layer)
   eth_frame = cli_register_command(cli, NULL, "ethernet", NULL, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure frame's Ethernet, 802.2, 802.3, or SNAP settings");
   macaddr = cli_register_command(cli, eth_frame, "address", NULL, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure frame's source or destination MAC address");
   cli_register_command(cli, macaddr, "source", cmd_packet_mac_address_source, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure frame's source MAC addresses");
   cli_register_command(cli, macaddr, "destination", cmd_packet_mac_address_destination, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure frame's destination MAC addresses");
   cli_register_command(cli, eth_frame, "type", cmd_eth_type, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure Ethernet's type field");
   cli_register_command(cli, eth_frame, "length", cmd_eth_length, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure IEEE 802.3 length field");
   cli_register_command(cli, eth_frame, "llc", cmd_eth_llc, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure the IEEE 802.2 field");
   cli_register_command(cli, eth_frame, "snap", cmd_eth_snap, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure the IEEE 802.2 field");

   // ---------- IP related (for all packets that have IPv4 as network layer)
   ip_packet = cli_register_command(cli, NULL, "ip", NULL, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure packet's IP settings");
   address = cli_register_command(cli, ip_packet, "address", NULL, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure packet's source or destination IP address");
   cli_register_command(cli, address, "source", cmd_ip_address_source, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure packet's source IP address");
   cli_register_command(cli, address, "destination", cmd_ip_address_destination, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure packet's destination IP address");
   cli_register_command(cli, ip_packet, "version", cmd_ip_version, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure version field in IPv4 header");
   cli_register_command(cli, ip_packet, "ttl", cmd_ip_ttl, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure TTL field in IPv4 header");
   cli_register_command(cli, ip_packet, "protocol", cmd_ip_protocol, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure protocol field in IPv4 header");
   cli_register_command(cli, ip_packet, "hlen", cmd_ip_hlen, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure header-length (aka IHL) field in IPv4 header");
   cli_register_command(cli, ip_packet, "length", cmd_ip_len, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure length field in IPv4 header");
   cli_register_command(cli, ip_packet, "identification", cmd_ip_id, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure identification field in IPv4 header");
   cli_register_command(cli, ip_packet, "offset", cmd_ip_offset, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure fragment offset field in IPv4 header");
   cli_register_command(cli, ip_packet, "checksum", cmd_ip_sum, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure checksum field in IPv4 header");
   cli_register_command(cli, ip_packet, "tos", cmd_ip_tos, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure type-of-service (ToS) field in IPv4 header");
   cli_register_command(cli, ip_packet, "dscp", cmd_ip_dscp, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure the ToS as DSCP field in IPv4 header");
   cli_register_command(cli, ip_packet, "reserved", cmd_ip_rsv, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure the reserved flag in IPv4 header");
   cli_register_command(cli, ip_packet, "dont-fragment", cmd_ip_df, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure the don't fragment flag in IPv4 header");
   cli_register_command(cli, ip_packet, "more-fragments", cmd_ip_mf, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure the more fragments flag in IPv4 header");
   cli_register_command(cli, ip_packet, "fragment-size", cmd_ip_fragsize, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure the fragment size to enable fragmentation");
   cli_register_command(cli, ip_packet, "fragment-overlap", cmd_ip_fragoverlap, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure a fragmentation overlap");
   cli_register_command(cli, ip_packet, "option", cmd_ip_option, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure IPv4 options");
   cli_register_command(cli, ip_packet, "auto-delivery", cmd_ip_delivery, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Enable or disable IP auto-delivery");
   // --------- IP commands:
   cli_register_command(cli, NULL, "version", cmd_ip_version, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IP, "Specify the IP version (default: 4)");
   cli_register_command(cli, NULL, "ttl", cmd_ip_ttl, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IP, "Specify the TTL (default: 255)");
   cli_register_command(cli, NULL, "source-address", cmd_ip_address_source, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IP, "Specify the source IP address");
   cli_register_command(cli, NULL, "destination-address", cmd_ip_address_destination, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IP, "Specify the destination IP address");
   cli_register_command(cli, NULL, "protocol", cmd_ip_protocol, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IP, "Specify the IP protocol");
   cli_register_command(cli, NULL, "hlen", cmd_ip_hlen, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IP, "Specify the IP header length");
   cli_register_command(cli, NULL, "len", cmd_ip_len, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IP, "Specify the IP packet length");
   cli_register_command(cli, NULL, "identification", cmd_ip_id, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IP, "Specify the IP identification");
   cli_register_command(cli, NULL, "offset", cmd_ip_offset, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IP, "Specify the fragment offset");
   cli_register_command(cli, NULL, "sum", cmd_ip_sum, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IP, "Specify the IP header checksum");
   cli_register_command(cli, NULL, "tos", cmd_ip_tos, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IP, "Specify the Type of Service");
   cli_register_command(cli, NULL, "dscp", cmd_ip_dscp, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IP, "Specify the DSCP");
   cli_register_command(cli, NULL, "reserved", cmd_ip_rsv, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IP, "Set or unset the reserved bit");
   cli_register_command(cli, NULL, "df", cmd_ip_df, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IP, "Set or unset the Don't Fragment (DF) bit");
   cli_register_command(cli, NULL, "mf", cmd_ip_mf, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IP, "Set or unset the More Fragments (MF) bit");
   cli_register_command(cli, NULL, "fragment-size", cmd_ip_fragsize, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IP, "Configure the fragment size to enable fragmentation");
   cli_register_command(cli, NULL, "fragment-overlap", cmd_ip_fragoverlap, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IP, "Configure a fragmentation overlap");
   cli_register_command(cli, NULL, "option", cmd_ip_option, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IP, "Configure an IP option");
   cli_register_command(cli, NULL, "auto-delivery", cmd_ip_delivery, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IP, "Enable or disable IP auto-delivery");
   cli_register_command(cli, NULL, "end", cmd_ip_end, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IP, "End IP configuration mode");

   // ---------- UDP related (for all packets that have UDP as transport layer)
   udp_packet = cli_register_command(cli, NULL, "udp", NULL, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure packet's UDP header parameters");
   cli_register_command(cli, udp_packet, "checksum", cmd_udp_sum, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure the UDP checksum");
   cli_register_command(cli, udp_packet, "length", cmd_udp_len, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure the UDP length field");
   // ---------- UDP commands:
   cli_register_command(cli, NULL, "checksum", cmd_udp_sum, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_UDP, "Configure the UDP checksum");
   cli_register_command(cli, NULL, "length", cmd_udp_len, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_UDP, "Configure the UDP length field");
   cli_register_command(cli, NULL, "end", cmd_udp_end, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_UDP, "End UDP configuration mode");
   
   // ---------- TCP related (for all packets that have TCP as transport layer)
   tcp_packet = cli_register_command(cli, NULL, "tcp", NULL, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure packet's TCP header parameters");
   cli_register_command(cli, tcp_packet, "seqnr", cmd_tcp_seqnr, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure the TCP sequence number");
   cli_register_command(cli, tcp_packet, "acknr", cmd_tcp_acknr, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure the TCP acknowledgement number");
   cli_register_command(cli, tcp_packet, "hlen", cmd_tcp_offset, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure the TCP header length");
   cli_register_command(cli, tcp_packet, "reserved", cmd_tcp_res, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure the TCP reserved field");
   cli_register_command(cli, tcp_packet, "flags", cmd_tcp_flags, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure a combination of TCP flags at once");
   cli_register_command(cli, tcp_packet, "cwr", cmd_tcp_cwr, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Set or unset the TCP CWR flag");
   cli_register_command(cli, tcp_packet, "ece", cmd_tcp_ece, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Set or unset the TCP ECE flag");
   cli_register_command(cli, tcp_packet, "urg", cmd_tcp_urg, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Set or unset the TCP URG flag");
   cli_register_command(cli, tcp_packet, "ack", cmd_tcp_ack, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "set or unset the TCP ACK flag");
   cli_register_command(cli, tcp_packet, "psh", cmd_tcp_psh, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "set or unset the TCP PSH flag");
   cli_register_command(cli, tcp_packet, "rst", cmd_tcp_rst, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "set or unset the TCP RST flag");
   cli_register_command(cli, tcp_packet, "syn", cmd_tcp_syn, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "set or unset the TCP SYN flag");
   cli_register_command(cli, tcp_packet, "fin", cmd_tcp_fin, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "set or unset the TCP FIN flag");
   cli_register_command(cli, tcp_packet, "window", cmd_tcp_window, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure the TCP window size");
   cli_register_command(cli, tcp_packet, "checksum", cmd_tcp_sum, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure the TCP checksum");
   cli_register_command(cli, tcp_packet, "urgent-pointer", cmd_tcp_urgptr, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure the TCP urgend pointer");
   cli_register_command(cli, tcp_packet, "options", cmd_tcp_options, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET, "Configure TCP options");
   // ---------- TCP commands:
   cli_register_command(cli, NULL, "seqnr", cmd_tcp_seqnr, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_TCP, "Configure the TCP sequence number");
   cli_register_command(cli, NULL, "acknr", cmd_tcp_acknr, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_TCP, "Configure the TCP acknowledgement number");
   cli_register_command(cli, NULL, "hlen", cmd_tcp_offset, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_TCP, "Configure the TCP header length");
   cli_register_command(cli, NULL, "reserved", cmd_tcp_res, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_TCP, "Configure the TCP reserved field");
   cli_register_command(cli, NULL, "flags", cmd_tcp_flags, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_TCP, "Configure a combination of TCP flags at once");
   cli_register_command(cli, NULL, "cwr", cmd_tcp_cwr, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_TCP, "Set or unset the TCP CWR flag");
   cli_register_command(cli, NULL, "ece", cmd_tcp_ece, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_TCP, "Set or unset the TCP ECE flag");
   cli_register_command(cli, NULL, "urg", cmd_tcp_urg, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_TCP, "Set or unset the TCP URG flag");
   cli_register_command(cli, NULL, "ack", cmd_tcp_ack, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_TCP, "set or unset the TCP ACK flag");
   cli_register_command(cli, NULL, "psh", cmd_tcp_psh, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_TCP, "set or unset the TCP PSH flag");
   cli_register_command(cli, NULL, "rst", cmd_tcp_rst, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_TCP, "set or unset the TCP RST flag");
   cli_register_command(cli, NULL, "syn", cmd_tcp_syn, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_TCP, "set or unset the TCP SYN flag");
   cli_register_command(cli, NULL, "fin", cmd_tcp_fin, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_TCP, "set or unset the TCP FIN flag");
   cli_register_command(cli, NULL, "window", cmd_tcp_window, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_TCP, "Configure the TCP window size");
   cli_register_command(cli, NULL, "checksum", cmd_tcp_sum, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_TCP, "Configure the TCP checksum");
   cli_register_command(cli, NULL, "urgent-pointer", cmd_tcp_urgptr, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_TCP, "Configure the TCP urgend pointer");
   cli_register_command(cli, NULL, "options", cmd_tcp_options, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_TCP, "Configure TCP options");
   cli_register_command(cli, NULL, "end", cmd_tcp_end, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_TCP, "End TCP configuration mode");   
   
   // --------- ARP commands:
   cli_register_command(cli, NULL, "hardware-type", cmd_arp_hwtype, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_ARP, "Specify the hardware type");
   cli_register_command(cli, NULL, "protocol-type", cmd_arp_prtype, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_ARP, "Specify the protocol type");
   cli_register_command(cli, NULL, "hw-addr-size", cmd_arp_hwaddrsize, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_ARP, "Specify the hardware address size");
   cli_register_command(cli, NULL, "pr-addr-size", cmd_arp_praddrsize, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_ARP, "Specify the protocol address size");
   cli_register_command(cli, NULL, "opcode", cmd_arp_opcode, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_ARP, "Specify the ARP opcode");
   cli_register_command(cli, NULL, "sender-mac", cmd_arp_smac, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_ARP, "Specify the sender MAC address");
   cli_register_command(cli, NULL, "sender-ip", cmd_arp_sip, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_ARP, "Specify the sender IP address");
   cli_register_command(cli, NULL, "target-mac", cmd_arp_tmac, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_ARP, "Specify the target MAC address");
   cli_register_command(cli, NULL, "target-ip", cmd_arp_tip, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_ARP, "Specify the target IP address");
   cli_register_command(cli, NULL, "trailer", cmd_arp_trailer, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_ARP, "Specify the trailer length");
   cli_register_command(cli, NULL, "end", cmd_arp_end, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_ARP, "End ARP configuration mode");

   // --------- BPDU commands:
   cli_register_command(cli, NULL, "id", cmd_bpdu_id, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_BPDU, "Specify the BPDU identifier");
   cli_register_command(cli, NULL, "version", cmd_bpdu_version, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_BPDU, "Specify the BPDU version");
   cli_register_command(cli, NULL, "bpdutype", cmd_bpdu_type, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_BPDU, "Specify the BPDU type");
   cli_register_command(cli, NULL, "flags", cmd_bpdu_flags, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_BPDU, "Specify the BPDU flags");
   cli_register_command(cli, NULL, "root-id", cmd_bpdu_rid, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_BPDU, "Specify the BPDU root identifier");
   cli_register_command(cli, NULL, "path-cost", cmd_bpdu_pc, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_BPDU, "Specify the BPDU root path cost");
   cli_register_command(cli, NULL, "bridge-id", cmd_bpdu_bid, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_BPDU, "Specify the BPDU bridge identifier");
   cli_register_command(cli, NULL, "port-id", cmd_bpdu_pid, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_BPDU, "Specify the BPDU port identifier");
   cli_register_command(cli, NULL, "age", cmd_bpdu_age, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_BPDU, "Specify the BPDU age");
   cli_register_command(cli, NULL, "maxage", cmd_bpdu_maxage, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_BPDU, "Specify the BPDU maxage");
   cli_register_command(cli, NULL, "hello-interval", cmd_bpdu_hello, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_BPDU, "Specify the BPDU hello interval");
   cli_register_command(cli, NULL, "forward-delay", cmd_bpdu_fwd, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_BPDU, "Specify the BPDU forward delay");
   cli_register_command(cli, NULL, "mode", cmd_bpdu_mode, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_BPDU, "Specify the BPDU mode");
   cli_register_command(cli, NULL, "vlan", cmd_bpdu_vlan, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_BPDU, "Specify the vlan for PVST+");
   cli_register_command(cli, NULL, "end", cmd_bpdu_end, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_BPDU, "End BPDU configuration mode");

   // --------- IGMP commands:
   cli_register_command(cli, NULL, "v2-general-query", 	cmd_igmpv2_genquery, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IGMP, "Create an IGMPv2 general query");
   cli_register_command(cli, NULL, "v2-group-specific-query", cmd_igmpv2_specquery, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IGMP, "Create an IGMPv2 group-specific query");
   cli_register_command(cli, NULL, "v2-report", cmd_igmpv2_report, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IGMP, "Create an IGMPv2 membership report");
   cli_register_command(cli, NULL, "v2-leave", cmd_igmpv2_leave, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IGMP, "Create an IGMPv2 leave group message");
   cli_register_command(cli, NULL, "v1-query", 	cmd_igmpv1_query, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IGMP, "Create an IGMPv1 query");
   cli_register_command(cli, NULL, "v1-report", cmd_igmpv1_report, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IGMP, "Create an IGMPv1 membership report");
   cli_register_command(cli, NULL, "end", cmd_ip_end, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_IGMP, "End IGMP configuration mode"); // we reuse cmd_ip_end here!

   cli_register_command(cli, NULL, "conformance", cmd_lldp_conformance, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_LLDP, "Enable or disable LLDP standard conformance");
   cli_register_command(cli, NULL, "chassis-id", cmd_lldp_chassis_id, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_LLDP, "Configure the LLDP Chassis-ID");
   cli_register_command(cli, NULL, "port-id", cmd_lldp_port_id, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_LLDP, "Configure the LLDP Port-ID");
   cli_register_command(cli, NULL, "ttl", cmd_lldp_ttl, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_LLDP, "Configure the LLDP Time-to-Live");	
   cli_register_command(cli, NULL, "vlan", cmd_lldp_vlan, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_LLDP, "Configure the LLDP Port VLAN-ID");
   cli_register_command(cli, NULL, "generic-tlv", cmd_lldp_opt_tlv, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_LLDP, "Configure a generic LLDP TLV");
   cli_register_command(cli, NULL, "bad-tlv", cmd_lldp_opt_tlv_bad, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_LLDP, "Configure a bad TLV for testing purposes");
   cli_register_command(cli, NULL, "organisational-tlv", cmd_lldp_opt_org, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_LLDP, "Configure an organisational LLDP TLV");
   cli_register_command(cli, NULL, "early-end", cmd_lldp_endtlv, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_LLDP, "Insert an 'early' End-of-LLDPU TLV");
   cli_register_command(cli, NULL, "reset", cmd_lldp_reset, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_LLDP, "Reset the LLDPU to defaults and clear all optional TLVs");
   cli_register_command(cli, NULL, "end", cmd_ip_end, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_LLDP, "End IGMP configuration mode"); // we reuse cmd_ip_end here!

   // --------- RTP commands:
   cli_register_command(cli, NULL, "version", cmd_rtp_version, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_RTP, "Specify the RTP version (default: 2)");
   cli_register_command(cli, NULL, "padding", cmd_rtp_padding, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_RTP, "Set or unset the padding flag (default: 0)");
   cli_register_command(cli, NULL, "xten", cmd_rtp_xten, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_RTP, "Set or unset the eXtension flag (default: 0)");
   cli_register_command(cli, NULL, "marker", cmd_rtp_marker, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_RTP, "Set or unset the marker flag (default: 0)");
   cli_register_command(cli, NULL, "csrc-count", cmd_rtp_cc, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_RTP, "Configure the CSRC count (default: 0)");
   cli_register_command(cli, NULL, "csrc-list", cmd_rtp_cclist, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_RTP, "Configure the CSRC list (default: none)");
   cli_register_command(cli, NULL, "payload-type", cmd_rtp_pt, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_RTP, "Configure the payload type (default: G.711, A-law, 20 msec)");
   cli_register_command(cli, NULL, "sequence-number", cmd_rtp_sqnr, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_RTP, "Configure the sequence number");
   cli_register_command(cli, NULL, "timestamp", cmd_rtp_time, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_RTP, "Configure the timestamp");
   cli_register_command(cli, NULL, "ssrc", cmd_rtp_ssrc, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_RTP, "Configure the SSRC (source identifier)");
   cli_register_command(cli, NULL, "extension", cmd_rtp_extension, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_RTP, "Configure an extension header");
   cli_register_command(cli, NULL, "source", cmd_rtp_source, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_RTP, "Specify a media source");
   cli_register_command(cli, NULL, "end", cmd_ip_end, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_RTP, "End RTP configuration mode"); // we reuse cmd_ip_end here!
	
   // --------- DNS commands:
   cli_register_command(cli, NULL, "ttl", cmd_dns_ttl, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_DNS, "Specify the TTL (default: 0)");
   cli_register_command(cli, NULL, "query", cmd_dns_query, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_DNS, "Specify the query");
   cli_register_command(cli, NULL, "answer", cmd_dns_answer, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_DNS, "Specify the answer");
   cli_register_command(cli, NULL, "end", cmd_dns_end, PRIVILEGE_PRIVILEGED, MZ_MODE_PACKET_DNS, "End DNS configuration mode");

	
   // --------- SEQUENCE COMMANDS
   cli_register_command(cli, NULL, "add", sequence_add, PRIVILEGE_PRIVILEGED, MZ_MODE_SEQUENCE, "Add another packet to the current sequence");
   cli_register_command(cli, NULL, "delay", sequence_delay, PRIVILEGE_PRIVILEGED, MZ_MODE_SEQUENCE, "Add a delay to the current sequence");
   cli_register_command(cli, NULL, "show", sequence_show, PRIVILEGE_PRIVILEGED, MZ_MODE_SEQUENCE, "Show current sequence list");
   cli_register_command(cli, NULL, "remove", sequence_remove, PRIVILEGE_PRIVILEGED, MZ_MODE_SEQUENCE, "Remove a packet or delay from the current sequence");
   cli_register_command(cli, NULL, "end", cmd_end_to_config, PRIVILEGE_PRIVILEGED, MZ_MODE_SEQUENCE, "End sequence configuration mode"); 
   // ---- BENCHMARK CONFIG MODE COMMANDS: ---
   // ---- SCAN CONFIG MODE COMMANDS: ---

   // ---- CONTROL COMMANDS: ----
   cli_register_command(cli, NULL, "terminate", stop_mausezahn, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Terminate the Mausezahn server");
   run = cli_register_command(cli, NULL, "run", NULL, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Run previously configured mops instances or sequences");
   cli_register_command(cli, run, "id", cmd_run_id, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Run mops packet(s) by specifying packet identifiers");
   cli_register_command(cli, run, "name", cmd_run_name, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Run mops packet(s) by specifying packet names");
   cli_register_command(cli, run, "sequence", cmd_run_sequence, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Run a packet sequence");
   cli_register_command(cli, run, "all", cmd_run_all, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Run all currently configured mops packet(s)");
   cli_register_command(cli, NULL, "tx", transmit, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Send inline configured packet (legacy mode; not recommended)");
   cli_register_command(cli, NULL, "stop", cmd_stop, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Stop transmission");
   cli_register_command(cli, NULL, "warranty", warranty, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Show license and warranty details");
   cli_register_command(cli, NULL, "load", cmd_load, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Load commands from a file");

   // ---- SET COMMANDS: -----
   cli_register_command(cli, NULL, "set", cmd_set, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Set global Mausezahn parameters");

   // ---- CLEAR COMMANDS: -----
   clear = cli_register_command(cli, NULL, "clear", NULL, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Clear something (use '?')");
   cli_register_command(cli, clear, "all", clear_all, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Re-initialize Mausezahn");
   cli_register_command(cli, clear, "packet", clear_packet, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Delete a packet (i. e. MOPS entry)");
   
   // ---- SHOW COMMANDS: -----
   show = cli_register_command(cli, NULL, "show", NULL, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Show something (use '?')");
   cli_register_command(cli, show, "packet", show_packets, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Show defined packets");
// cli_register_command(cli, show, "system", show_system, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Show basic system settings");
   cli_register_command(cli, show, "interfaces", show_interfaces, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Show detailed interface information");
   cli_register_command(cli, show, "mops", show_mops, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Show MOPS details");
// cli_register_command(cli, show, "processes", cmd_test, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "List all Mausezahn processes");
   cli_register_command(cli, show, "set", show_set, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "List general packet parameters");
   cli_register_command(cli, show, "arp", show_arp, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Show the advanced Mausezahn ARP table");

// cli_register_command(cli, show, "report", cmd_test, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Print reports");
   cli_register_command(cli, show, "license", warranty, PRIVILEGE_UNPRIVILEGED, MODE_EXEC, "Show license and warranty details");

   // ---- PRIVILEGE (OTHER) ----
   reset = cli_register_command(cli, NULL, "reset", NULL, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Reset something...");
    cli_register_command(cli, reset, "interface", cmd_reset_interface, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Reset interfaces");
    cli_register_command(cli, reset, "packet", cmd_reset_packet, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Reset interfaces");
   // ------- LAUNCH ------
   launch = cli_register_command(cli, NULL, "launch", NULL, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Launch a predefined MOPS process");
    cli_register_command(cli, launch, "bpdu", launch_bpdu, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Launch a(nother) BPDU process");
    cli_register_command(cli, launch, "synflood", launch_synflood, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Launch a(nother) SYN-Flood process");
//    cli_register_command(cli, launch, "alot", launch_alot, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Launch lots of traffic");
//    cli_register_command(cli, launch, "rtp", launch_rtp, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Launch rtp stream(s)");
//    cli_register_command(cli, launch, "arp", launch_arp, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Launch a(nother) ARP process");
//    cli_register_command(cli, launch, "lldp", launch_lldp, PRIVILEGE_PRIVILEGED, MODE_EXEC, "Launch a(nother) LLDP process");
	
	
   // *******************************************************
   
   // Create a socket
   s = socket(AF_INET, SOCK_STREAM, 0);
   setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

   // Should we bind the CLI session to a specific interface?
   // TODO: This does nothing !?
   for (i=0; i<device_list_entries; i++) {
	   if (device_list[i].cli) {
		   setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, device_list[i].dev, strnlen(device_list[i].dev, 16));
		   break; // can only be one interface
	   }
   }
   
	
   // Listen on port mz_port (default: 25542, towel day)
   memset(&servaddr, 0, sizeof(servaddr));
   servaddr.sin_family = AF_INET;
   servaddr.sin_addr.s_addr = htonl(INADDR_ANY);  // TODO: specified interface
   servaddr.sin_port = htons(mz_port); 
   bind(s, (struct sockaddr *)&servaddr, sizeof(servaddr));

   // Wait for a connection
   listen(s, 50);

   while ((x = accept(s, NULL, 0)))
     {
	if (!quiet)
	  {
	     cnt++;
	     timestamp_human(TimeStamp, NULL);
	     fprintf(stderr, "Got incoming connection [%i] at %s.\n", cnt, TimeStamp);
	     fflush(stderr);
	  }
	
	// Pass the connection off to libcli
	cli_loop(cli, x);
	
	if (!quiet)
	  {
	     timestamp_human(TimeStamp, NULL);
	     fprintf(stderr, "Connection [%i] left at %s.\n", cnt, TimeStamp);
	  }
	
	close(x);
     }
   
   // Free data structures
   cli_done(cli);

   return 0;
}



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


// Catch SIGINT and clean up, close everything...
void  clean_up(int sig)
{
	int i;
	struct arp_table_struct *cur, *next;
	
	if (!quiet) fprintf(stderr, "\nMausezahn cleans up...\n");
	
	if (fp!=NULL) {
		if (verbose) fprintf(stderr, " close files (1) ...\n");
		(void) fflush(fp);
		(void) fclose(fp);
	}
   
	if (fp2!=NULL) {
		if (verbose) fprintf(stderr, " close files (2) ...\n");
		(void) fflush(fp2);
		(void) fclose(fp2);
	}

	// interactive mode?
	if (mz_port) { 
		if (verbose) fprintf(stderr, " clear mops list...\n");
		mops_cleanup (mp_head);
		if (verbose) fprintf(stderr, " clear automops list...\n");
		automops_cleanup (amp_head);
		if (verbose) fprintf(stderr, " clear packet sequences...\n");
		mz_ll_delete_list (packet_sequences);
	}

	for (i=0; i<device_list_entries; i++) {
		if (device_list[i].p_arp!=NULL) {
			pcap_close(device_list[i].p_arp);
			fprintf(stderr, " stopped ARP process for device %s\n", device_list[i].dev);
		}
		if (device_list[i].arprx_thread!=0) {
			pthread_cancel(device_list[i].arprx_thread);
			if (verbose) 
				fprintf(stderr, " (ARP thread for device %s done)\n", device_list[i].dev);
		}
		
		if (device_list[i].arp_table!=NULL) {
			cur=device_list[i].arp_table;
			while (cur!=NULL) {
				next = cur->next;
				if (cur!=NULL) free(cur);
				cur=next;
			}
		}
		
		// close packet sockets
		if (device_list[i].ps>=0) { 
			close(device_list[i].ps);
		}
		
	}


	
	if (verbose) fprintf(stderr, "finished.\n");
	exit(sig);
}



void usage()
{
   (void) fprintf (stderr,"\n"
		   MAUSEZAHN_VERSION
		   "\n"
		   "|\n"
		   "| USAGE: mz [options] [interface] keyword | arg_string | hex_string\n"
		   "|\n"
		   "| Short option description (see doc or manpage for more information):\n"
		   "|  -h                    Prints this information.\n"
		   "|  -4		     IPv4 mode (default)\n"
		   "|  -6		     IPv6 mode\n"
		   "|  -c <count>            Send the packet count times (default: 1, infinite: 0).\n"
		   "|  -d <delay>            Apply delay between transmissions. The delay value can be\n"
		   "|                        specified in usec (default, no additional unit needed), or in\n"
		   "|                        msec (e. g. 100m or 100msec), or in seconds (e. g. 100s or 100sec).\n"
		   "|  -r                    Multiplies the specified delay with a random value.\n"
		   "|  -p <length>           Pad the raw frame to specified length (using random bytes).\n"
		   "|  -a <Src_MAC|keyword>  Use specified source mac address, no matter what has\n"
		   "|                        been specified with other arguments. Keywords see below.\n"
		   "|                        Default is own interface MAC.\n"
		   "|  -b <Dst_MAC|keyword>  Same with destination mac address.\n"
		   "|                        Keywords are: \n"
		   "|          rand            use a random MAC address\n"
		   "|          bc              use a broadcast MAC address\n"
		   "|          own             use own interface MAC address (default for source MAC)\n"
		   "|          stp             use IEEE 802.1d STP multicast address\n"
		   "|          cisco           use Cisco multicast address as used for CDP, VTP, or PVST+\n"
		   "|  -A <Src_IP>           Use specified source IP address (default is own interface IP).\n"
		   "|  -B <Dst_IP|DNS_name>  Send packet to specified destination IP or domain name.\n"
		   "|  -P <ASCII Payload>    Use the specified ASCII payload.\n"
		   "|  -f <filename>         Read the ASCII payload from a file.\n"
		   "|  -F <filename>         Read the hexadecimal payload from a file.\n" 
		   "|  -Q <[CoS:]vlan>       Specify 802.1Q VLAN tag and optional Class of Service. You can\n"
		   "|                        specify multiple 802.1Q VLAN tags (QinQ...) by separating them\n"
		   "|                        via a comma or a period (e. g. '5:10,20,2:30').\n"
		   "|  -t <packet_type>      Specify packet type for autobuild (you don't need to care for\n"
		   "|                        encapsulations in lower layers. Most packet types allow/require\n"
		   "|                        additional packet-specific arguments in an arg_string.\n"
		   "|                        Currently supported types: arp, bpdu, cdp, ip, icmp, udp, tcp,\n"
		   "|                        dns, rtp, syslog, lldp.\n"
		   "|                        For context-help use 'help' as arg_string!\n"
		   "|  -T <packet_type>      Specify packet type for server mode. Currently only rtp is supported.\n"
		   "|                        Enter -T help or -T rtp help for further information.\n"
		   "|  -M <MPLS label>       Insert a MPLS label. Enter '-M help' for a syntax description.\n"
  		   "|  -v|V                  Verbose and more verbose mode\n"
		   "|  -q                    Quiet mode, i. e. even omit 'important standard short messages'.\n"
   		   "|  -S                    Simulation mode: DOES NOT put anything on the wire. This is\n"
		   "|                        typically combined with one of the verbose modes (v or V).\n"
		   "\n"
		   );
   exit(0);
}





int main(int argc, char *argv[])
{

   
   // These handles are only used when creating L3 and above packets.
   libnet_t             *l;               // the context 
   libnet_ptag_t         t2=0, t3=0, t4=0;      // handles to layers 
   
   double cpu_time_used;

   // Check if we have root priviliges
   if ( (getuid()!=0) && (geteuid()!=0) )
     {
	fprintf(stderr, " Mausezahn requires root privileges.\n Exit.\n");
	return 1;
     }
   
   
   // Reset all globals
   (void) reset(0); 
   
   // Get all CLI options (sets globals, see mz.h)
   if ( getopts(argc, argv) ) 
     {
	(void) fprintf(stderr, " Invalid command line parameters!\n");
	usage();
     }

   // Check whether hires timers are supported or not:
   (void) check_timer();

   
     
   // *********************************************************************
   //           First prefer data in a mausezahn description file!
   // *********************************************************************

   
   
               // >>> TODO:
               // Note that argument 'device' is also used here!
               // Support libpcap
               // Must end in state machine!

   
   
   // *********************************************************************
   //    If no MDF given, then send packet according CLI specifications
   // *********************************************************************
   

   (void) signal(SIGINT, clean_up);  // to close all file pointers etc upon SIGINT

   switch (mode)
     {
      case BYTE_STREAM:
	send_eth();
	break;
	
      case ARP:
	(void) send_arp();
	break;
	
      case BPDU:
	(void) send_bpdu();
	break;
	
      case CDP:
	(void) send_cdp();
	break;
	
      case IP:                        // From now on a new much more modular method is used:
	l = get_link_context();
	t3 = create_ip_packet(l);     // t3 can be used for later header changes
	if (!quiet) complexity();
	if (tx.packet_mode==0)        // Ethernet manipulation features does NOT use ARP to determine eth_dst  
	  t2 = create_eth_frame(l, t3, t4);   // t2 can be used for later header changes
	else
	  send_frame (l, t3, t4); // NOTE: send_frame also destroys context finaly
	break;
	
      case ICMP:
	tx.ip_proto = 1;  
	l = get_link_context();
	t4 = create_icmp_packet(l);    // t4 can be used for later header changes
	t3 = create_ip_packet(l);      // t3 can be used for later header changes
	if (!quiet) complexity();
	if (tx.packet_mode==0)         // Ethernet manipulation features does NOT use ARP to determine eth_dst  
	  t2 = create_eth_frame(l, t3, t4);    // t2 can be used for later header changes
	else
	  send_frame (l, t3, t4); // NOTE: send_frame also destroys context finaly
	break;
	
      case ICMP6:
	tx.ip_proto = 58;
	l = get_link_context();
	t4 = create_icmp6_packet(l);	// t4 can be used for later header changes
	t3 = create_ip_packet(l);	// t3 can be used for later header changes
	if (ipv6_mode)
	  update_ISUM(l, t4);
	if (!quiet) complexity();
	if (tx.packet_mode==0)		// Ethernet manipulation features does NOT use ARP to determine eth_dst
	  t2 = create_eth_frame(l, t3, t4);	// t2 can be used for later header changes
	else
	  send_frame (l, t3, t4); // NOTE: send_frame also destroys context finaly
	break;

      case UDP:
	tx.ip_proto = 17;
	l = get_link_context();
	t4 = create_udp_packet(l);     // t4 can be used for later header changes
	t3 = create_ip_packet(l);      // t3 can be used for later header changes
	if (ipv6_mode)
	  update_USUM(l, t4);
	if (!quiet) complexity();
	if (tx.packet_mode==0)         // Ethernet manipulation features does NOT use ARP to determine eth_dst  
	  t2 = create_eth_frame(l, t3, t4);    // t2 can be used for later header changes
	else
	  send_frame (l, t3, t4); // NOTE: send_frame also destroys context finaly
	break;
	
      case TCP:
	tx.ip_proto = 6;    
	l = get_link_context();
	t4 = create_tcp_packet(l);     // t4 can be used for later header changes
	t3 = create_ip_packet(l);      // t3 can be used for later header changes
	if (ipv6_mode)
	  update_TSUM(l, t4);
	if (!quiet) complexity();
	if (tx.packet_mode==0)         // Ethernet manipulation features does NOT use ARP to determine eth_dst  
	  t2 = create_eth_frame(l, t3, t4);    // t2 can be used for later header changes
	else
	  send_frame (l, t3, t4); // NOTE: send_frame also destroys context finaly
	break;
	
      case DNS:
	tx.ip_proto = 17;
	l = get_link_context();
	(void) create_dns_packet();
	t4 = create_udp_packet(l);     // t4 can be used for later header changes
	t3 = create_ip_packet(l);      // t3 can be used for later header changes
	if (!quiet) complexity();
	if (tx.packet_mode==0)         // Ethernet manipulation features does NOT use ARP to determine eth_dst  
	  t2 = create_eth_frame(l, t3, t4);    // t2 can be used for later header changes
	else
	  send_frame (l, t3, t4); // NOTE: send_frame also destroys context finaly
	break;
	
      case RTP:
	tx.ip_proto = 17;
	l = get_link_context();
	if (!quiet) fprintf(stderr, " mz: RTP mode! (count=%u, delay=%u usec)\n\n", tx.count, tx.delay);
	(void) create_rtp_packet();
	t4 = create_udp_packet(l);     // t4 can be used for later header changes
	t3 = create_ip_packet(l);      // t3 can be used for later header changes
	if (!quiet) complexity();
	if (tx.packet_mode==0)         // Ethernet manipulation features does NOT use ARP to determine eth_dst  
	  t2 = create_eth_frame(l, t3, t4);    // t2 can be used for later header changes
	else
	  send_frame (l, t3, t4); // NOTE: send_frame also destroys context finaly
	break;
	
      case RX_RTP:  // Receive RTP packets
	rcv_rtp_init();
	rcv_rtp();
	break;

      case SYSLOG:
	tx.ip_proto = 17;
	l = get_link_context();
	(void) create_syslog_packet();
	t4 = create_udp_packet(l);     // t4 can be used for later header changes
	t3 = create_ip_packet(l);      // t3 can be used for later header changes
	if (!quiet) complexity();

	if (tx.packet_mode==0)         // Ethernet manipulation features does NOT use ARP to determine eth_dst  
	  t2 = create_eth_frame(l, t3, t4);    // t2 can be used for later header changes
	else
	  send_frame (l, t3, t4); // NOTE: send_frame also destroys context finaly
	break;

      case LLDP: // start with a new concept here
	//l = get_link_context();
	//(void) create_lldp_packet();
	// // // printf("SIZE=%lu\n",sizeof(struct tx_struct));
        fprintf(stderr, "LLDP is currently only supported via the interactive mode\n");
	     exit(1);
	break;

	
      default:
	(void) fprintf(stderr," mz/main: unknown mode! Stop.\n");
	return (1);
     }

   if (!quiet) 
     {
	mz_stop = clock();
	cpu_time_used = ((double) (mz_stop - mz_start)) / CLOCKS_PER_SEC;
	if (cpu_time_used > 0)
	  {
	     total_d /= cpu_time_used;
	     fprintf(stderr, "%.2f seconds (%.Lf packets per second)\n",cpu_time_used,total_d);
	  }
	else
	  {
	     fprintf(stderr, "\n");
	  }
     }
   
   return(0);
}

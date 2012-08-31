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


int tx_switch(struct cli_def *cli)
{

   // These handles are only used when creating L3 and above packets.
   libnet_t             *l;               // the context 
   libnet_ptag_t         t2=0, t3=0, t4=0;      // handles to layers 

   double cpu_time_used;
   
   switch (mode)
     {
      case BYTE_STREAM:
	send_eth();
	break;
	
      case ARP:
	if (send_arp()==-1) return 0;
	break;
	
      case BPDU:
	if (send_bpdu()==-1) return 0;
	break;
	
      case CDP:
	if (send_cdp()==-1) return 0;
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
	if (t4==-1) return 0;
	t3 = create_ip_packet(l);      // t3 can be used for later header changes
	if (!quiet) complexity();
	if (tx.packet_mode==0)         // Ethernet manipulation features does NOT use ARP to determine eth_dst  
	  t2 = create_eth_frame(l, t3, t4);    // t2 can be used for later header changes
	else
	  send_frame (l, t3, t4); // NOTE: send_frame also destroys context finaly
	break;
	
      case UDP:
	tx.ip_proto = 17;
	l = get_link_context();
	t4 = create_udp_packet(l);     // t4 can be used for later header changes
	if (t4==-1) return 0;
	t3 = create_ip_packet(l);      // t3 can be used for later header changes
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
	if (t4==-1) return 0;
	t3 = create_ip_packet(l);      // t3 can be used for later header changes
	if (!quiet) complexity();
	if (tx.packet_mode==0)         // Ethernet manipulation features does NOT use ARP to determine eth_dst  
	  t2 = create_eth_frame(l, t3, t4);    // t2 can be used for later header changes
	else
	  send_frame (l, t3, t4); // NOTE: send_frame also destroys context finaly
	break;
	
      case DNS:
	tx.ip_proto = 17;
	l = get_link_context();
	if (create_dns_packet()==-1) return 0;
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
	if (create_rtp_packet()==-1) return 0;
	cli_print(cli, "RTP mode! (count=%u, delay=%u usec)\n", tx.count, tx.delay);
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
	if (create_syslog_packet()==-1) return 0;
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
	break;
	
	
      default:
	cli_print(cli,"Unknown mode!\n");
	return (1);
     }

   
   // *****  Re-init packet functions: *****
   tx.ip_payload_s = 0;
   tx.udp_len = 0;
   tx.tcp_payload_s = 0;
   tx.icmp_payload_s = 0;
   tx.cdp_sum = 0;
   mode = 0;
   // **************************************
   
   
   mz_stop = clock();
   cpu_time_used = ((double) (mz_stop - mz_start)) / CLOCKS_PER_SEC;
   if (cpu_time_used > 0)
     {
	total_d /= cpu_time_used;
	cli_print(cli, "%.2f seconds (%.Lf packets per second)\n",cpu_time_used,total_d);
     }
   
   return 0;
}

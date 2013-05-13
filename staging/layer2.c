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



// ***************************************************************************
//    This sections contains functions to send various L2-based PDUs such as 
//    * ARP
//    * BPDU
// ***************************************************************************

#include "mz.h"
#include "cli.h"



#define MZ_ARP_HELP \
   		"| ARP type: Send arbitrary ARP packets.\n" \
		"| Note:\n" \
		"| - The Ethernet dst and src MAC addresses can be specified but can be also 'rand'.\n" \
		"| - If dst and src are NOT specified then practical defaults are used (src=own MAC, dst=bc).\n" \
		"|\n" \
		"|    ARGUMENT SYNTAX: <command> [<parameters>]\n" \
		"|                         |           |\n" \
		"|  help, request, reply --+           |\n" \
		"|                                     +-- sendermac, senderip, targetmac, targetip\n" \
		"|                                         smac       sip       tmac       tip\n" \
		"|\n" \
		"| EXAMPLES:\n" \
		"|   1. Legitimate ARP response to broadcast:\n" \
		"|      # mz eth0 -t arp \"reply\"\n" \
		"|   2. ARP cache poisoning, claiming to be 192.168.0.1, telling a target PC:\n" \
		"|      # mz eth0 -t arp \"reply, senderip=192.168.0.1, targetmac=00:00:0c:01:02:03, targetip=172.16.1.50\"\n" \
		"\n"


#define MZ_BPDU_HELP \
   		"| BPDU type: Send arbitrary BPDU packets (spanning tree).\n" \
		"|\n" \
		"| ARGUMENT SYNTAX: <command> [<parameters>]\n" \
		"|                      |           \n" \
		"|          conf, tcn --+           \n" \
		"|                                  \n" \
		"| Parameters:\n" \
		"|\n" \
		"|      id = 0-65535      ..... default: 0, identifies 'Spanning Tree Protocol'\n" \
		"| version = 0-255        ..... default: 0\n" \
		"|    type = 0-255        ..... BPDU Type: 0=CONF, 1=TCN (default: CONF)\n" \
		"|   flags = 0-255        ..... 1=TC, 128=ACK (default: 0 = No TC, No ACK)\n" \
		"|  rootid = <pri>:<mac>  ..... 8 byte Root-ID (default: 00:00:<own-mac>)\n" \
		"|  rootpc = 0-4294967295 ..... root path cost (default: 0)\n" \
		"|     bid = <mac>        ..... 6 byte MAC address (default: own-mac)\n" \
		"|     pid = 0-65535      ..... port identifier (default: 0)\n" \
		"|     age = 0-65535      ..... message age (default: 0)\n" \
		"|  maxage = 0-65535      ..... max age (default: 20)\n" \
		"|   hello = 0-65535      ..... hello time (default: 2)\n" \
		"|     fwd = 0-65535      ..... forward delay (default: 15)\n" \
		"|     tag     -          ..... Keyword to enforce 802.1Q VLAN tag; use this\n" \
		"|                              together with the 'vlan' parameter below.\n" \
		"|\n" \
		"| PVST+ extensions:\n" \
		"|\n" \
		"|  vlan     ..... VLAN number (default: 0)\n" \
		"|  pri      ..... 802.1P-Priority (0-7, default: 0)\n" \
		"|  notag    ..... Omit 802.1Q VLAN tag\n" \
		"|  \n" \
                "|\n" \
		"| DEFAULTS: mz sends standard IEEE 802.1d (CST) BPDUs and assumes that your computer\n" \
		"| wants to become the root bridge (rid=bid). Configuration BPDUs are the default but\n" \
		"| can be changed using the 'tcn' keyword. Optionally the 802.3 source and destination\n" \
		"| MAC addresses can be specified using the -a and -b options. Per default, the correct\n" \
		"| STP or  PVST+ destination addresses are used (same as '-b stp' or '-b pvst', \n" \
		"| respectively).\n" \
		"| \n" \
		"| Note that the parameter 'vlan' only selects the PVST+ mode if the parameter 'tag' is\n" \
		"| NOT used.\n" \
		"\n"



// Send arbitrary ARP packets.
// Note:
//    - The Ethernet dst and src MAC addresses can be specified,
//      the eth_src_txt can be 'rand' 
//    - If eth_dst and eth_src are NOT specified then practical defaults are used
//
// arg_string syntax: <command>, <param>, ... , <param>
//    - commands: 'request' OR 'reply'
//    - params: 'sendermac', 'senderip', 'targetmac', 'targetip'
//
// Example arg_string for ARP cache poisoning: 
//     "reply, senderip=192.168.0.1, targetmac=00:00:0c:01:02:03, targetip=172.16.1.50"
//     where sendermac will be automatically replaced by own mac, 
//     senderip is the spoofed IP, 
//     targetmac and targetip identifies the receiver. 
// 
int send_arp ()
{
   libnet_t             *l;
   libnet_ptag_t         t;

   char 
     argval[64],
     t1[64],
     t2[64],
     src,
     dst,
     errbuf[LIBNET_ERRBUF_SIZE];

   int 
     i,
     arpmode=0, 
     arpop=0, 
     loop,
     tm=0;
   
   u_int8_t 
     *packet,
     sendermac[6], 
     targetmac[6];
   
   
   
   u_int32_t   
     packet_s,
     senderip=0, 
     targetip=0;


   if (tx.dot1Q)
     {
	fprintf(stderr," Note: ARP mode does not support 802.1Q builder.\n");
	exit(1);
     }
   
   if (tx.mpls)
     {
	fprintf(stderr," Note: ARP mode does not support MPLS builder.\n");
	exit(1);
     }

   if (getarg(tx.arg_string,"help", NULL)==1)
     {
	if (mz_port)
	  {
	     cli_print(gcli, "%s", MZ_ARP_HELP);
	     return -1;
	  }
	else
	  {
	     fprintf(stderr,"\n" 
		     MAUSEZAHN_VERSION
		     "\n%s", MZ_ARP_HELP);
	     exit(0);
	  }
     }

   
   // Set the flags to shorten subsequent decisions:
   src = strlen(tx.eth_src_txt);
   dst = strlen(tx.eth_dst_txt);
   
   l = libnet_init(LIBNET_LINK_ADV, tx.device, errbuf);   

   if (l == NULL)
     {
	fprintf(stderr, "%s", errbuf);
	exit(EXIT_FAILURE);
     }

   
   
   if (getarg(tx.arg_string,"request", NULL)==1)
     {
	arpmode=1;
	arpop = ARPOP_REQUEST;
     }
   else
     if (getarg(tx.arg_string, "reply", NULL)==1)
       {	
	  arpmode=2; 
	  arpop = ARPOP_REPLY;
       }	
   else	
     { // Default:
        arpmode=2; 
	arpop = ARPOP_REPLY;
     }
   

  
   if ( (getarg(tx.arg_string,"sendermac", argval)==1) || (getarg(tx.arg_string,"smac", argval)==1) )
     {
	//TODO: Allow 'rand' as sendermac
	str2hex(argval,sendermac,6);
     }
   else
     {
        // sendermac is usually ALWAYS own MAC:
	getbytes(tx.eth_src, sendermac,1,6);
     }
   
	
   if ( (getarg(tx.arg_string,"targetmac", argval)==1) || (getarg(tx.arg_string,"tmac", argval)==1) )
     {
	str2hex(argval,targetmac,6);
	tm=1;
     }
   else
     {  
	// targetmac is either zero (request) or bcast (reply=>gratitious ARP)
	if (arpmode==1) //request
	  str2hex("00:00:00:00:00:00",targetmac, 6);
	else //reply
	  str2hex("ff:ff:ff:ff:ff:ff",targetmac, 6);
     }

   
   if ( (getarg(tx.arg_string,"senderip", argval)==1) || (getarg(tx.arg_string,"sip", argval)==1) )
     {
	senderip = str2ip32_rev(argval);
     }
   else
     {
	// senderip is usually ALWAYS the own IP
	senderip = libnet_get_ipaddr4(l); // TODO - use tx.ip_src
     }
   
   
   
   if ( (getarg(tx.arg_string,"targetip", argval)==1) || (getarg(tx.arg_string,"tip", argval)==1) )
     {
	targetip = str2ip32_rev(argval);
     }
   else
     {
	// if targetip is missing also use own IP because it may be used for duplicate IP detection
	targetip = libnet_get_ipaddr4(l);
     }


   
   // NOTE: Now all ARP parameters are set (possibly defaults used!)

   bs2str(sendermac,t1,6); 
   bs2str(targetmac,t2,6);
   //Check:
   //printf("-- sendermac=%s targetmac=%s senderip=%u targetip=%u\n",t1,t2,senderip,targetip);
   


   // Build the ARP header
   
   t = libnet_autobuild_arp(arpop,                            /* operation type */
			    sendermac,                        /* sender hardware addr */
			    (u_int8_t *)&senderip,            /* sender protocol addr */
			    targetmac,                        /* target hardware addr */
			    (u_int8_t *)&targetip,            /* target protocol addr */
			    l);                               /* libnet context */
   
   if (t == -1)
     {
	fprintf(stderr, " mz/send_arp: Can't build ARP header: %s\n", libnet_geterror(l));
	exit(EXIT_FAILURE);
     }
   
   
   // Finally build the Ethernet header
	
   if ((!dst) && (!src)) // ... user does not care about addresses (both eth_dst and eth_src NOT specified)
     {
	if (arpmode==1)
	  str2hex("ff:ff:ff:ff:ff:ff", tx.eth_dst, 6);
	else
	  getbytes(targetmac, tx.eth_dst, 1, 6); // either also bcast or specific MAC
	
	t = libnet_autobuild_ethernet(tx.eth_dst,                             /* ethernet destination */
				      ETHERTYPE_ARP,                          /* protocol type */
				      l);                                     /* libnet handle */
	
	if (t == -1)
	  {
	     fprintf(stderr, " mz/send_arp: Can't build ethernet header: %s\n",
		     libnet_geterror(l));
	     exit(EXIT_FAILURE);
	  }
     } 
   else // EITHER eth_dst OR eth_src OR BOTH specified:
     {
	if (!dst)
	  {
	     if (arpmode==1)
	       str2hex("ff:ff:ff:ff:ff:ff", tx.eth_dst, 6);
	     else
	       getbytes(targetmac, tx.eth_dst, 1, 6); // either also bcast when reply or specific MAC
	  }
	else // eth_dst specified
	  {
	     if (check_eth_mac_txt(ETH_DST))  // if true then problem!
	       {
		  str2hex("ff:ff:ff:ff:ff:ff",tx.eth_dst, 6); // the default
	       }
	  }
	
	
	if (!src)
	  {
	     // tx.eth_src contains own MAC by default!
	  }
	else // use specified source MAC address
	  {
	     if (check_eth_mac_txt(ETH_SRC))  // if true then problem!
	       {
		  str2hex("ff:ff:ff:ff:ff:ff",tx.eth_src, 6); // the default
	       }
	  }
	
	t = libnet_build_ethernet (tx.eth_dst, tx.eth_src, ETHERTYPE_ARP, NULL, 0, l, 0); // Note: payload=NULL, payload_s=0
     }
   
   if (libnet_adv_cull_packet(l, &packet, &packet_s) == -1)
     {
	fprintf(stderr, "%s", libnet_geterror(l));
     }
    	else
     {
	libnet_adv_free_packet(l, packet);
     }
   
   // this is for the statistics:
   mz_start = clock();
   total_d = tx.count;

   
   again:
   
   if (tx.count==0)
     loop=1000000;
   else
     loop=tx.count;
   
   for (i=1; i<=loop; i++)
     {
	     
	if (!simulate) libnet_write(l);
	
	if (verbose)
	  {
	     fprintf(stderr," sent ARP: %s smac=%s sip=%s tmac=%s tip=%s\n",
		     (arpmode==1) ? "request" : "reply",
		     t1,
		     libnet_addr2name4(senderip,LIBNET_DONT_RESOLVE),
		     t2,
		     libnet_addr2name4(targetip,LIBNET_DONT_RESOLVE));
	  }
	
	
	if (tx.delay) SLEEP (tx.delay);
     }

   if (tx.count==0)
     {
	goto again;
     }
   
   
   libnet_destroy(l);
   
   return 0;
} 















///////////////////////////////////////////////////////////////////////////////////////
// Send arbitrary BPDU frames.
//
// commands: 
//     conf|tcn ...when specifying everything yourself
//    
// params: 
//     id, version, type, flags, rootid, rootpc, bid, pid, age, maxage, hello, fwd,
//     vlan
// 
// defaults:
//     mz assumes you want to become root bridge! (rid=bid)
//     
int send_bpdu ()
{

   // BPDU parameters:
   u_int16_t 
     id=0;       
   u_int8_t 
     version=0, 
     bpdu_type=0,   // 0=conf, 1=topology change (actually in big endian!) 
     flags=0,       // 1=TC, 128=TCAck 
     root_id[8],    // Root BID 
     bridge_id[8];  // Own BID
   u_int32_t 
     root_pc=0;     // Root Path Cost
   u_int16_t 
     port_id=0,     // Port Identifier
     message_age=0, // All timers are multiples of 1/256 sec. Thus times range from 0 to 256 seconds.
     max_age=20, 
     hello_time=2,  //
     f_delay=15;

   // LLC Parameters:
   u_int8_t 
     dsap=0x42, 
     ssap=0x42, 
     control=0x3;

   // Optional payload (needed for PVST+)
   u_int8_t
     bpdu_payload[64],
     snap_oui[3];
   u_int32_t 
     bpdu_payload_s=0;
   u_int16_t
     vlan=0;
   u_int8_t
     priority=0x00,
     *x;
   int 
     tag=0;
   
   
   // Standard libnet variables: 
   libnet_t *l;
   libnet_ptag_t t;
   char errbuf[LIBNET_ERRBUF_SIZE];
   
   // Other variables:
   unsigned int  i, loop;
   int           bpdumode=0;
   char          argval[64];
   char          dum1[32], dum2[32];

   
   if (tx.dot1Q)
     {
	fprintf(stderr," Note: BPDU mode does not support 802.1Q builder.\n");
	exit(1);
     }
   
   if (tx.mpls)
     {
	fprintf(stderr," Note: BPDU mode does not support MPLS builder.\n");
	exit(1);
     }


   // HELP TEXT
   if (getarg(tx.arg_string,"help", NULL)==1)
     {
	if (mz_port)
	  {
	     cli_print(gcli, "%s", MZ_BPDU_HELP);
	     return -1;
	  }
	else
	  {
	     fprintf(stderr,"\n" 
		     MAUSEZAHN_VERSION
		     "\n%s", MZ_BPDU_HELP);
	     exit(0);
	  }
     }

   /////////////////////////////////////////////////////////
   // Default Destination Address
   if (check_eth_mac_txt(ETH_DST))  // if true then problem!
     {
	str2hex("01:80:C2:00:00:00",tx.eth_dst, 6); // if '1' then user did not set MAC address (or problem occurred)
     }
   
   // Default Bridge-ID
   bridge_id[0]=0x00;
   bridge_id[1]=0x00;
   for (i=0; i<6; i++)   bridge_id[2+i]=tx.eth_src[i];
   for (i=0; i<8; i++)   root_id[i]=bridge_id[i];
   /////////////////////////////////////////////////////////
   
   
   
   
   // determine BPDU type:
   if (getarg(tx.arg_string,"conf", NULL)==1)
     {
	bpdumode=1;
	tx.eth_len = LIBNET_802_2_H + LIBNET_STP_CONF_H;   
     }
   else
     if (getarg(tx.arg_string, "tcn", NULL)==1)
       {	
	  bpdumode=2; 
	  tx.eth_len = LIBNET_802_2_H + LIBNET_STP_TCN_H;
	  bpdu_type=0x80;
       }	
   else // default
     {
	bpdumode=1;
	tx.eth_len = LIBNET_802_2_H + LIBNET_STP_CONF_H;
     }
   

// Commands summary:
// id, version, type, flags, rid, rootpc, bid, pid, age, maxage, hello, fwd   

   if (getarg(tx.arg_string,"id", argval)==1)
     {
	id = (u_int16_t) str2int(argval);
     }
   
   if (getarg(tx.arg_string,"version", argval)==1)
     {
	version = (u_int8_t) str2int(argval);
     }
   
   if (getarg(tx.arg_string,"bpdu_type", argval)==1)
     {
	bpdu_type = (u_int8_t) str2int(argval);
     }
   
   if (getarg(tx.arg_string,"flags", argval)==1)
     {
	flags = (u_int8_t) str2int(argval);
     }
   
   if (getarg(tx.arg_string,"rid", argval)==1)
     {
	if (str2hex(argval,root_id, 8)!=8)
	  {
	     fprintf(stderr," mz/send_bpdu: [ERROR] The root-id must be exactly 8 bytes!\n");
	     exit (-1);
	  }
     }

   if (getarg(tx.arg_string,"rootpc", argval)==1)
     {
	root_pc = (u_int32_t) str2int(argval);
     }

   if (getarg(tx.arg_string,"bid", argval)==1)
     {
	if (str2hex(argval,bridge_id, 6)!=6)
	  {
	     fprintf(stderr," mz/send_bpdu: [ERROR] The bridge-id must be exactly 6 bytes!\n");
	     exit (-1);
	  }
     }
   
   if (getarg(tx.arg_string,"pid", argval)==1)
     {
	port_id = (u_int16_t) str2int(argval);
     }
   
   if (getarg(tx.arg_string,"age", argval)==1)
     {
	message_age = (u_int16_t) str2int(argval);
     }

   if (getarg(tx.arg_string,"maxage", argval)==1)
     {
	max_age = (u_int16_t) str2int(argval);
     }
   
   if (getarg(tx.arg_string,"hello", argval)==1)
     {
	hello_time = (u_int16_t) str2int(argval);
     }
   
   if (getarg(tx.arg_string,"fwd", argval)==1)
     {
	f_delay = (u_int16_t) str2int(argval);
     }



   if (getarg(tx.arg_string,"vlan", argval)==1)
     {
	// PVST+ uses TLVs of type=0x00, len=0x02, and Value=0xVV which is the VLAN ID
	// The DA must be 0100.0ccc.cccd instead of the standard 0180.c200.0000
	// 
	if (check_eth_mac_txt(ETH_DST))  // if '1' then user did not set MAC address (or problem occurred)
	  {
	     str2hex("01:00:0C:CC:CC:CD",tx.eth_dst, 6); // Cisco PVST+ address
	  }
	
/*	// OLD TLV, maybe wrong, maybe obsolete, I don't know.
        
        bpdu_payload[0] = 0x34;
	bpdu_payload[1] = 0x00;
	bpdu_payload[2] = 0x02;
	vlan = (u_int16_t) str2int(argval);
	
	x = (u_int8_t*) &vlan;
	bpdu_payload[3] = *(x+1);
	bpdu_payload[4] = *(x);
	bpdu_payload[5] = 0x00;
	bpdu_payload[6] = 0x00;
	bpdu_payload_s = 7;
*/
        // Updated PVST+ TLV:
     	bpdu_payload[0] = 0x00;
	bpdu_payload[1] = 0x00;
	bpdu_payload[2] = 0x00;
	bpdu_payload[3] = 0x00;
	bpdu_payload[4] = 0x02;
        vlan = (u_int16_t) str2int(argval);
        x = (u_int8_t*) &vlan;
	bpdu_payload[5] = *(x+1);
	bpdu_payload[6] = *(x);
	bpdu_payload_s = 7;
	     
	tag=1; // set the default: Use 802.1Q tag !!!
     }
   else // even a normal BPDU must be padded to 60 bytes (total)
     { 
	bpdu_payload[0] = 0x00;
	bpdu_payload[1] = 0x00;
	bpdu_payload[2] = 0x00;
	bpdu_payload[3] = 0x00;
	bpdu_payload[4] = 0x00;
	bpdu_payload[5] = 0x00;
	bpdu_payload[6] = 0x00;
	bpdu_payload[7] = 0x00;
	bpdu_payload_s = 8;
	
	tag=0; // set the default: send untagged !!!
     }

   
   // Note: The order is important because above the defaults for 'tag' has been set. 
   // 
   if (getarg(tx.arg_string,"notag", NULL)==1)
     {
	tag=0;
     }
   
   
   // Send normal BPDU with VLAN tag
   if (getarg(tx.arg_string,"tag", NULL)==1)
     {
	tag=2;
	bpdu_payload[0] = 0x00;
	bpdu_payload[1] = 0x00;
	bpdu_payload[2] = 0x00;
	bpdu_payload[3] = 0x00;
	bpdu_payload[4] = 0x00;
	bpdu_payload[5] = 0x00;
	bpdu_payload[6] = 0x00;
	bpdu_payload[7] = 0x00;
	bpdu_payload_s = 8;

	// Rewrite to standard 0180.c200.0000
	// 
	if (check_eth_mac_txt(ETH_DST))  // if '1' then user did not set MAC address (or problem occurred)
	  {
	     str2hex("01:80:C2:00:00:00",tx.eth_dst, 6);
	  }
	vlan = (u_int16_t) str2int(argval);
     }
   
   
   if (getarg(tx.arg_string,"pri", argval)==1)
     {
	priority = (u_int8_t) str2int(argval);
	if (priority>7)
	  {
	     fprintf(stderr, " mz/send_bpdu: Priority must be between 0 and 7.\n");
	     exit(1);
	  }
	
	if (tag==0)
	  {
	     fprintf(stderr, " mz/send_bpdu: Priority cannot be used together with the 'notag' keyword.\n");
	     exit(1);
	  }  
     }
   
   
   // Open the link - get libnet handle
   l = libnet_init(LIBNET_LINK_ADV, tx.device, errbuf);
   
   if (l == NULL)
     {
	fprintf(stderr, "%s", errbuf);
	exit(EXIT_FAILURE);
     }


   if (bpdumode==1)    // Prepare CONFIGURATION BPDU:
     {

	t = libnet_build_stp_conf (id, 
				   version, 
				   bpdu_type,
				   flags, 
				   root_id, 
				   root_pc, 
				   bridge_id,
				   port_id, 
				   message_age, 
				   max_age,
				   hello_time, 
				   f_delay,
				   (bpdu_payload_s) ? bpdu_payload : NULL,
				   bpdu_payload_s,
				   l, 
				   0);
	
	if (t == -1)
	  {
	     fprintf(stderr, " mz/send_bpdu: Can't build BPDU header: %s\n",
		     libnet_geterror(l));
	     exit(EXIT_FAILURE);
	  }
     }
   else // Topology Change BPDU
     {
	t = libnet_build_stp_tcn(id, 
				 version,
				 bpdu_type,
				 (bpdu_payload_s) ? bpdu_payload : NULL,
				 bpdu_payload_s,    
				 l,    
				 0);   
	if (t == -1)
	  {
	     
	     fprintf(stderr, " mz/send_bpdu: Can't build BPDU header: %s\n",
		     libnet_geterror(l));
	     exit(EXIT_FAILURE);
	  }
     }
	

   
   if ( (vlan==0) || (tag==2) )  // normal BPDU
     {
	// normal LLC without SNAP
	t = libnet_build_802_2 (dsap, 
				ssap, 
				control,
				NULL,
				0,
				l, 
				0);
	
	if (t == -1)
	  {
	     fprintf(stderr, " mz/send_bpdu: Can't build LLC header: %s\n",
		     libnet_geterror(l));
	     exit(EXIT_FAILURE);
	  }
     }
   else // PVST+ => LLC with SNAP
     {
	snap_oui[0]=0x00;
	snap_oui[1]=0x00;
	snap_oui[2]=0x0c;
	
	// requires a SNAP header with oui=0x00000c and type=0x010b
	t = libnet_build_802_2snap(0xAA,
				   0xAA, 
				   0x03,
				   snap_oui, 
				   0x010b, 
				   NULL, 
				   0,
				   l, 
				   0);
	
	if (t == -1)
	  {
	     fprintf(stderr, " mz/send_bpdu: Can't build SNAP header: %s\n",
		     libnet_geterror(l));
	     exit(EXIT_FAILURE);
	  }
     }

   
   if (tag==0)
     {
	// Normal 802.3 header without VLAN tag
	t = libnet_build_802_3 (tx.eth_dst, 
				tx.eth_src,
				(vlan) ? 0x36 : tx.eth_len, // NOTE the LENGTH field => 802.3 header!
				NULL,
				0,
				l, 
				0);
	
     }
   else // PVST+ => 802.3 with 802.1Q
     {
	t = libnet_build_802_1q(tx.eth_dst, 
				tx.eth_src, 
				0x8100,
				priority,
				0x00, // CFI
				vlan, 
				0x32, //tx.eth_len,
				NULL,
				0,
				l,
				0);
     }
   
   
   if (t == -1)
     {
	fprintf(stderr, " mz/send_bpdu: Can't build 802.3 header: %s\n",
		libnet_geterror(l));
	exit(EXIT_FAILURE);
     }


   // This is ugly but it works good ;-)
   if (tx.count==0)
     loop=1000000;
   else
     loop=tx.count;

   // this is for the statistics:
   mz_start = clock();
   total_d = tx.count;

   
   again:
   
   for (i=1; i<=loop; i++)
     {
	if (!simulate) libnet_write(l);
	
	if (verbose)
	  {
	     bs2str(root_id,dum1,8);
	     bs2str(bridge_id,dum2,8);
	     fprintf(stderr," sent BPDU: ");
	     fprintf(stderr,"%s ", (bpdumode==1) ? "conf" : "tcn ");
	     fprintf(stderr," id=%u ver=%u flags=%x rid=%s bid=%s\n"
		            "                  rpc=%u pid=%u age=%u maxage=%u hello=%u fwd_delay=%u\n",
		     id, 
		     version, 
		     flags, 
		     dum1, 
		     dum2,
		     root_pc, 
		     port_id, 
		     message_age, 
		     max_age,
		     hello_time, 
		     f_delay);
	     
	     fprintf(stderr,"\n");
	  }
	
	
	if (tx.delay) SLEEP (tx.delay);
     }
   
   if (tx.count==0)
     {
	goto again;
     }
   
   
   libnet_destroy(l); 

   return 0;
}


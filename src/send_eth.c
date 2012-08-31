/*
 * Mausezahn - A fast versatile traffic generator
 * Copyright (C) 2008 Herbert Haas
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
//    This sections contains (as alternative to 'send_frame' in send.c) 
//    a layer-2 based flexible sending function.
//    
//    Layer-2 modifications such as 802.1Q and MPLS is considered here!
//     
// ***************************************************************************



#include "mz.h"

libnet_ptag_t  create_eth_frame (libnet_t *l, libnet_ptag_t  t3, libnet_ptag_t  t4)
{
   libnet_t *L=NULL;
   char errbuf[LIBNET_ERRBUF_SIZE];
   libnet_ptag_t  t=0, tmpls;
   char argval[128];   
   u_int8_t et[2];
   int et_len;
   
   int i=0, j, mlen, mkomma, len, count, offset=0, found_colon=0;
   char *left, *right;
   char *f, mtag[64];
   char verbose_mpls_string[128];
   
   u_int8_t *packet;
   u_int32_t packet_s;

   char *saveptr, *ptrsubstring, substring[16], tmp[4*MAX_8021Q_TAGS];
   u_int8_t  CoS;       // 0..7
   u_int16_t vlan;      // 12 bit value (0..4095)
   u_int8_t dot1Q[4*MAX_8021Q_TAGS], *ptr;
   u_int16_t dot1Q_eth_type=0x8100;
   int bytecnt=0;

   int  isdot1Q, tcp_seq_delta, dp_isrange, sp_isrange, ip_dst_isrange, ip_src_isrange, eth_src_rand, rtp_mode=0;
   unsigned int delay;

   
   
   
   
   
   ////////////////////////////////////////////////////
   // Prepare MPLS header if required
   if (tx.mpls)
     {
	// first check how many labels have been specified:
	mlen = strlen (tx.mpls_txt);
	mkomma=0;
	
	for (i=0; i<mlen; i++)
	  {
	     if (tx.mpls_txt[i]==',') mkomma++;
	  }
	
	f = strtok_r (tx.mpls_txt, ",", &saveptr);
	
	tx.mpls_bos=1;
	
	do
	  {
	     strncpy(mtag, f, 64);
	     /*
	     if (mkomma==0) 
	       {
		  tx.mpls_bos=0;
	       }
	     else
	       {
		  printf("BOS=1\n");
		  tx.mpls_bos=1;
	       }
	     */

	     
	     if ( get_mpls_params(mtag) ) // error?
	       {
		  fprintf(stderr," mz/get_mpls_params: MPLS Parameters problem.\n");
		  exit (0);
	       }
	     
	     tmpls = libnet_build_mpls(tx.mpls_label, 
				       tx.mpls_exp,
				       tx.mpls_bos,
				       tx.mpls_ttl,
				       NULL, 
				       0, 
				       l,
				       0);
	     
	     if (tmpls == -1)
	       {
		  fprintf(stderr, " mz/create_ip_packet: Can't build MPLS header: %s\n", libnet_geterror(l));
		  exit (0);
	       }

	     if (verbose)
	       {
		  sprintf(verbose_mpls_string,"[%u:%u:%u:%u]",
			  tx.mpls_label, 
			  tx.mpls_exp,
			  tx.mpls_bos,
			  tx.mpls_ttl);
		  strcat(tx.mpls_verbose_string, verbose_mpls_string);
		  strcat(tx.mpls_verbose_string, " ");
	       }
	     
	     tx.mpls_bos=0;
	     mkomma--;
	  }
	while ( (f=strtok_r(NULL, ",", &saveptr)) != NULL);
	
     }

   
   
   
   
   
   
   ////////////////////////////////////////////////////////////////////////////////////////////   
   // Evaluate Ethernet CLI options (-a and -b)
   if (check_eth_mac_txt(ETH_DST))  // if true then problem (invalid user input?)
     {
	str2hex("ff:ff:ff:ff:ff:ff",tx.eth_dst, 6); // the default
     }
   
   // if not specified then own MAC will be used automatically
   (void) check_eth_mac_txt(ETH_SRC); 
   
   
   // Get CLI arguments:
   // If NOT set, default: 0x800 or ETHERTYPE_MPLS if MPLS is used (see init.c)
   if (getarg(tx.arg_string,"ether_type", argval)==1)
     {
	et_len = str2hex (argval, et, 2);
	
	if (et_len==1)
	  tx.eth_type = et[0];
	else // 2 bytes specified
	  tx.eth_type = 256 * et[0] + et[1];
	
	//tx.eth_type = (u_int16_t) str2int(argval);
     }

   
   
   
   
   
   
   
   /////////////////////////////////////////////////////////////////////////////////
   // Ethernet with 802.1Q
   // 
   // If multiple 802.1Q tags are specified then we need to build the whole
   // frame manually because libnet only supports adding a single VLAN header.
   // The easiest solution is to create the hex-string of the 802.1Q-chain as
   // u_int8_t QinQ[] then add the IP packet as payload... 
   // 
   if (tx.dot1Q) // actually contains the number of VLAN tags
     {

	// we want our own context!
	L = libnet_init(LIBNET_LINK_ADV, tx.device, errbuf);
	if (L == NULL)
	  {
	     fprintf(stderr, "%s", errbuf);
	     exit(EXIT_FAILURE);
	  }   
	
	strncpy(tmp,tx.dot1Q_txt,(4*MAX_8021Q_TAGS));
	ptrsubstring = strtok_r(tmp, ",.", &saveptr);
	bytecnt=0;
	do
	  {
	     // make a local copy
	     strncpy(substring, ptrsubstring, 16);
	     CoS=0; vlan=0;
	     // Get CoS and VLAN ID from partial string 
	     len = strlen(substring);
	     found_colon=0;
	     for (i=0; i<len; i++)
	       {
		  if  (substring[i]==':')  found_colon=1;
	       }
	     if (found_colon) // Both CoS and VLAN specified
	       {
		  left = strtok (substring, ":");
		  right = strtok (NULL, ":");
		  CoS = (u_int8_t) str2int (left);
		  vlan = (u_int16_t) str2int (right);
	       }
	     else  // Only VLAN specified
	       {
		  vlan = (u_int16_t) str2int (substring);
	       }
	     
	     if (CoS > 7) 
	       {
		  fprintf(stderr, " mz/create_eth_frame: CoS too high, adjusted to 7\n");
		  CoS = 7;
	       }
	     
	     if (vlan > 4095) 
	       {
		  fprintf(stderr, " mz/create_eth_frame: VLAN number too high, adjusted to 4095\n");
		  vlan = 4095;
	       }
	     
	     // create 4 byte 802.1Q header:
	     
	     dot1Q[bytecnt+0]=0x81;
	     dot1Q[bytecnt+1]=0x00;
	     ptr = (u_int8_t*) &vlan;
	     dot1Q[bytecnt+3]=*ptr;
	     ptr++;
	     *ptr = *ptr ^ (CoS<<5);  // add CoS 
	     dot1Q[bytecnt+2]=*ptr;
	     //check:
	     //printf("%02x %02x %02x %02x\n",dot1Q[bytecnt+0],dot1Q[bytecnt+1],dot1Q[bytecnt+2],dot1Q[bytecnt+3]);
	     bytecnt+=4; // next tag (note that bytecnt will finally hold the number of used bytes!)
	     
	  } while ( (ptrsubstring = strtok_r(NULL, ",.", &saveptr)) !=NULL); //get all VLAN tags 
		    
	// now create the whole packet:

	dot1Q_eth_type = 0x8100; //these are also the first two bytes of dot1Q[]
	bytecnt = bytecnt-2;
	
	for (i=0;i<bytecnt;i++)
	  {
	     tx.eth_payload[i]=dot1Q[i+2];
	  }
	
	// now add official EtherType for the payload (this has been determined some lines above)
	ptr = (u_int8_t*) & tx.eth_type;
	tx.eth_payload[i+1]= *ptr;
	ptr++;
	tx.eth_payload[i]= *ptr;
	offset = i+2;

	// -
	// --
	// ---
	// ---- now all 802.1Q headers are genereated    ----
	// ---- and are placed already in tx.eth_payload ----
	// ---- (and 'i' points to the next free byte)   ----
	// ---
	// --
	// -
	
	// Finally get all bytes of upper layers (IP packet and payload) 
	if (libnet_adv_cull_packet(l, &packet, &packet_s) == -1)
	  {
	     fprintf(stderr, "%s", libnet_geterror(l));
	  }

	// Copy the upper layer data to the eth_payload
	for (j=0; j<packet_s; j++)
	  {
	     tx.eth_payload[j+offset]=packet[j];
	  } 

	// 'libnet_adv_cull_packet' performs an implicit malloc() and a corresponding call 
	// to libnet_adv_free_packet() should be made to free the memory packet occupies:
	libnet_adv_free_packet(l, packet); 
	
	tx.eth_payload_s = j+offset;
	tx.eth_type = dot1Q_eth_type;
	
	t = libnet_build_ethernet (tx.eth_dst, 
				   tx.eth_src, 
				   tx.eth_type,
				   tx.eth_payload,
				   tx.eth_payload_s, 
				   L,
				   0);

	if (t == -1)
	  {
	     fprintf(stderr, " mz/create_eth_frame: Can't build Ethernet header: %s\n",
		     libnet_geterror(l));
	     exit(EXIT_FAILURE);
	  }
	
	// NOW the whole frame is ready to send!

     }
   
   else // normal Ethernet header without any 802.1Q-tag or MPLS-label
     
     {
	
	t = libnet_build_ethernet (tx.eth_dst, 
				   tx.eth_src, 
				   tx.eth_type, 
				   NULL,              // the payload
				   0, 
				   l, 
				   0);
	
	if (t == -1)
	  {
	     fprintf(stderr, " mz/create_eth_frame: Can't build Ethernet header: %s\n",
		     libnet_geterror(l));
	     exit(EXIT_FAILURE);
	  }
     }

   /////////////////////////////////////////////////////////////////////////////
   //
   // Now send everything - maybe lots of times with modifications.
   // 
   // 

   // local vars are faster :-)
   count = tx.count;
   delay = tx.delay;
   eth_src_rand = tx.eth_src_rand;
   tcp_seq_delta = tx.tcp_seq_delta;
   dp_isrange = tx.dp_isrange;
   sp_isrange = tx.sp_isrange;
   ip_dst_isrange = tx.ip_dst_isrange;
   ip_src_isrange = tx.ip_src_isrange | tx.ip_src_rand; // either case should call update_SA()
   isdot1Q = tx.dot1Q;
   if (mode == RTP) rtp_mode = 1;
   
   if (count==0) goto AGAIN;
   
   for (i=0; i<count; i++)
     {
	
	AGAIN:

	if (isdot1Q)
	  {
	     // Get all bytes of upper layers (IP packet and payload) 
	     if (libnet_adv_cull_packet(l, &packet, &packet_s) == -1)
	       {
		  fprintf(stderr, "%s", libnet_geterror(l));
	       }
	     
	     // Copy the upper layer data to the eth_payload
	     for (j=0; j<packet_s; j++)
	       {
		  tx.eth_payload[j+offset]=packet[j];
	       } 

	     // 'libnet_adv_cull_packet' performs an implicit malloc() and a corresponding call 
	     // to libnet_adv_free_packet() should be made to free the memory packet occupies:
	     libnet_adv_free_packet(l, packet); 
	     
	     if (eth_src_rand) update_Eth_SA(L, t);
	     
	     t = libnet_build_ethernet (tx.eth_dst, 
					tx.eth_src, 
					tx.eth_type,
					tx.eth_payload,
					tx.eth_payload_s,
					L, 
					t);
	     if (t == -1)
	       {
		  fprintf(stderr, " mz/create_eth_frame: Can't build Ethernet header: %s\n",
			  libnet_geterror(l));
		  exit(EXIT_FAILURE);
	       }
	     if (verbose) (void) print_frame_details();
	     libnet_write(L);
	  }
	else // No QinQ and/or MPLS modifications => use normal 'l' context:
	  {
	     if (eth_src_rand) update_Eth_SA(l, t);
	     if (verbose) (void) print_frame_details();
	     libnet_write(l);
	  }

	
//	if (verbose) (void) print_frame_details();
	if (delay) SLEEP (delay);
	     
	     
	if (tcp_seq_delta)
	  {
	     if (update_TCP_SQNR(l, t4)==0) // end of range not yet reached
	       {
		  goto AGAIN;
	       }
	  }
	
	if (dp_isrange)
	  {
	     if (update_DPORT(l, t4)==0) // end of range not yet reached
	       {
		  goto AGAIN;
	       }
	  }
	
	if (sp_isrange)
	  {
	     if (update_SPORT(l, t4)==0) // end of range not yet reached
	       {
		  goto AGAIN;
	       }
	  }

	if (ip_dst_isrange)
	  {
	     if (update_IP_DA(l, t3)==0) // end of range not yet reached
	       {
		  goto AGAIN;
	       }
	  }
	
	if (ip_src_isrange)
	  {
	     if (update_IP_SA(l, t3)==0) // end of range not yet reached
	       {
		  goto AGAIN;
	       }
	  }

	
	if (rtp_mode) // update SQNR and Timestamps in RTP header and payload
	  {
	     update_RTP(l, t4);
	  }

	
	if (!count) goto AGAIN;
     }
   
   
   libnet_destroy(l);
   if (isdot1Q)
   libnet_destroy(L);
   

   return t;
}



void print_dot1Q_help(void)
{
   
	     fprintf(stderr,"\n"
		     MAUSEZAHN_VERSION
		     "\n"
		     "| 802.1Q header Syntax: -Q tag[,tag[,tag[,...]]]\n"
		     "| where each tag may consist of a CoS value using the syntax:\n"
		     "|\n"
		     "|  <CoS>:<tag value>\n"
		     "|\n"
		     "| Examples:\n"
		     "|\n"
		     "|  # mz -Q 100\n"
		     "|  # mz -Q 5:100\n"
		     "|  # mz -Q 5:100,200\n"
		     "|  # mz -Q 5:100,7:200\n"
		     "|  # mz -Q 100,200,300,5:400\n"
		     "\n\n");
	     
	     exit(0);
}
	
	

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

// Callback functions for the commands.
// __FUNCTION__ contains the name of the current callback function (for troubleshootig)


////////////////////////////////////////////////////////////////////////////////
int cmd_test(struct cli_def *cli, char *command, char *argv[], int argc)
{
    cli_print(cli, "called %s with %s\r\n", __FUNCTION__, command);
    return CLI_OK;
}



////////////////////////////////////////////////////////////////////////////////
int debug_all (struct cli_def *cli, char *command, char *argv[], int argc)
{
   if ( strncmp(argv[argc-1], "?", 1) == 0)
     {
	cli_print(cli, "Will debug everything. (Be careful!)\n");
	return CLI_OK;
     }
   

   cli_debug = 0x7fff;
   cli_print(cli, "Debug all enabled - stop with undebug all\r");
   cli_print(cli, "Note: _Already_ active packets will not be omitted!\n");
   
   if (mz_strcmp(argv[argc-1], "dev", 3)==0)
     {
	cli_print(cli, "*** Developer mode debugging enabled ***\n");
	cli_debug = 0xffff;
     }
   
   return CLI_OK;
}




////////////////////////////////////////////////////////////////////////////////
// Clear all _legacy_ Mausezahn settings (reinitialize anything)
int clear_all(struct cli_def *cli, char *command, char *argv[], int argc)
{
	if (argc) {
		cli_print(cli, "No argument required! Try again.\n");
		return CLI_OK;
	}

	reset();
	cli_print(cli, "All legacy Mausezahn parts have been reinitialized.\r");
	mops_delete_all(mp_head);
	mops_reset_packet (mp_head);
	cli_print(cli, "MOPS has been reinitialized.\n");
   return CLI_OK;
}


int clear_packet(struct cli_def *cli, char *command, char *argv[], int argc)
{
	
	struct mops *cur;
	u_int32_t i;
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc!=1) )
	{
		cli_print(cli, "Delete a single packet (i. e. MOPS entry).\r");
		cli_print(cli, "Expects a single argument which is either a packet's ID or name.\r");
		cli_print(cli, "NOTE: If the name matches an ID then the name has higher preference.\n");
		return CLI_OK;
	}

	
	if (argc!=1) {
		cli_print(cli, "Please specify only the packets ID or name\n");
		return CLI_OK;
	}

	cur = mops_search_name (mp_head, argv[0]);
	if (cur==NULL) {
		i = (u_int32_t) str2int (argv[0]);
		cur = mops_search_id (mp_head, i);
		if (cur==NULL) {
			cli_print(cli, "No packet found with that ID or name!\n");
			return CLI_OK;
		}
	}
	clipkt = mops_delete_packet(cur);
	cli_print(cli, "Packet deleted.\n");
   return CLI_OK;
}


int cmd_reset_packet(struct cli_def *cli, char *command, char *argv[], int argc)
{
	struct mops *cur;
	u_int32_t i;
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc!=1) )
	{
		cli_print(cli, "Resets a single packet (i. e. MOPS entry).\r");
		cli_print(cli, "Expects a single argument which is either a packet's ID or name.\r");
		cli_print(cli, "NOTE: If the name matches an ID then the name has higher preference.\n");
		return CLI_OK;
	}

	
	if (argc!=1) {
		cli_print(cli, "Please specify only the packets ID or name\n");
		return CLI_OK;
	}

	cur = mops_search_name (mp_head, argv[0]);
	if (cur==NULL) {
		i = (u_int32_t) str2int (argv[0]);
		cur = mops_search_id (mp_head, i);
		if (cur==NULL) {
			cli_print(cli, "No packet found with that ID or name!\n");
			return CLI_OK;
		}
	}
	
	mops_reset_packet(cur);
	cli_print(cli, "New packet name: %s\n", cur->packet_name);
   return CLI_OK;
}




////////////////////////////////////////////////////////////////////////////////
int warranty(struct cli_def *cli, char *command, char *argv[], int argc)
{
   cli_print(cli, MZ_WARRANTY_TEXT);
   return CLI_OK;
}


int show_system(struct cli_def *cli, char *command, char *argv[], int argc)
{
    cli_print(cli, "Not supported in this version\n");
    return CLI_OK;
}




////////////////////////////////////////////////////////////////////////////////
// Run through packet list and print some details about existing packets.
// SYNTAX:
// 
//   show packet 
//   show packet MyPacket
//   
int show_packets(struct cli_def *cli, char *command, char *argv[], int argc)
{
   int a=0, i, j=0, k, v, active_only=0;
   u_int32_t t;
   char c,T;
   char name[32], ds[16], pr[16], ps[16];
   char myframe[MAX_MOPS_FRAME_SIZE*3];
   char mystate[32];
   char line[150], line2[150], line3[150];
   char delay_str[64];
   unsigned char *x0, *x1, *x2, *x3;
    
   struct mops *head = mp_head;
   struct mops *mp = mp_head;
   

   if (strncmp(argv[argc-1], "?", 2)==0) {
	   cli_print(cli, "<CR>           Show list of all defined packets\r");
	   cli_print(cli, "active         Only show active packets\r");
	   cli_print(cli, "<PKT_ID>       Show detailed info about given packet\r");
//TODO	   cli_print(cli, "type <proto>   Only list packets r");
	   cli_print(cli, "\n");
	   return CLI_OK;
   }
   
   if (argc==1) {
      if (mz_strcmp(argv[0], "active", 1)==0) {
           active_only=1;
      }
   }
	
   if ((argc==0) || (active_only)) // show packet summary
     {
	cli_print(cli, "Packet layer flags: E=Ethernet, S=SNAP, Q=802.1Q, M=MPLS, I/i=IP/delivery_off, U=UDP, T=TCP\n");
	cli_print(cli, "PktID  PktName           Layers  Proto    Size  State      Device      Delay       Count/CntX\n");
	
	do
	  {
             if (active_only) {
		    if (mp->state < MOPS_STATE_ACTIVE) {
			    mp = mp->next;
			    j++;
			    continue;
		    } 
	     }
		     
	     ds[0]='\0';
	     ps[0]='\0';
	     pr[0]='\0';
	     
	     if (mp->use_ETHER) strcat(ds,"E"); else strcat(ds,"-");
	     if (mp->use_SNAP) strcat(ds,"S"); else strcat(ds,"-");
	     if (mp->use_dot1Q) strcat(ds,"Q"); else strcat(ds,"-");
	     if (mp->use_MPLS) strcat(ds,"M"); else strcat(ds,"-");
	     if (mp->use_IP) {
		     if (mp->auto_delivery_off) 
			     strcat(ds,"i"); 
		     else
			     strcat(ds,"I");
	     } else strcat(ds,"-");
		  
	     if (mp->use_UDP) 
	       strcat(ds,"U"); 
	     else if 
	       (mp->use_TCP) strcat(ds,"T"); 
	     else strcat(ds,"-");
		  


	     switch (mp->p_desc_type)
	       {
		case MOPS_ARP:
		  strncpy(pr, "ARP", 8);
		  break;
		case MOPS_BPDU:
		  strncpy(pr, "BPDU", 8);
		  break;
		case MOPS_CDP:
		  strncpy(pr, "CDP", 8);
		  break;
		case MOPS_DNS:
		  strncpy(pr, "DNS", 8);
		  break;
		case MOPS_ICMP:
		  strncpy(pr, "ICMP", 8);
		  break;
		case MOPS_IGMP:
		  strncpy(pr, "IGMP", 8);
		  break;
		case MOPS_LLDP:
		  strncpy(pr, "LLDP", 8);
		  break;
		case MOPS_RTP:
		  strncpy(pr, "RTP", 8);
		  break;
		case MOPS_SYSLOG:
		  strncpy(pr, "SYSLOG", 8);
		  break;
		default:
		  break;
	       }

	     
	     switch (mops_state(mp))
	       {
		case MOPS_STATE_NULL:
		  strcat(ps, "NULL");       // should never happen!
		  break;
		case MOPS_STATE_INIT:
		  strcat(ps, "init");
		  break;
		case MOPS_STATE_CONFIG:
		  strcat(ps, "config");
		  break;
		case MOPS_STATE_ACTIVE:
		  strcat(ps, "active");
		  a++;
		  break;
		case MOPS_STATE_SEQACT:
                  strcat(ps, "actseq");
		  a++;
		  break;
		default:
		  strcat(ps, "unknown");
		  break;
	       }

	  switch (mp->interval_used) {
	   case 1: // interval only configured, not started
		  strncat(ps, "-i", 2);
		  break;
		  
	   case 2:
		  strncat(ps, "+I", 2);
		  break;
	   default:
		  break;
	  }

		  
	     strncpy (name, mp->packet_name, 13); // only show first 13 chars
	     
	     if (strnlen(mp->packet_name, MAX_MOPS_PACKET_NAME_LEN)>13) 
	       {
		  name[13]=0x00;        
		  strcat(name, "...");
	       }
	     
	     // To determine the actual packet length  ***
	     // we must reassemble everything:         ***
	     mops_ext_update (mp);
	     mops_update (mp);
		  
	     timespec2str(&mp->ndelay, delay_str);
		  
	     //             ID   name  lrs  prot size state  dev    del   count/cntx/%
	     sprintf(line, "%5i  %-16s  %s  %-8s %4i  %-9s  %-6s    %10s%9lu/%lu (%i%%)\r",
		       mp->id,         // ID
		       name,           // packet_name
		       ds,             // layers
		       pr,             // protocol  
		       mp->frame_s,    // size
		       ps,             // state
		       mp->device,     // device
		       delay_str,      // delay
		       mp->count,      // Configured count value
		       mp->cntx,       // Current count
		       (mp->count) ? (int) (100 * (mp->count - mp->cntx)/mp->count) : 0 );
	     cli_print(cli, "%s\r", line);
	     mp = mp->next;
	     j++;
	  }
	while (head != mp);

	cli_print(cli, "\r");
	cli_print(cli, "%i packets defined, %i active.\n", j, a);
     }
   //////////////////////////////////////////////////////////////////////////////////////////////////////////
	
   //////////////////////////////////////////////////////////////////////////////////////////////////////////
   else if (argc == 1) // show details about a specific packet **********************************************
     { 
	if ( (mp = mops_search_name (mp_head, argv[0])) == NULL)// not found
	  {
	     if ( (mp = mops_search_id (mp_head, (int) str2int(argv[0]))) == NULL)// not found
	       {
		  cli_print (cli, "Packet not in list.\n");
		  return CLI_OK;
	       }
	  }

	// To determine the actual packet length  ***
	// we must reassemble everything:         ***
	mops_ext_update (mp);
	mops_update (mp);
	
	cli_print(cli, "Packet [%i] %s\r", mp->id, mp->packet_name);
	cli_print(cli, " Description: %s \r", 
		  (strnlen(mp->description, MAX_MOPS_DESCRIPTION_LEN)) ? mp->description : "(no description)");
	
	switch(mp->state)
	  {
	   case MOPS_STATE_NULL:
	     sprintf(mystate, "NULL");
	     break;
	   case MOPS_STATE_INIT:
	     sprintf(mystate, "init");
	     break;
	   case MOPS_STATE_CONFIG:
	     sprintf(mystate, "config");
	     break;
	   case MOPS_STATE_ACTIVE:
	     sprintf(mystate, "active(tx)");
	     break;
	   default:
	     sprintf(mystate, "unknown");
	  }
	
        timespec2str(&mp->ndelay, delay_str);
        if (mp->interval_used) 
	     timespec2str(&mp->interval, line2);
        else 	
	     sprintf(line2, "(undefined)");

	sprintf(line, "State: %s, Count=%lu, delay=%s (%lu s %lu nsec), interval= %s\r",
		  mystate, 
		  mp->count, 
		  delay_str, 
		  mp->ndelay.tv_sec, 
		  mp->ndelay.tv_nsec,
		  line2);
	cli_print(cli, " %s\r", line);
	     
	cli_print(cli, " Headers:\r");
	i=0;
	if (mp->use_ETHER)
	  {
	     if (mp->eth_src_israndom)
	       {
		  cli_print(cli, "  Ethernet: *** RANDOMIZED SMAC *** => %02x-%02x-%02x-%02x-%02x-%02x  [%04x%s]\r",
			    mp->eth_dst[0],mp->eth_dst[1],mp->eth_dst[2],mp->eth_dst[3],mp->eth_dst[4],mp->eth_dst[5], 
			    mp->eth_type, (mp->use_dot1Q) ? " after 802.1Q tag" : "");
	       }
	     else
	       {
		  cli_print(cli, "  Ethernet: %02x-%02x-%02x-%02x-%02x-%02x => %02x-%02x-%02x-%02x-%02x-%02x  [%04x%s]\r",
			    mp->eth_src[0],mp->eth_src[1],mp->eth_src[2],mp->eth_src[3],mp->eth_src[4],mp->eth_src[5],
			    mp->eth_dst[0],mp->eth_dst[1],mp->eth_dst[2],mp->eth_dst[3],mp->eth_dst[4],mp->eth_dst[5], 
			    mp->eth_type, (mp->use_dot1Q) ? " after 802.1Q tag" : "");
	       }
		  
		  if (mp->use_IP) {
			  if (mp->auto_delivery_off)
				  cli_print(cli, "  NOTE: Auto-delivery is OFF (that is, the destination MAC is fixed)\r");
			  else 
				  cli_print(cli, "  Auto-delivery is ON (that is, the actual MAC is determined upon transmission)\r");
		  }
	     i++;
	  }
	if (mp->use_SNAP)
	  {
	     bs2str(clipkt->eth_snap, line, clipkt->eth_snap_s);
	     cli_print(cli, "  LLC/SNAP: %s\r", line);
	     i++;
	  }
	if (mp->use_dot1Q)
	  {
	     k = clipkt->dot1Q_s/4; // number of tags
	     sprintf(line, "%i tag(s); ", k);
	     for (j=0; j<k; j++)
	       {  // tag format = 0x81 0x00 cosTvvvv vvvvvvvv
		  //                           x0       x1
		  x0 = (unsigned char*) &clipkt->dot1Q[(j*4)+2];
		  x1 = (unsigned char*) &clipkt->dot1Q[(j*4)+3];
		  v =  (*x0 & 0x0f)*256 + *x1;  // VLAN
//		  c = *x0 & 0xe0; // CoS   e0=11100000
		  c = *x0 >> 5;
		  sprintf(ds, "%i:%i%s",
			  v,
			  (unsigned char) c,
			  (*x0 & 0x10) ? "[CFI]" : ""); // CFI
		  strncat(line, ds, 14);
		  if (j<(k-1)) strcat(line, ", ");
	       }
	     
	     cli_print(cli, "  802.1Q: %s (VLAN:CoS)\r", line);
	     i++;
	  }
	if (mp->use_MPLS)
	  {
	     k = clipkt->mpls_s/4; // number of tags
	     sprintf(line, "%i tag(s); ", k);
	     for (j=0; j<k; j++)
	       {  // tag format = llllllll llllllll llllcccB TTTTTTTT
		  x0 = (unsigned char*) &clipkt->mpls[(j*4)+0];
		  x1 = (unsigned char*) &clipkt->mpls[(j*4)+1];
		  x2 = (unsigned char*) &clipkt->mpls[(j*4)+2];
		  x3 = (unsigned char*) &clipkt->mpls[(j*4)+3];
		  t = *x0; 
		  t <<= 12;
		  t += *x1 * 16;
		  t +=  (*x2 & 0xf0) >> 4;
		  c = (*x2 & 0x0e) >> 1;
		  T = *x3;
		  sprintf(ds, "%i:%i:%i%s",
			  t,
			  (unsigned char) c,
			  (unsigned char) T,
			  (*x2 & 0x01) ? "[BoS]" : ""); // Bottom of Stack?
		  strncat(line, ds, 20); 
		  if (j<(k-1)) strcat(line, ", ");
	       }
	     
	     cli_print(cli, "  MPLS: %s (Label:CoS:TTL)\r", line);

	     i++;
	  }
	if (mp->use_IP)
	  {
	     // Source IP settings:
	     x0 = (unsigned char*) & clipkt->ip_src;
	     line2[0]=0x00;
	     if (clipkt->ip_src_isrange) 
	       {
		  x1 = (unsigned char*) & clipkt->ip_src_start;
		  x2 = (unsigned char*) & clipkt->ip_src_stop;
		  sprintf(line2, "%u.%u.%u.%u-%u.%u.%u.%u",
			  (unsigned char) *(x1+3), (unsigned char) *(x1+2), (unsigned char) *(x1+1) , (unsigned char) *x1,
			  (unsigned char) *(x2+3), (unsigned char) *(x2+2), (unsigned char) *(x2+1) , (unsigned char) *x2);
	       }
	     sprintf(line, "SA=%u.%u.%u.%u %s %s %s",
		     (unsigned char) *(x0+3), (unsigned char) *(x0+2), (unsigned char) *(x0+1) , (unsigned char) *x0,
		     (clipkt->ip_src_israndom) ? "RANDOM" : "(not random)",
		     (clipkt->ip_src_isrange) ? "RANGE:" : "(no range)",
		     line2);
				
	     cli_print(cli, "  IP:  %s\r", line);
	     //Destination IP settings:
	     x0 = (unsigned char*) & clipkt->ip_dst;
	     line2[0]=0x00;
	     if (clipkt->ip_dst_isrange) 
	       {
		  x1 = (unsigned char*) & clipkt->ip_dst_start;
		  x2 = (unsigned char*) & clipkt->ip_dst_stop;
		  sprintf(line2, "%u.%u.%u.%u-%u.%u.%u.%u",
			  (unsigned char) *(x1+3), (unsigned char) *(x1+2), (unsigned char) *(x1+1) , (unsigned char) *x1,
			  (unsigned char) *(x2+3), (unsigned char) *(x2+2), (unsigned char) *(x2+1) , (unsigned char) *x2);
	       }
	     
	     sprintf(line, "DA=%u.%u.%u.%u %s %s",
		     (unsigned char) *(x0+3), (unsigned char) *(x0+2), (unsigned char) *(x0+1) , (unsigned char) *x0,
		     (clipkt->ip_dst_isrange) ? "RANGE:" : "(no range)",
		     line2);
	     cli_print(cli, "       %s\r", line);
	     
	     sprintf(line, "ToS=0x%02x  proto=%u  TTL=%u  ID=%u  offset=%u  flags: %s|%s|%s",
		     clipkt->ip_tos, clipkt->ip_proto, clipkt->ip_ttl, clipkt->ip_id, clipkt->ip_frag_offset,
		     (clipkt->ip_flags_RS) ? "RS" : "-",
		     (clipkt->ip_flags_DF) ? "DF" : "-",
		     (clipkt->ip_flags_MF) ? "MF" : "-");
	     
	     cli_print(cli, "       %s\r", line);
	     
		  if (clipkt->ip_fragsize) {
			  sprintf(line, "NOTE: Auto-fragmentation is ON! Fragment size %u bytes, overlap %u",
				  clipkt->ip_fragsize,
				  clipkt->ip_frag_overlap);
			  cli_print(cli, "       %s\r", line);
		  }
		  
	     sprintf(line, "len=%u(%s)  checksum=0x%02x%02x(%s)",
		     clipkt->frame[clipkt->begin_IP+2]*256+clipkt->frame[clipkt->begin_IP+3],
		     (clipkt->ip_len_false) ? "false" : "correct",
		     clipkt->frame[clipkt->begin_IP+10],
		     clipkt->frame[clipkt->begin_IP+11],
		     (clipkt->ip_sum_false) ? "false" : "correct");
		     
	     cli_print(cli, "       %s\r", line);
	     
	     i++;
	  }
	if (mp->use_UDP)
	  { 
	     if (clipkt->sp_isrange)
			  sprintf(line2, "RANGE: %u-%u", clipkt->sp_start, clipkt->sp_stop);
	     else
			  sprintf(line2, "(norange)");
	     if (clipkt->dp_isrange)
			  sprintf(line3, "RANGE: %u-%u", clipkt->dp_start, clipkt->dp_stop);
	     else
			  sprintf(line3, "(norange)");
	     sprintf(line, "SP=%i %s %s, DP=%i %s %s\r",
		     clipkt->sp, 
		     line2,
		     (clipkt->sp_isrand) ? "RANDOM" : "(not random)",
		     clipkt->dp, 
		     line3,
		     (clipkt->dp_isrand) ? "RANDOM" : "(not random)");
	     cli_print(cli, "  UDP: %s\r", line);
	     sprintf(line, "checksum= %04x (%s), length= %u (%s)",
		     clipkt->udp_sum, (clipkt->udp_sum_false) ? "false" : "correct",
		     clipkt->udp_len, (clipkt->udp_len_false) ? "false" : "correct");
             cli_print(cli, "       %s\r", line);
	     i++;
	  }
	if (mp->use_TCP)
	  {
	     sprintf(line, "%u bytes segment size (including TCP header)", mp->tcp_len);
	     cli_print(cli, "  TCP: %s\r", line);
	     if (clipkt->sp_isrange)
		 sprintf(line2, "RANGE: %u-%u", clipkt->sp_start, clipkt->sp_stop);
	     else
	         sprintf(line2, "(norange)");
	     if (clipkt->dp_isrange)
	         sprintf(line3, "RANGE: %u-%u", clipkt->dp_start, clipkt->dp_stop);
	     else
	         sprintf(line3, "(norange)");
	     sprintf(line, "SP=%i %s %s, DP=%i %s %s\r",
		     clipkt->sp, 
		     line2,
		     (clipkt->sp_isrand) ? "RANDOM" : "(not random)",
		     clipkt->dp, 
		     line3,
		     (clipkt->dp_isrand) ? "RANDOM" : "(not random)");
             cli_print(cli, "       %s\r", line);
             sprintf(line, "SQNR=%u (start %u, stop %u, delta %u) -- ACKNR=%u %s",
		     clipkt->tcp_seq,
		     clipkt->tcp_seq_start,
		     clipkt->tcp_seq_stop,
		     clipkt->tcp_seq_delta,
		     clipkt->tcp_ack,
		     (clipkt->tcp_ctrl_ACK) ? "(valid)" : "(invalid)");
	     cli_print(cli, "       %s\r", line);
             mops_tcp_flags2str(clipkt,line2);
             sprintf(line, "Flags: %s, reserved field is %02x, urgent pointer= %u",
		     line2, 
		     clipkt->tcp_res,
		     clipkt->tcp_urg);
             cli_print(cli, "       %s\r", line);
	     sprintf(line, "Announced window size= %u", clipkt->tcp_win);
             cli_print(cli, "       %s\r", line);
	     sprintf(line, "Offset= %u (times 32 bit; value is %s), checksum= %04x (%s)",
	     clipkt->tcp_offset,
	     (clipkt->tcp_offset_false) ? "FALSE" : "valid",
	     clipkt->tcp_sum,
	     (clipkt->tcp_sum_false) ? "FALSE" : "valid");
             cli_print(cli, "       %s\r", line);
	     sprintf(line, "%s - %u bytes defined",
		     (clipkt->tcp_option_used) ? "TCP options attached" : "(No TCP options attached)",
		     clipkt->tcp_option_s);
             cli_print(cli, "       %s\r", line);
	     i++;
	  }
	
	if (!i) cli_print(cli, "  No headers defined.\r");
	
         if (mp->msg_s) {
	     cli_print(cli, " Payload size: %i bytes\r", mp->msg_s);
	  }
	
	cli_print(cli, " Frame size: %i bytes\n", mp->frame_s);

	mops_print_frame(mp, myframe);
	cli_print(cli, "%s\n", myframe);
     }
   
   return CLI_OK;
}


////////////////////////////////////////////////////////////////////////////////
int show_interfaces (struct cli_def *cli, char *command, char *argv[], int argc)
{ 
	int i, j=0;
	char line[100];
	char ip[20];
	
	
	if (strncmp(argv[argc-1], "?", 2)==0) {
		cli_print(cli, "<CR>           Show summary list of all interfaces found\r");
		cli_print(cli, "detailed       Additionally show network, mask, default gatway, and MTU\r");
		cli_print(cli, "\n");
		return CLI_OK;
	}

	// Some safety checks
	if (argc>1) return CLI_OK;
	if (argc==1) {
		if (mz_strcmp(argv[0], "detailed", 1)!=0) {
			cli_print(cli, "invalid keyword (use ?)\n");
			return CLI_OK;
		}
	}
	
	/* Refresh interface data */

	lookupdev();
	
	for (i=0; i<device_list_entries; i++) {
		get_dev_params(device_list[i].dev);
	}

	
	
	/* No additional keyword */
	if (argc==0) {
		cli_print(cli, "Available network interfaces:\n");
		cli_print(cli, "                real             real                  used (fake)      used (fake)\r");
		cli_print(cli, "  device        IPv4 address     MAC address           IPv4 address     MAC address\r");
		cli_print(cli, "---------------------------------------------------------------------------------------\r");
		for (i=0; i<device_list_entries; i++) {
			sprintf(ip,"%u.%u.%u.%u", 
				device_list[i].ip_mops[0],
				device_list[i].ip_mops[1],
				device_list[i].ip_mops[2],
				device_list[i].ip_mops[3]);
			
			sprintf(line, "%-10s  %-15s  %02x:%02x:%02x:%02x:%02x:%02x     %-15s  %02x:%02x:%02x:%02x:%02x:%02x",
				device_list[i].dev, device_list[i].ip_str,
				device_list[i].mac[0],
				device_list[i].mac[1],
				device_list[i].mac[2],
				device_list[i].mac[3],
				device_list[i].mac[4],
				device_list[i].mac[5],
				ip,
				device_list[i].mac_mops[0],
				device_list[i].mac_mops[1],
				device_list[i].mac_mops[2],
				device_list[i].mac_mops[3],
				device_list[i].mac_mops[4],
				device_list[i].mac_mops[5]
				);
			
			
			if (strncmp(device_list[i].dev, tx.device, 16)==0) {
				cli_print(cli, "%s%s> %s\r",
					  (device_list[i].cli) ? "C" : " ",
					  (device_list[i].mgmt_only) ? "!" : "", 
					  line);
				j=i;
			}
			else
				cli_print(cli, "%s%s %s\r",
					  (device_list[i].cli) ? "C" : " ",
					  (device_list[i].mgmt_only) ? "M" : "",
					  line);
		}
	} 
	/////////////////////////
	else
   
	/* keyword detailed used */
	if (mz_strcmp(argv[0], "detailed", 1)==0) {
		cli_print(cli, "Detailed interface list:\n");
		for (i=0; i<device_list_entries; i++) {
			sprintf(line, "interface %s [%i] %s%stype %s, MTU=%i bytes", // general HW info
				device_list[i].dev, 
				device_list[i].index, 
				(device_list[i].cli) ? "[cli] " : "", 
				(device_list[i].mgmt_only) ? "[management-only] " : "", 
				(device_list[i].phy) ? "physical" : "software",
				device_list[i].mtu);
			cli_print(cli,"%s\r",line);
			sprintf(line, "MAC bia:  %02x:%02x:%02x:%02x:%02x:%02x\n   MAC fake: %02x:%02x:%02x:%02x:%02x:%02x",
				device_list[i].mac[0],
				device_list[i].mac[1],
				device_list[i].mac[2],
				device_list[i].mac[3],
				device_list[i].mac[4],
				device_list[i].mac[5],
				device_list[i].mac_mops[0],
				device_list[i].mac_mops[1],
				device_list[i].mac_mops[2],
				device_list[i].mac_mops[3],
				device_list[i].mac_mops[4],
				device_list[i].mac_mops[5]);
			cli_print(cli,"   %s\r",line);
			sprintf(line,"IP addr: %s  mask %u.%u.%u.%u  (net %u.%u.%u.%u)",
				device_list[i].ip_str, 
				device_list[i].mask[0],
				device_list[i].mask[1],
				device_list[i].mask[2],
				device_list[i].mask[3],
				device_list[i].net[0],
				device_list[i].net[1],
				device_list[i].net[2],
				device_list[i].net[3]);
			cli_print(cli,"   %s\r",line);
			sprintf(line,"IP fake: %u.%u.%u.%u",
				device_list[i].ip_mops[0],
				device_list[i].ip_mops[1],
				device_list[i].ip_mops[2],
				device_list[i].ip_mops[3]);
			cli_print(cli, "   %s\r", line);
			sprintf(line,"GW addr: %u.%u.%u.%u (%02x:%02x:%02x:%02x:%02x:%02x)",
				device_list[i].ip_gw[0],
				device_list[i].ip_gw[1],
				device_list[i].ip_gw[2],
				device_list[i].ip_gw[3],
				device_list[i].mac_gw[0],
				device_list[i].mac_gw[1],
				device_list[i].mac_gw[2],
				device_list[i].mac_gw[3],
				device_list[i].mac_gw[4],
				device_list[i].mac_gw[5]);
			cli_print(cli,"   %s\n",line);
		}
	}
	
	/* In any case, print final summary line: */
	cli_print(cli, "\n%i interfaces found.\nDefault interface is %s.\n",
		  device_list_entries, device_list[j].dev);
	
   return CLI_OK;
}



////////////////////////////////////////////////////////////////////////////////
int show_set(struct cli_def *cli, char *command, char *argv[], int argc)
{
   unsigned char *x;
   char hexload[3*MAX_PAYLOAD_SIZE];
   
   cli_print(cli, "----- Packet parameters: ------   -------- Value: ----------\r");
   cli_print(cli, "Source MAC address (sa)        %02x:%02x:%02x:%02x:%02x:%02x [%s]\r", 
	     tx.eth_src[0], tx.eth_src[1], tx.eth_src[2],
	     tx.eth_src[3], tx.eth_src[4], tx.eth_src[5],
	     (tx.eth_src_rand) ? "rand" : "spec");
   cli_print(cli, "Basic MAC address              %02x:%02x:%02x:%02x:%02x:%02x\r",
	     tx.eth_mac_own[0], tx.eth_mac_own[1], tx.eth_mac_own[2],
	     tx.eth_mac_own[3], tx.eth_mac_own[4], tx.eth_mac_own[5]);
   cli_print(cli, "Destination MAC address (da)   %02x:%02x:%02x:%02x:%02x:%02x [%s]\r",
	     tx.eth_dst[0], tx.eth_dst[1], tx.eth_dst[2],
	     tx.eth_dst[3], tx.eth_dst[4], tx.eth_dst[5],
	     (tx.eth_dst_rand) ? "rand" : "spec");
   cli_print(cli, "\r");
   x = (unsigned char *) &tx.ip_src;
   cli_print(cli, "Source IP address (SA)         %i.%i.%i.%i [%s]\r",
	     *x,*(x+1),*(x+2),*(x+3),
	     (tx.ip_src_rand) ? "rand" : "spec");

   if (tx.ip_src_isrange)
     {
	x = (unsigned char *) &tx.ip_src_start;
	cli_print(cli, "Source IP range start:         %i.%i.%i.%i\r",
		  *(x+3), *(x+2), *(x+1), *x);
	x = (unsigned char *) &tx.ip_src_stop;
	cli_print(cli, "Source IP range stop:          %i.%i.%i.%i\r",
		  *(x+3), *(x+2), *(x+1), *x);
     }
   else
     {
	cli_print(cli, "No source IP range specified\r");
     }
   x = (unsigned char *) &tx.ip_dst;
   cli_print(cli, "Destination IP address (DA)    %i.%i.%i.%i\r",
	     *x,*(x+1),*(x+2),*(x+3));
   
   if (tx.ip_dst_isrange)
     {
	x = (unsigned char *) &tx.ip_dst_start;
	cli_print(cli, "Destination IP range start:    %i.%i.%i.%i\r",
		  *(x+3), *(x+2), *(x+1), *x);
	x = (unsigned char *) &tx.ip_dst_stop;
	cli_print(cli, "Destination IP range stop:     %i.%i.%i.%i\r",
		  *(x+3), *(x+2), *(x+1), *x);
     }
   else
     {
	cli_print(cli, "No destination IP range specified\r");
     }
   
   if (tx.dot1Q)
     {
	cli_print(cli, "802.1Q tags specified:         %s\r", tx.dot1Q_txt);
     }
   
   if (tx.mpls)
     {
	cli_print(cli, "MPLS labels specified:         %s\r", tx.mpls_txt);
     }
   
   if (tx.ascii)
     {  cli_print(cli, "\r");
	cli_print(cli, "---- ASCII payload is set: ----- \r");
	cli_print(cli, ">>>%s<<<\r", tx.ascii_payload);
	cli_print(cli, "-------------------------------- \n");
     }
   
   if (tx.hex_payload_s)
     {  cli_print(cli, "\r");
	cli_print(cli, "---- Hexadecimal payload is set: ----- \r");
	bs2str(tx.hex_payload, hexload, tx.hex_payload_s);
	cli_print(cli, "%s\r", hexload);
	cli_print(cli, "-------------------------------------- \n");
     }
   
   if (tx.padding)
     {
	cli_print(cli, "Configured padding:            %u\r", tx.padding);
     }
   
   cli_print(cli, "\r");
   cli_print(cli, "Packet count value             %u\r", tx.count);
   cli_print(cli, "Interpacket delay (usec)       %u\r", tx.delay);
   cli_print(cli, "\r");
   cli_print(cli, "Used network device(s):        %s\r", tx.device);
   cli_print(cli, "\n");
    return CLI_OK;
}







////////////////////////////////////////////////////////////////////////////////
int stop_mausezahn (struct cli_def *cli, char *command, char *argv[], int argc)
{
	if (strncmp(argv[argc-1], "?", 2)==0) {
		cli_print(cli, "now    Terminate the mausezahn server! BEWARE!\n");
		return CLI_OK;
	}
	
	if (argc!=1) {
		cli_print(cli, "The only allowed argument is 'now' -- anything else is ignored\n");
		return CLI_OK;
	}
	
	if (mz_strcmp(argv[0], "now", 3)==0) {
		cli_print(cli, "Good bye...\n");
		cli_done(cli);
		clean_up(0);
		return CLI_OK;
	} else {
		cli_print(cli, "Invalid argument. If you want to stop the Mausezahn server then\r");
		cli_print(cli, "enter 'terminate now'. You cannot abbreviate the argument 'now'. \n");
	}
	
	return CLI_OK;
}




int cmd_run_id (struct cli_def *cli, char *command, char *argv[], int argc)
{
	int i, slot;
	struct mops *mp;

	if (argc == 0) {
		cli_print(cli, "Specify one or more packet identifiers to run.\n");
		return CLI_OK;
	}
   
	if ( strncmp(argv[argc-1], "?", 1) == 0) {
		cli_print(cli, "Run packet transmission processes for given list of packet identifiers\n");
		return CLI_OK;
	}
	
	// User provided packet id numbers 
	if (argc > 0) {
		for (i=0; i<argc; i++) {
			slot = (int) str2int(argv[i]);
			if ( (mp = mops_search_id (mp_head, slot)) == NULL) { // not found
				cli_print (cli, "Packet %i not in list.\n", slot );
				return CLI_OK;
			}
			else {
				switch (mops_tx_simple (mp)) {
				 case 1:
					cli_print(cli, "Cannot create sending process.\r");
					return CLI_OK;
					break;
				 case 3:
					cli_print(cli, "Packet [%i] has already an active sending process\r", mp->id);
					return CLI_OK;
					break;
				 default:
					cli_print (cli, "Activate [%i] ", slot );
					break;
				}
			}
		}
		cli_print (cli, "\n");
	}
	return CLI_OK;
}


int cmd_run_name (struct cli_def *cli, char *command, char *argv[], int argc)
{
	int i;
	struct mops *mp;
   
	if (argc == 0) {
		cli_print(cli, "Specify one or more packet name(s)  to run.\n");
		return CLI_OK;
	}
   
	if ( strncmp(argv[argc-1], "?", 1) == 0) {
		cli_print(cli, "Run packet transmission processes for specified packet name(s).\n");
		return CLI_OK;
	}

	if (argc > 0) {
		for (i=0; i<argc; i++) {
			if ( (mp = mops_search_name (mp_head, argv[i])) == NULL) { // not found
				cli_print (cli, "Packet %s not in list.\n", argv[i]);
				return CLI_OK;
			}
			else {
				switch (mops_tx_simple (mp)) {
				 case 1:
					cli_print(cli, "Cannot create sending process.\r");
					return CLI_OK;
					break;
				 case 3:
					cli_print(cli, "Packet [%i] has already an active sending process\r", mp->id);
					return CLI_OK;
					break;
				 default:
					cli_print (cli, "Activate [%i] ", mp->id );
					break;
				}
			}
		}
		cli_print (cli, "\n");
	}
	return CLI_OK;
}


int cmd_run_sequence (struct cli_def *cli, char *command, char *argv[], int argc)
{
	struct mz_ll *cur;
	int ret=0;
	if (argc != 1) {
		cli_print(cli, "Specify one (and only one) packet sequence name to run.\n");
		return CLI_OK;
	}
   
	if ( strncmp(argv[argc-1], "?", 1) == 0) {
		cli_print(cli, "Run sequence transmission processes for specified sequence name.\n");
		return CLI_OK;
	}
	
	cur = mz_ll_search_name (packet_sequences, argv[0]);
	if (cur==NULL) { // NOT FOUND !!!
		cli_print(cli, "Sequence %s does not exist.", argv[0]);
		return CLI_OK;
	}
	ret = mops_tx_sequence(cur);
	switch (ret) {
	 case 0: cli_print(cli, "Sequence %s is runnning\n", cur->name);
		break;
	 case 1: cli_print(cli, "Cannot run sequence: All packets must be in config state!\n");
		break;
	 case 2: cli_print(cli, "Cannot run sequence: All packets must have a finite count!\n");
		break;
	 case 3: cli_print(cli, "Cannot run sequence: Unable to start sequence transmission process.\n");
		break;
	}
	return CLI_OK;
}



int cmd_run_all (struct cli_def *cli, char *command, char *argv[], int argc)
{
	int i;
	struct mops *mp;
	struct mops *head;
   
	if ( strncmp(argv[argc-1], "?", 1) == 0) {
		cli_print(cli, "Run all user-specified packets.\n");
		return CLI_OK;
	}
	
	if (argc>0) {
		cli_print(cli, "No arguments expected!\n");
		return CLI_OK;
	}
	
	// Send all valid packets
	i=0;
	head = mp_head;
	mp = mp_head;
	do {  
		if ((mp->mz_system==0) && (mops_state(mp) == MOPS_STATE_CONFIG)) {
			switch (mops_tx_simple (mp)) {
			 case 1:
				cli_print(cli, "Cannot create sending process.\r");
					return CLI_OK;
				break;
			 case 3:
				cli_print(cli, "Packet [%i] has already an active sending process\r", mp->id);
				return CLI_OK;
				break;
			 default:
				break;
			}
			i++;
			cli_print (cli, "Activate [%i] %s\r", mp->id, mp->packet_name );
		}
		mp = mp->next;
	}
	while (head != mp);
	if (i==0) {
		cli_print (cli, "No valid packets found\n");
	} else {
		cli_print (cli, "\r");
		cli_print (cli, "Activated %i packets \n", i);
	}
	return CLI_OK;
}



int cmd_stop (struct cli_def *cli, char *command, char *argv[], int argc)
{
	struct mops *mp;
	int i, ret=0, slot=0;
	
	struct mops *head = mp_head;
	struct mops *cur = mp_head;
     
	if ((strncmp(argv[argc-1], "?", 2)==0) || (argc==0)) {
		cli_print(cli, "Stop transmission process(es) or an active sequence.\r");
		cli_print(cli, "SYNTAX:  1) Either specify one or more packet-ids or packet names of active packets\r");
		cli_print(cli, "         2) Or enter 'sequence <seq-name>' to stop an active sequence and its associated packets.\n");
		return CLI_OK;
	}
	
	// Did the user specify a sequence? (ONE SEQUENCE ONLY)
	if ((mz_strcmp(argv[0], "sequence", 3)==0) && (argc==2)) {
		ret = stop_sequence (argv[1]);
		switch (ret) {
		 case 0:
			cli_print(cli, "Sequence '%s' stopped.\n", argv[1]);
			break;

		 case 1: 
			cli_print(cli, "Sequence '%s' does not exist!\n", argv[1]);
			break;
		 case 2:
			cli_print(cli, "Sequence '%s' is not active. Nothing to stop.\n", argv[1]);
			break;
		}
		return CLI_OK;
	}

	
	if (((mz_strcmp(argv[0], "all", 3)==0) || (mz_strcmp(argv[0], "*", 1)==0)) && (argc==1)) {
		i=0;
		cli_print(cli, "Stopping ");
		do {
			if (mops_destroy_thread (cur)==0)  {
				i++;
				cli_print(cli, "[%i] %s", cur->id, cur->packet_name);
			}
			cur = cur->next;
		}
		while (head != cur);
		cli_print(cli, "\n");
		if (i) {
			cli_print(cli, "Stopped %i transmission processe(s)\r", i);
		}
		else {
			cli_print(cli, "No active transmission processes found.\r");
		}
		
		i = stop_all_sequences ();
		if (i) {
			cli_print(cli, "Stopped %i sequence(s)\n", i);
		}
		else {
			cli_print(cli, "No active sequences found.\n");
		}
		
		return CLI_OK;
	}

	// Stop all specified packets:
	// 
	for (i=0; i<argc; i++) {
		mp = NULL;
		// is argv[i] a numerical pkt-id?
		if (mz_strisnum(argv[i])) {
			slot = (int) str2int(argv[i]);
			mp = mops_search_id (mp_head, slot);
		}
		// still not found? Is it a name?
		if (mp==NULL) mp = mops_search_name (mp_head, argv[i]);
		if (mp==NULL) cli_print(cli, "Packet '%s' not in list!\r",argv[i]);
		else { // packet found:
			if (mops_destroy_thread (mp)) {
				cli_print(cli, "Packet [%i] '%s' has no associated transmission process (nothing to stop).\r", mp->id, mp->packet_name);
			} else 
				cli_print (cli, "Stopped transission process for packet [%i] '%s'.\r", mp->id, mp->packet_name);
		}
	}
	
	cli_print(cli, "\r");
	return CLI_OK;
}



int show_mops(struct cli_def *cli, char *command, char *argv[], int argc)
{
	char tmp[120];
   
	if (strncmp(argv[argc-1], "?", 2)==0) {
		cli_print(cli, "<ENTER>    Check MOPS version and details\n");
		return CLI_OK;
	}
   
	cli_print(cli, "-----------------------------------------------------\r");
	cli_print(cli, "Mops version %s [%s]\n", MOPS_VERSION, MOPS_CODENAME);
	cli_print(cli, "Maximum packet sequence length is          %i packets\r", MAX_PACKET_SEQUENCE_LEN);
	cli_print(cli, "Maximum frame size is                      %i bytes\r", MAX_MOPS_FRAME_SIZE);
	cli_print(cli, "Minimum frame size is                      %i bytes\r", MIN_MOPS_FRAME_SIZE);
	cli_print(cli, "PCAP readout delay is                      %i msec\r", PCAP_READ_TIMEOUT_MSEC);
	cli_print(cli, "Maximum payload size is                    %i bytes\r", MAX_MOPS_MSG_SIZE);
	cli_print(cli, "Maximum chunk size is                      %i bytes\r", MAX_MOPS_MSG_CHUNK_SIZE);
	cli_print(cli, "Maximum counters per packet is             %i\r", MAX_MOPS_COUNTERS_PER_PACKET);
	cli_print(cli, "Maximum number of 802.1Q tags is           %i\r", MAX_MOPS_DOT1Q_TAGS);
	cli_print(cli, "Maximum number of MPLS tags is             %i\r", MAX_MOPS_MPLS_TAGS);
	cli_print(cli, "Maximum length of packet names is          %i characters\r", MAX_MOPS_PACKET_NAME_LEN);
	cli_print(cli, "Maximum length of packet descriptions is   %i characters\r", MAX_MOPS_DESCRIPTION_LEN);
	cli_print(cli, "Bytes per line for formatted frame output  %i\r", MAX_CLI_LINE_BYTES);
	cli_print(cli, "Maximum LLDP optional section length is    %i bytes\r", MAX_LLDP_OPT_TLVS);
	if (AUTOMOPS_ENABLED) {
		cli_print(cli, "Auto-MOPS subsystem is enabled\r");
		cli_print(cli, "  Maximum nesting depth is %i\r", XN_MAX_STACK);
		cli_print(cli, "  Maximum file size for protocol definitions is %i\r", AUTOMOPS_MAX_FILE_SIZE);
		cli_print(cli, "  Maximum names length is %i\r", AUTOMOPS_MAX_NAME_LEN);
		cli_print(cli, "  Maximum short description length is %i\r", AUTOMOPS_MAX_SHORTDESC_LEN);
		cli_print(cli, "  Maximum XML tag length is %i\r", XML_MAX_TAG_LEN);
	} else	cli_print(cli, "Auto-MOPS subsystem is disabled\r");
	
	if (mops_dump_all(mp_head, tmp)) {
		cli_print(cli, "No mopses found.\n"); // keine Möpse gefunden ;-)
	} else {
		cli_print(cli, "%s\n", tmp);
	}
   
	return CLI_OK;
}




int cmd_reset_interface (struct cli_def *cli, char *command, char *argv[], int argc)
{
	int i;
	
	if (strncmp(argv[argc-1], "?", 2)==0) {
		cli_print(cli, "<ENTER>    Check MOPS version and details\n");
		return CLI_OK;
	}
	
	if (argc>0) {
		cli_print(cli, "Unknown parameter\n");
		return CLI_OK;
	}
	
	lookupdev();

	for (i=0; i<device_list_entries; i++) {
		get_dev_params(device_list[i].dev);
		// refresh ARP table i. e. MAC addresses of default GWs
		service_arp(device_list[i].dev, device_list[i].ip_gw, device_list[i].mac_gw);  
	}

   return CLI_OK;
}




int conf_frame_limit (struct cli_def *cli, char *command, char *argv[], int argc)
{
   unsigned int tmp;
   
   if (strncmp(argv[argc-1], "?", 2)==0)
     {
	cli_print(cli, "Configure global frame size limits:\n");
	cli_print(cli, "  <min-frame-size> [max-frame-size]\n");
	return CLI_OK;
     }
   
   if (argc>2) 
     {
	cli_print(cli, "Two arguments allowed: <min-frame-size> [max-frame-size]\n");
	return CLI_OK;
     }
   
   tmp = (unsigned int) str2int (argv[0]);
   if (tmp < MIN_MOPS_FRAME_SIZE)
     {
	cli_print(cli, "This Mausezahn requires that the minimum frame size is at least %i bytes\n", MIN_MOPS_FRAME_SIZE);
	return CLI_OK;
     }
   
   if (tmp>(max_frame_s-2))
     {
	cli_print(cli, "The minimum frame size must be below %i bytes\n", max_frame_s-1);
	return CLI_OK;
     }
   
   min_frame_s = tmp;
   
   if (argc==2)
     {
	tmp = (unsigned int) str2int (argv[1]);

	if (tmp > MAX_MOPS_FRAME_SIZE-MOPS_SIZE_MARGIN)
	  {
	     cli_print(cli, "This Mausezahn requires that the maximum frame size is not greater than %i bytes\n",
		       MAX_MOPS_FRAME_SIZE-MOPS_SIZE_MARGIN);
	     return CLI_OK;
	  }
	
	if (tmp<(min_frame_s+2))
	  {
	     cli_print(cli, "The maximum frame size must be greater than %i bytes\n", min_frame_s+1);
	     return CLI_OK;
	  }
	
	max_frame_s = tmp;
     }
   
   return CLI_OK;
}




int cmd_load (struct cli_def *cli, char *command, char *argv[], int argc)
{
	int i;
	FILE *fp;

	if ( (strcmp(argv[argc-1],"?")==0) || (argc!=1) ) {
		cli_print(cli, "Load commands from one or more specified file(s)\r");
		cli_print(cli, "\n");
		return CLI_OK;
	}

	if (!argc){
		cli_print(cli, "Specify one or more configuration files\n");
		return CLI_OK;
	}
	
	for (i=0; i<argc; i++) {
		fp = fopen(argv[i], "r");
		if (fp==NULL) {
			cli_print(cli, "Warning: Cannot read %s\n", argv[i]);
			continue;
		}
		cli_print(cli, "Read commands from %s...\n", argv[i]);
		cli_file (cli, fp, PRIVILEGE_PRIVILEGED, MODE_EXEC);
		if (fclose(fp) == EOF)
		{
			cli_print(cli, "Warning: problems closing %s (errno=%i)\n", argv[i],errno);
		}
	}
   
   return CLI_OK;
}


int show_arp (struct cli_def *cli, char *command, char *argv[], int argc)
{
	int i;
	struct arp_table_struct *cur;
	char s[128], ip[20], uc[16], bc[16], ch[16];
	struct mz_timestamp now, prev, result;

	
	
	if  (strcmp(argv[argc-1],"?")==0) {
		cli_print(cli, "<CR>        shows the advanced Mausezahn ARP table\n");
		return CLI_OK;
	}

	if (argc>0) {
		cli_print(cli, "Unknown parameter\n");
		return CLI_OK;
	}
	
	
	cli_print(cli, "Intf    Index     IP address     MAC address       last       Ch  UCast BCast Info\r");
	cli_print(cli, "----------------------------------------------------------------------------------\r");
// ------------------------------------------------------------------------------
// wlan0 [1] DL  192.168.0.1  at 00:09:5b:9a:15:84  3'42''  1   

	for (i=0; i<device_list_entries; i++) {
		cur=device_list[i].arp_table;
		while(cur!=NULL) {
			sprintf(ip,"%i.%i.%i.%i",cur->sip[0],cur->sip[1],cur->sip[2],cur->sip[3]);
			if (cur->changed>99999) mz_strncpy(ch,"ALERT",6); else sprintf(ch,"%lu", cur->changed);
			if (cur->uni_resp>99999) mz_strncpy(uc,"ALERT",6); else sprintf(uc,"%lu", cur->uni_resp);
			if (cur->bc_resp>99999) mz_strncpy(bc,"ALERT",6); else sprintf(bc,"%lu", cur->bc_resp);
			sprintf(s, "%-7s [%i] %s%s %15s  %02x:%02x:%02x:%02x:%02x:%02x  %8s %5s %5s %5s  %04x",
				device_list[i].dev,
				cur->index,
				(cur->dynamic) ? "D" : "U",
				(cur->locked) ? "L" : "",
				ip,
				cur->smac[0],
				cur->smac[1],
				cur->smac[2],
				cur->smac[3],
				cur->smac[4],
				cur->smac[5],
				cur->when,
				ch,
				uc,
				bc,
				cur->flags);
			cli_print(cli, "%s\r", s);
			if (cur->changed>1) {
				now.sec = cur->sec;
				now.nsec = cur->nsec;
				prev.sec = cur->sec_prev;
				prev.nsec= cur->nsec_prev;
				printf("sec=%u nsec=%u sec=%u nsec=%u\n", cur->sec, cur->nsec, cur->sec_prev, cur->nsec_prev);
				timestamp_subtract(&now, &prev, &result);
				sprintf(s,"  previous MAC was: %02x:%02x:%02x:%02x:%02x:%02x   time delta: %u sec %u msec",
					cur->smac_prev[0],
					cur->smac_prev[1],
					cur->smac_prev[2],
					cur->smac_prev[3],
					cur->smac_prev[4],
					cur->smac_prev[5],
					(unsigned int) result.sec, (unsigned int) result.nsec/1000000);
				cli_print(cli, "           %s\r", s);
			}
			cur=cur->next;
		}

	}
	return CLI_OK;
}


// general 'end' command to return to global config mode
int cmd_end_to_config(struct cli_def *cli, char *command, char *argv[], int argc)
{
   cli_set_configmode(cli, MODE_CONFIG, NULL);
   return CLI_OK;
}

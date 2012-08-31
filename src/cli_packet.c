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


int debug_packet (struct cli_def *cli, char *command, char *argv[], int argc)
{
   cli_debug = CLI_DEBUG_PACKET;
   cli_print (cli, "Packet debugging enabled\n");
   return CLI_OK;
}




// Enter packet config mode:
// 
//   1) either with an optional packet slot number => modify existing slot
//   2) or without number to allocate a new slot entry
//   
int enter_packet (struct cli_def *cli, char *command, char *argv[], int argc)
{
	char prompt[16];
   
	if (argc==0) { // Allocate new packet
		if ((clipkt = mops_alloc_packet(mp_head)) == NULL) { // Problem, memory full?
			cli_print(cli, "Holy flying spaghetti monster! Cannot allocate additional memory!\n");
			return CLI_OK;
		}
		// OK, created a new packet
		snprintf(prompt, 16, "pkt-%i",clipkt->id);
		cli_print(cli, "Allocated new packet %s at slot %i",clipkt->packet_name, clipkt->id);
		// mops_set_defaults(clipkt);   //// implicitly done by mops_alloc_packet
	} else if ( (strcmp(argv[argc-1],"?")==0) || (argc>1) ) {
		cli_print(cli, "<CR>         create a new packet slot\r");
		cli_print(cli, "NAME         enter packet slot of packet with name NAME\r");
		cli_print(cli, "ID           enter packet slot of packet with number ID\n");
		return CLI_OK;
	} else { // user specified a unique packet_name
		if ( (clipkt = mops_search_name (mp_head, argv[0]))==NULL) { // packet name does not exist
			if ( (clipkt = mops_search_id (mp_head, (int) str2int(argv[0])))==NULL) { // packet id does not exist
				cli_print(cli, "Packet does not exist\n");
				return CLI_OK;
			}
		}
		if (mops_is_any_active(clipkt)) {  // don't allow to configure packets which are active!
			cli_print(cli, "The selected packet is currently in active state!\r");
			cli_print(cli, "In order to configure this packet, please stop the associated packet process first.\n");
			return CLI_OK;
		}
		snprintf(prompt, 16, "pkt-%i",clipkt->id);
		cli_print(cli, "Modify packet parameters for packet %s [%i]",clipkt->packet_name, clipkt->id);
	}
	cli_set_configmode(cli, MZ_MODE_PACKET, prompt);
	//cli_print(cli, "Packet configuration mode - called %s with %s\r\n", __FUNCTION__, command);
	return CLI_OK;
}







// Specify the type and enter the appropriate configuration mode
// NOTE that we also reset and create the p_desc here!
int cmd_packet_type(struct cli_def *cli, char *command, char *argv[], int argc)
{
	char prompt[16];
	int ret=0;
	char wrn[] = "Error: Could not create mops extension handle\n";
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc!=1) ) 
	{
		cli_print(cli, "Specify a packet type from the following list:\r\n");
		cli_print(cli, " arp\r");
		cli_print(cli, " bpdu\r");
//		cli_print(cli, " cdp       (not supported in this version)\r");
//		cli_print(cli, " icmp      (not supported in this version)\r");
		cli_print(cli, " igmp\r");
		cli_print(cli, " ip\r");
		cli_print(cli, " lldp\r");
		cli_print(cli, " rtp\r");
//		cli_print(cli, " syslog    (not supported in this version)\r");
		cli_print(cli, " tcp\r");
		cli_print(cli, " udp\r");
		return CLI_OK;
	}
	
	if (mz_strcmp(argv[0],"arp",3) == 0)
	{
		if (mops_ext_add_pdesc (clipkt, MOPS_ARP))
			cli_print(cli, "%s", wrn);
		else
		{
			ret=mops_clear_layers(clipkt,
					      MOPS_SNAP|MOPS_MPLS|MOPS_IP|MOPS_UDP|MOPS_TCP);
			clipkt->use_ETHER = 1;
			clipkt->eth_type = 0x806;
			sprintf(prompt, "pkt-%i-arp",clipkt->id);
			cli_set_configmode(cli, MZ_MODE_PACKET_ARP, prompt);
			mops_update_arp(clipkt);
			mops_set_conf(clipkt);
		}
		
	}
	else if (mz_strcmp(argv[0],"dns",3) == 0)
	{
		if (mops_ext_add_pdesc (clipkt, MOPS_DNS))
			cli_print(cli, "%s", wrn);
		else
		{
			ret=mops_clear_layers(clipkt, MOPS_SNAP|MOPS_TCP);
			clipkt->use_ETHER = 1;
			clipkt->use_IP= 1;
			clipkt->use_UDP= 1;
			sprintf(prompt, "pkt-%i-dns",clipkt->id);
			cli_set_configmode(cli, MZ_MODE_PACKET_DNS, prompt);
			mops_set_conf(clipkt);
		}
	}
	else if (mz_strcmp(argv[0],"icmp",3) == 0)
	{
		if (mops_ext_add_pdesc (clipkt, MOPS_ICMP))
			cli_print(cli, "%s", wrn);
		else
		{
			ret=mops_clear_layers(clipkt, MOPS_SNAP|MOPS_TCP|MOPS_UDP);
			clipkt->use_ETHER = 1;
			clipkt->use_IP= 1;
			sprintf(prompt, "pkt-%i-icmp",clipkt->id);
			cli_set_configmode(cli, MZ_MODE_PACKET_ICMP, prompt);
			mops_set_conf(clipkt);
		}
	}
	else if (mz_strcmp(argv[0],"igmp",3) == 0)
	{
		if (mops_ext_add_pdesc (clipkt, MOPS_IGMP))
			cli_print(cli, "%s", wrn);
		else
		{
			ret=mops_clear_layers(clipkt, MOPS_SNAP|MOPS_TCP|MOPS_UDP);
			clipkt->use_ETHER = 1;
			clipkt->use_IP= 1;
			clipkt->ip_proto = 2;
			mops_ip_option_ra(clipkt, 0); // add router alert option to IP header
			sprintf(prompt, "pkt-%i-igmp",clipkt->id);
			cli_set_configmode(cli, MZ_MODE_PACKET_IGMP, prompt);
			mops_update_igmp(clipkt);
			mops_set_conf(clipkt);
		}
	}

	else if (mz_strcmp(argv[0],"cdp",3) == 0)
	{
		if (mops_ext_add_pdesc (clipkt, MOPS_CDP))
			cli_print(cli, "%s", wrn);
		else
		{
			ret=mops_clear_layers(clipkt, MOPS_ALL);
			clipkt->use_ETHER = 1;
			sprintf(prompt, "pkt-%i-cdp",clipkt->id);
			cli_set_configmode(cli, MZ_MODE_PACKET_CDP, prompt);
			mops_set_conf(clipkt);
		}
	}
	else if (mz_strcmp(argv[0],"bpdu",3) == 0)
	{
		if (mops_ext_add_pdesc (clipkt, MOPS_BPDU))
			cli_print(cli, "%s", wrn);
		else
		{
			ret=mops_clear_layers(clipkt, MOPS_MPLS|MOPS_IP|MOPS_UDP|MOPS_TCP);
			clipkt->use_ETHER = 1;
			clipkt->use_SNAP  = 1;
			sprintf(prompt, "pkt-%i-bpdu",clipkt->id);
			cli_set_configmode(cli, MZ_MODE_PACKET_BPDU, prompt);
			mops_update_bpdu(clipkt);
			mops_set_conf(clipkt);
		}
	}
	else if (mz_strcmp(argv[0],"ip",2) == 0)
	{
		ret=mops_clear_layers(clipkt, MOPS_TCP|MOPS_UDP);
		clipkt->use_ETHER = 1;
		clipkt->use_IP = 1;
		sprintf(prompt, "pkt-%i-ip",clipkt->id);
		cli_set_configmode(cli, MZ_MODE_PACKET_IP, prompt);
		mops_set_conf(clipkt);
	}
	else if (mz_strcmp(argv[0],"udp",3) == 0)
	{	
		ret=mops_clear_layers(clipkt, MOPS_SNAP|MOPS_TCP);
		clipkt->use_ETHER = 1;
		clipkt->use_IP = 1;
		clipkt->use_UDP = 1;
		clipkt->ip_proto = 17;
		sprintf(prompt, "pkt-%i-udp",clipkt->id);
		cli_set_configmode(cli, MZ_MODE_PACKET_UDP, prompt);
		mops_set_conf(clipkt);
	}
	else if (mz_strcmp(argv[0],"tcp",3) == 0)
	{
		ret=mops_clear_layers(clipkt, MOPS_SNAP|MOPS_UDP);
		clipkt->use_ETHER = 1;
		clipkt->use_IP = 1;
		clipkt->use_TCP = 1;
		clipkt->ip_proto = 6;
		sprintf(prompt, "pkt-%i-tcp",clipkt->id);
		cli_set_configmode(cli, MZ_MODE_PACKET_TCP, prompt);
		mops_set_conf(clipkt);
	}
	else if (mz_strcmp(argv[0],"syslog",3) == 0)
	{	
		if (mops_ext_add_pdesc (clipkt, MOPS_SYSLOG))
			cli_print(cli, "%s", wrn);
		else
		{	
			ret=mops_clear_layers(clipkt, MOPS_SNAP|MOPS_TCP);
			clipkt->use_ETHER = 1;
			clipkt->use_IP = 1;
			clipkt->use_UDP = 1;
			sprintf(prompt, "pkt-%i-syslog",clipkt->id);
			cli_set_configmode(cli, MZ_MODE_PACKET_SYSLOG, prompt);
			mops_set_conf(clipkt);
		}
	}
	else if (mz_strcmp(argv[0],"lldp",3) == 0)
	{
		if (mops_ext_add_pdesc (clipkt, MOPS_LLDP))
			cli_print(cli, "%s", wrn);
		else
		{
			ret=mops_clear_layers(clipkt, MOPS_SNAP|MOPS_IP|MOPS_UDP|MOPS_TCP);
			clipkt->use_ETHER = 1;
			sprintf(prompt, "pkt-%i-lldp",clipkt->id);
			cli_set_configmode(cli, MZ_MODE_PACKET_LLDP, prompt);
			mops_set_conf(clipkt);
		}
	}
	else if (mz_strcmp(argv[0],"rtp",3) == 0)
	{
		if (mops_ext_add_pdesc (clipkt, MOPS_RTP))
			cli_print(cli, "%s", wrn);
		else
		{
			ret=mops_clear_layers(clipkt, MOPS_SNAP|MOPS_TCP);
			clipkt->use_ETHER = 1;
			clipkt->use_IP = 1;
			clipkt->use_UDP = 1;
			sprintf(prompt, "pkt-%i-rtp",clipkt->id);
			cli_set_configmode(cli, MZ_MODE_PACKET_RTP, prompt);
			mops_set_conf(clipkt);
		}
	}
   
	else // wrong user input
	{
		cli_print(cli, "Unknown type\n");
		return CLI_OK;
	}

   if (ret) {
	   cli_print(cli, "Note that the following layer(2) have configured information:\r");
	   if (ret & 1) cli_print(cli, "  - Ethernet or 802.3\r");
	   if (ret & 2) cli_print(cli, "  - SNAP\r");
	   if (ret & 4) cli_print(cli, "  - 802.1Q\r");
	   if (ret & 8) cli_print(cli, "  - MPLS\r");
	   if (ret & 16) cli_print(cli, "  - IP\r");
	   if (ret & 32) cli_print(cli, "  - UDP\r");
	   if (ret & 64) cli_print(cli, "  - TCP\r");
   }

	mops_update(clipkt);
   return CLI_OK;
}





int cmd_packet_end(struct cli_def *cli, char *command, char *argv[], int argc)
{
   cli_set_configmode(cli, MODE_CONFIG, NULL);
   return CLI_OK;
}





int cmd_packet_clone (struct cli_def *cli, char *command, char *argv[], int argc)
{
   // TODO
   return CLI_OK;
}


// Reserved words: "all", "slot" 
int cmd_packet_name (struct cli_def *cli, char *command, char *argv[], int argc)
{
   if (strncmp(argv[0], "?", 2) == 0)
     {
	cli_print(cli, "Assign a packet name (max 16 chars)\n");
	return CLI_OK;
     }

   if (argc>1)
     {
	cli_print(cli, "Packet name must not contain spaces\n");
	return CLI_OK;
     }
   
   if (strlen(argv[0])>MAX_MOPS_PACKET_NAME_LEN)
       {
	  cli_print(cli, "Packet name is limited to %i chars. You might use the 'description' command.\n",MAX_MOPS_PACKET_NAME_LEN);
	  return CLI_OK;
       }
       
   if (mz_strcmp(argv[0], "all", 3)==0)
       {
	  cli_print(cli, "This is a reserved word. Please choose another\n");
	  return CLI_OK;
       }
       
   strncpy(clipkt->packet_name, argv[0], MAX_MOPS_PACKET_NAME_LEN);
   clipkt->packet_name[MAX_MOPS_PACKET_NAME_LEN-1] = 0x00; 
// cli_print(cli, "Changed packet name to '%s'\n", clipkt->packet_name);
   
   return CLI_OK;
}

int cmd_packet_description (struct cli_def *cli, char *command, char *argv[], int argc)
{
   if (strncmp(argv[argc-1], "?", 2) == 0)
     {
	cli_print(cli, "Assign a packet description (max %i chars)\n", MAX_MOPS_DESCRIPTION_LEN);
	return CLI_OK;
     }  
   
   if (mops_pdesc_mstrings (clipkt->description, argv, argc, MAX_MOPS_DESCRIPTION_LEN))
     {
	cli_print(cli, "String too long. Currently the description is limited to %i characters.\n",
		  MAX_MOPS_DESCRIPTION_LEN);
	cli_print(cli, "Current description is:\n%s\n", clipkt->description);
     }
   
   return CLI_OK;
}

int cmd_packet_count (struct cli_def *cli, char *command, char *argv[], int argc)
{

   if (strncmp(argv[argc-1], "?", 2) == 0)   
     {
	cli_print(cli,"Specify the packet count. Zero means infinity.\n");
	return CLI_OK;
     }
   else if (argc)
     {
	clipkt->count = (unsigned long) str2int(argv[0]);
	if (clipkt->count) 
	  { 
	     clipkt->cntx = clipkt->count; // count is finite: cntx will count down
	  }
	else
	  {
	     clipkt->cntx = 0;  // infinity: cntx will count up
	  }
	return CLI_OK;
     }
   cli_print(cli,"Specify a packet count.\n");
   return CLI_OK;
}


int cmd_packet_delay (struct cli_def *cli, char *command, char *argv[], int argc)
{
	int ret=0;
	char str[100];
		
	if (strncmp(argv[argc-1], "?", 2) == 0) {
		cli_print(cli, "delay <value> [hour | min | sec | msec | usec | nsec]\n");
		cli_print(cli, "Specify the inter-packet delay in hours, minutes, seconds, milliseconds, microseconds,\r");
		cli_print(cli, "or nanoseconds. The default unit is milliseconds (i. e. when no unit is given).\n");
		return CLI_OK;
	}
	
	switch (argc) {
	 case 1:  // only one argument, but may contain an unit (such as '314sec')
		ret = delay_parse(&clipkt->ndelay, argv[0], NULL);
		break;
		
	 case 2: // user specified two arguments such as '100 msec'
		ret = delay_parse(&clipkt->ndelay, argv[0], argv[1]);
		break;
	 default:
		cli_print(cli, "Too many arguments! Expected delay value and unit, such as '10 msec'\n");
		return CLI_OK;
	}
	
	switch (ret) {
	 case 1:
		cli_print(cli, "Invalid unit! Use one of {nsec, usec, msec, sec, min, hours}\n");
		return CLI_OK;
		break;
	 case 2:
		cli_print(cli, "Value too large! Supported range is from 0 to 999999999\n");
		return CLI_OK;
		break;
	}
	sprintf(str, "Inter-packet delay set to %lu sec and %lu nsec", clipkt->ndelay.tv_sec, clipkt->ndelay.tv_nsec);
	cli_print(cli, "%s\n", str);
	
	return CLI_OK;
}



int cmd_packet_bind (struct cli_def *cli, char *command, char *argv[], int argc)
{
   int i;
   
   if (strncmp(argv[argc-1], "?", 2) == 0)   
     {
	cli_print(cli,"<DEVICE>    Change the packet's network interface\r");
	cli_print(cli,"default     Use interface settings as packet default\n");
	return CLI_OK;
     }
   else if (argc)
     {
	if (mz_strcmp(argv[0], "default", 3)==0)
	  {
	     i = mops_get_device_index(clipkt->device);
	     // Copy device_list[i].ip_mops and .mac_mops to clipkt->ip_src and ->eth_src
	     memcpy((void *) &clipkt->eth_src, (void *) &device_list[i].mac_mops[0], 6);
	     memcpy((void *) &clipkt->ip_src, (void *) &device_list[i].ip_mops[0], 4);
	  }
	else
	  {
	     i = mops_get_device_index(argv[0]);
	     
	     if (i != -1)
	       {
		  strncpy(clipkt->device, argv[0], 16); // assign device to this mops
		  mops_use_device(clipkt, i);
	       }
	     else
	       cli_print(cli, "Unknown device, will stick on %s\n", clipkt->device);
	  }
     }
   else
     cli_print(cli, "Nothing specified, will stick on %s\n", clipkt->device);
   
   return CLI_OK;
}







// FORMAT: <VLAN>:<CoS> such as: "100:3  17:5 ..."
// NOTE: LEFTMOST TAG = OUTER TAG IN FRAME
// CFI is set/unset separately (see ? below)
// Transmission format: 0x8100 plus CoS (3) CFI(1) VLAN(12)
int cmd_packet_dot1q (struct cli_def *cli, char *command, char *argv[], int argc)
{
   int i, j, k=0;
   int n;
   char Vlan[64], CoS[64];
   u_int16_t v,c;
   
   if (strcmp(argv[argc-1],"?")==0) 
     {
	cli_print(cli, "Configure 802.1Q tags:\n");
	cli_print(cli, "  VLAN[:CoS] [VLAN[:CoS]] ...   The leftmost tag is the outer tag in the frame\r");
	cli_print(cli, "  remove <tag-nr> | all         Remove one or more tags (<tag-nr> starts with 1),\r");
	cli_print(cli, "                                by default the first (=leftmost,outer) tag is removed,\r");
	cli_print(cli, "                                keyword 'all' can be used instead of tag numbers.\r");	
	cli_print(cli, "  cfi | nocfi [<tag-nr>]        Set or unset the CFI-bit in any tag (by default\r");
	cli_print(cli, "                                assuming the first tag).\n");
	return CLI_OK;
     }

   if (argc==0)
     {
	cli_print(cli, "Specify one or more VLAN-IDs, optionally with CoS values\n");
	return CLI_OK;
     }

   n = clipkt->dot1Q_s/4; // n = number of tags

//////////////////////////////////////////
   if (mz_strcmp(argv[0], "remove", 2)==0)
     {
	
	if (argc>2)
	  {
	     cli_print(cli, "Too many arguments!\n");
	     return CLI_OK;
	  }

	if (n==0) 
	  {
	     cli_print(cli, "No 802.1Q tags present. None to be removed.\n");
	     return CLI_OK;
	  }
	
	if ((argc==2) && (mz_strcmp(argv[1], "all", 1)==0))
	  {
	     mops_dot1Q_remove(clipkt, 0);
	     return CLI_OK;
	  }
	
	if (argc==1) // no tag-nr specified => assume first tag
	  {
	     j=1;
	  }
	else
	  {
	     j = (unsigned int) str2int(argv[1]); // take first argument
	     if (j==0) 
	       {
		  cli_print(cli, "The tag-nr must be within {1..%i}\n", n);
		  return CLI_OK;
	       }
	  }
	
	// now remove tag
	if (mops_dot1Q_remove(clipkt, j))
	  {
	     cli_print(cli, "The packet only consists of %i tag(s)!\n", n);
	  }
	return CLI_OK;
     }
   
     
/////////////////////////////////////////
   if (mz_strcmp(argv[0], "nocfi", 2)==0)
     {
	if (n==0)
	  {
	     cli_print(cli, "There are no 802.1Q tags yet!\n");
	     return CLI_OK;
	  }
	
	if (argc>2)
	  {
	     cli_print(cli, "Invalid format!\n");
	     return CLI_OK;
	  }
	
	if (argc==1) // no tag-nr specified => assume first tag
	  {
	     j=1;
	  }
	else
	  {
	     j = (unsigned int) str2int(argv[1]);
	  }
	
	if (mops_dot1Q_nocfi(clipkt, j))
	  {
	     cli_print(cli, "The packet only consists of %i tags!\n",k);
	  }
	return CLI_OK;
     }
   
///////////////////////////////////////   
   if (mz_strcmp(argv[0], "cfi", 2)==0)
     {
	if (n==0)
	  {
	     cli_print(cli, "There are no 802.1Q tags yet!\n");
	     return CLI_OK;
	  }
	
	if (argc>2)
	  {
	     cli_print(cli, "Invalid format!\n");
	     return CLI_OK;
	  }
	
	if (argc==1) // no tag-nr specified => assume first tag
	  {
	     j=1;
	  }
	else
	  {
	     j = (unsigned int) str2int(argv[1]);
	  }
	
	if (mops_dot1Q_cfi(clipkt, j))
	  {
	     cli_print(cli, "The packet only consists of %i tags!\n",k);
	  }
	return CLI_OK;
     }
   

/////////////////////////
   for (i=0; i<argc; i++) // scan through all user tokens
     {
	v=0;c=0; k=0;
	
	if (mz_tok(argv[i],":",2, Vlan, CoS) == -1)
	  {
	     cli_print(cli, "Invalid format. Correct format: VLAN[:CoS] [VLAN[:CoS] ...]\n");
	     return CLI_OK;
	  }
	
	if (Vlan[0]==0x00)
	  {
	     cli_print(cli, "[tag %i] Missing VLAN number\n", i+1);
	     return CLI_OK;
	  }
	else
	  {
	     v = (u_int16_t) str2int(Vlan);
	     if (v>4095) 
	       {
		  cli_print(cli, "[tag %i] VLAN number must not exceed 4095.\n", i+1);
		  return CLI_OK;
	       }
	  }
	
	if (CoS[0]==0x00)
	  {
	     c=0;
	  }
	else
	  {
	     c = (u_int16_t) str2int(CoS);
	     if (c>7)
	       {
		  cli_print(cli, "[tag %i] CoS must not exceed 7.\n", i+1);
		  return CLI_OK;
	       }
	  }
	
	mops_dot1Q (clipkt, i, 1, v, c);  // 3rd param '1' means 'new stack, also set dot1Q_s'
     }
   return CLI_OK;
}


// MPLS transmission format: Label(20) EXP(3) BoS(1) TTL(8)
//    -- where BoS=0 indicate MORE labels, BoS=1 means last (bottom) label
//    
// NOTE: The EtherType must be 0x8847 which identifies 'IP over MPLS' that is 
//       we do NOT need to set 0x800 for IP somewhere! Instead, mops_update() 
//       will always correctly set the single EtherType, if necessary after
//       802.1Q tags. For example when VLAN tags are present, the frame looks
//       like this:----------------------------------vvvv-----------------------
//       DMAC-SMAC-8100VLAN1-...-8100VLANn-EtherType(8847)-MPLS1-...-MPLSn-IP...
// 
//       MPLS Multicast packets are indicated by EtherType 8848 (!)
//       See also RFC 5332 which allows both 'Codepoints' to carry MPLS multicast
//       while 0x8848 only indicates multiaccess media.
//        
// NOTE: If all MPLS labels are removed again, the original EtherType is restored again!
//       The original EtherType is stored in mp->eth_type_backup
int cmd_packet_mpls (struct cli_def *cli, char *command, char *argv[], int argc)
{
   int a=0,i,j=0,k;
   char LabelS[64], ExpS[64], TTLS[64];
   u_int32_t Label;
   u_int8_t Exp;
   u_int8_t TTL;

   
   if ( (strcmp(argv[argc-1],"?")==0) || (argc==0) )
     {
	cli_print(cli, "Configure one or more MPLS labels:\r");
	cli_print(cli, "  LABEL[:EXP[:TTL]] [LABEL[:EXP[:TTL]]] ... The leftmost tag is the outer tag in frame\r");
	cli_print(cli, "  remove <tag-nr> | all         Remove tag with number <tag-nr> (starts with 1) or all.\r");
	cli_print(cli, "  bos | nobos [<tag-nr>]        Set/unset BoS flag, by default in last (rightmost) label\r");
	cli_print(cli, "  unicast|multicast             Choose EtherType 0x8847 or 0x8848 respectively\n");
	cli_print(cli, "Examples:\r");
	cli_print(cli, "  tag mpls 100 200 300          Specify three tags, 100,200,300 \r");
	cli_print(cli, "  tag mpls 100:5 200:5:1        Let first tag have CoS 5, second tag additionally uses TTL=1\r");
	cli_print(cli, "  tag mpls 100::8               Let first tag have TTL=8\n");
	cli_print(cli, "Reserved label numbers:\r");
	cli_print(cli, "  0 ... explicit NULL (IPv4)\r");
	cli_print(cli, "  1 ... Router Alert\r");
	cli_print(cli, "  2 ... explicit NULL (IPv6)\r");
	cli_print(cli, "  3 ... implicit NULL (only announced within LDP)\r");
	cli_print(cli, " 14 ... OAM Alert (ITU-T Y.1711, RFC 3429)\n");
	return CLI_OK;
     }

///////////////////////////////////////////
   if (mz_strcmp(argv[0], "unicast", 2)==0)
     {  
	if (clipkt->use_MPLS==0)
	  {
	     cli_print(cli, "First configure an MPLS label stack.");
	     return CLI_OK;
	  }
	
	if (argc>1)
	  {
	     cli_print(cli, "This command does not support any argument.\n");
	  }
	
	clipkt->eth_type = 0x8847;
	return CLI_OK;
     }
   
/////////////////////////////////////////////
   if (mz_strcmp(argv[0], "multicast", 2)==0)
     {  
	if (clipkt->use_MPLS==0)
	  {
	     cli_print(cli, "First configure an MPLS label stack.");
	     return CLI_OK;
	  }
	
	if (argc>1)
	  {
	     cli_print(cli, "This command does not support any argument.\n");
	  }
	
	clipkt->eth_type = 0x8848;
	return CLI_OK;
     }
   
   k = clipkt->mpls_s/4; // number of available tags
   
//////////////////////////////////////////
   if (mz_strcmp(argv[0], "remove", 2)==0)
     {
	if (argc>2)
	  {
	     cli_print(cli, "Too many arguments!\n");
	     return CLI_OK;
	  }

	if ((argc==2) && (mz_strcmp(argv[1], "all", 1)==0))
	  {
	     if (mops_mpls_remove(clipkt, 0))
		  cli_print(cli, "No MPLS label stack present. Nothing removed\n");
	     return CLI_OK;
	  }

	if (argc==1) // no tag-nr specified => assume first tag
	  {
	     if (k==0) 
	       cli_print(cli, "Currently the packet has no tag that can be removed.\n");
	     else
	       j=1;
	  }
	else
	  {
	     j = (unsigned int) str2int(argv[1]); // take first argument
	  }
	if (mops_mpls_remove(clipkt, j))
	  cli_print(cli, "The tag number must be within 1..%i\n",k);

	return CLI_OK;
     }

///////////////////////////////////////   
   if (mz_strcmp(argv[0], "bos", 2)==0)
     {
	if (argc>2)
	  {
	     cli_print(cli, "Too many arguments\n");
	     return CLI_OK;
	  }
	if (argc==2)
	  {
	     i = (int) str2int(argv[1]);
	     if (i>k)
	       {
		  cli_print(cli, "Tag number exceeds actual number of tags (%i)\n",a);
		  return CLI_OK;
	       }
	  }
	else // argc==1 (no tag number specified)
	  {
	     i = k; // default: last tag!
	  }

	mops_mpls_bos (clipkt, i);
	return CLI_OK;
     }
   
   if (mz_strcmp(argv[0], "nobos", 2)==0)
     {
	if (argc>2)
	  {
	     cli_print(cli, "Too many arguments\n");
	     return CLI_OK;
	  }
	if (argc==2)
	  {
	     i = (int) str2int(argv[1]);
	     if (i>k)
	       {
		  cli_print(cli, "Tag number exceeds actual number of tags (%i)\n",k);
		  return CLI_OK;
	       }
	  }
	else // argc==1 (no tag number specified)
	  {
	     i = k; // default: last tag!
	  }
	mops_mpls_nobos (clipkt, i);
	return CLI_OK;
     }
   
   
////////////////////////////////////////////
   for (i=0;i<argc;i++)    // Get all labels 
     {
	if (mz_tok(argv[i], ":", 3, LabelS, ExpS, TTLS) < 0)
	  {
	     cli_print(cli, "[Tag %i]Incorrect label specification! Use format LABEL[:EXP[:TTL]]\n", i+1);
	     return CLI_OK;
	  }
	
	// Get Label
	if (LabelS[0]==0x00) 
	  {
	     cli_print(cli, "[Tag %i] Invalid label value!\n", i+1);
	     return CLI_OK;
	  }
	else
	  {
	     Label = (u_int32_t) str2int (LabelS);
	     if (Label > 1048575) 
	       {
		  cli_print(cli, "[Tag %i] Label value cannot exceed 1048575\n", i+1);
		  return CLI_OK;
	       }
	  }
	// Get EXP
	if (ExpS[0]==0x00) 
	  {
	     Exp=0;
	  }
	else
	  {
	     Exp = (u_int8_t) str2int(ExpS);
	     if (Exp>7) 
	       {
		  cli_print(cli, "[Tag %i] EXP value must be within range 0..7\n", i+1);
		  return CLI_OK;
	       }
	  }
	
	// Get TTL
	if (TTLS[0]==0x00)
	  {
	     TTL=255;
	  }
	else
	  {
	     if (str2int(TTLS)>255)
	       {
		  cli_print(cli, "[Tag%i] TTL value must be within range 0..255\n", i+1);
		  return CLI_OK;
	       }
	     TTL = (u_int8_t) str2int(TTLS);
	  }
	
	// Now add MPLS tag:
	mops_mpls(clipkt, i, argc, Label, Exp, TTL);
     }
   
   return CLI_OK;
}


// SYNTAX:
// 
//   payload hex ff:00:01:02:aa:bb:cc:dd aa:bb:cc
//   payload hex file tmp/dump.dat
//   
int cmd_packet_payload_hex (struct cli_def *cli, char *command, char *argv[], int argc)
{
   char str[MAX_MOPS_MSG_SIZE*3];
   int len, i;
   
   if (strncmp(argv[argc-1], "?", 2)==0)
     {
	cli_print(cli, "Specify a payload in hexadecimal format:\n");
	cli_print(cli, "   XX:XX:XX:...       Either directly as sequence of digits, separated by colon or space\r");
	cli_print(cli, "   file <filename>    Or specify a filename with hexadecimal digits as content\r");
	cli_print(cli, "                      (Also in the file the separator can be either a colon or a space)\n");
	cli_print(cli, "Example: \r");
	cli_print(cli, "payload hex ff:ff:ff:ff:ff:ff 00:12:34:56:67:89 08:00 ca:fe:ba:be\n");
	return CLI_OK;
     }

   if (argc==0) 
     {
	cli_print(cli, "Specify an ascii payload\n");
	return CLI_OK;
     }

   
   if (mz_strcmp(argv[0],"file", 2)==0)
     {
	// > > > > > ******* TODO: Open file and configure mops with filepointer ******** < < < < < < < <
	cli_print(cli, "This feature is currently not supported.\n");
	return CLI_OK;
     }
   
   // Get byte sequence - first copy into str
   if (mops_pdesc_mstrings (str, argv, argc, MAX_MOPS_MSG_SIZE*3))
     {
	cli_print(cli, "Payload too long (limited to %i bytes).\n", MAX_MOPS_MSG_SIZE);
     }
   else // str contains byte sequence now - convert into msg and set msg_s
     {
	len = strlen(str);
	for (i=0; i<len; i++)
	  {
	     if (str[i]=='?') 
	       {
		  cli_print(cli, "Specify hexadecimal digits {1234567890abcdef} or separators\n");
		  return CLI_OK;
	       }
	     
	     if ( (!isxdigit(str[i])) &&   // Only allow "1234567890abcdefABCDEF", ":", ".", "-", and SPACE.
		  (!isspace(str[i])) &&
		  (str[i]!=':') &&
		  (str[i]!='.') &&
		  (str[i]!='-'))
	       {
		  cli_print(cli, "Invalid character at position %i\n", i+1);
		  return CLI_OK;
	       }
	  }
	
	len = str2hex (str, clipkt->msg, MAX_MOPS_MSG_SIZE);
	if (len==-1)
	  {
	     cli_print(cli, "Invalid byte sequence. Each byte must be specified with two hexadecimal digits.\n");
	     return CLI_OK;
	  }
	
	clipkt->msg_s = (u_int32_t) len;
     }
   
   return CLI_OK;
}



int cmd_packet_payload_ascii (struct cli_def *cli, char *command, char *argv[], int argc)
{
   char str[MAX_MOPS_MSG_SIZE*3];
   int len, i;
   
   if (strncmp(argv[argc-1], "?", 2)==0)
     {
	cli_print(cli, "Specify a payload in ascii format.\r");
	cli_print(cli, "Note that multiple white spaces are replaced by a single white space. If you\r");
	cli_print(cli, "really want to specify multiple white spaces then use a dash '-' instead of\r");
	cli_print(cli, "a white space. If you want to specify a dash then use a caret '^' as escape\r");
	cli_print(cli, "character.\n");
	
	return CLI_OK;
     }

   if (argc==0) 
     {
	cli_print(cli, "Specify an ascii payload\n");
	return CLI_OK;
     }
   
   
   if (mz_strcmp(argv[0],"file", 2)==0)
     {
	// > > > > > ******* TODO: Open file and configure mops with filepointer ******** < < < < < < < <
	cli_print(cli, "This feature is currently not supported.\n");
	return CLI_OK;
     }

      // Get byte sequence - first copy into str
   if (mops_pdesc_mstrings (str, argv, argc, MAX_MOPS_MSG_SIZE))
     {
	cli_print(cli, "Payload too long (limited to %i bytes).\n", MAX_MOPS_MSG_SIZE);
     }
   else // str contains byte sequence now - convert into msg and set msg_s
     {
	len = strlen(str);
	for (i=0; i<len; i++) // Replace
	  {
	    if (str[i]=='-')
	       {
		  if ((i>0) && (str[i-1]=='^')) 
		    {
		       memcpy((void*) &str[i-1], (void*) &str[i], len-i+1); 
		       i--; len--;
		    }
		  else
		    {
		       str[i]=' ';
		    }
	       }
	  }
	len--; // to eliminate the trailing space (created by mops_pdesc_mstring)
	memcpy((void*) clipkt->msg, (void*) str, len);
	clipkt->msg_s = len;
     }
   return CLI_OK;
}


int cmd_packet_payload_raw (struct cli_def *cli, char *command, char *argv[], int argc)
{
   
   return CLI_OK;
}



int cmd_packet_interval (struct cli_def *cli, char *command, char *argv[], int argc)
{
	unsigned long long iv, tv_sec=0;
	
	if (strncmp(argv[argc-1], "?", 1)==0) {
		cli_print(cli, "Configure a greater packet interval in days, hours, minutes, or seconds\n");
		cli_print(cli, "Arguments: <value>  <days | hours | minutes | seconds>\n");
		cli_print(cli, "Use a zero value to disable an interval.\n");
		return CLI_OK;
	}

	if (argc!=2) {
		cli_print(cli,"Enter a value and an unit\n");
		return CLI_OK;
	}
	
	
	if (mz_strisnum(argv[0])==0) {
		cli_print(cli,"Invalid value\n");
		return CLI_OK;
	}
	
	iv = str2lint(argv[0]);
	
	if (iv==0) {
		cli_print(cli,"Interval disabled.\n");
		clipkt->interval_used = 0;
		return CLI_OK;
	}
	
	if (mz_strcmp(argv[1], "days", 1)==0) {
		if (iv>365) {
			cli_print(cli, "Supported range: 1..365 days\n");
			return CLI_OK;
		}
		tv_sec = 86400 * iv;
	}

	if (mz_strcmp(argv[1], "hours", 1)==0) {
		if (iv>1000) {
			cli_print(cli, "Supported range: 1..1000 hours\n");
			return CLI_OK;
		}
		tv_sec = 3600 * iv;
	}

	if (mz_strcmp(argv[1], "minutes", 1)==0) {
		if (iv>1000) {
			cli_print(cli, "Supported range: 1..1000 minutes\n");
			return CLI_OK;
		}
		tv_sec = 60 * iv;
	}

	if (mz_strcmp(argv[1], "seconds", 1)==0) {
		if (iv>999999) {
			cli_print(cli, "Supported range: 1..999999 seconds\n");
			return CLI_OK;
		}
		tv_sec = iv;
	}
	
	if (clipkt->count==0) {
		cli_print(cli, "Note: reconfigured count value from 0 (infinity) to 1.\n");
		clipkt->count=1;
	}
	
	if ((clipkt->count * clipkt->ndelay.tv_sec)>tv_sec) {
		cli_print(cli, "Error: intervals are smaller than packet trains.\r");
		cli_print(cli, "Reduce either count or delay, or both\n");
		return CLI_OK;
	}
	
	clipkt->interval.tv_sec = tv_sec;
	clipkt->interval_used = 1;
	
   return CLI_OK;
}


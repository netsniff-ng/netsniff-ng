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


// ------- TOC ---------
// 
// int     cmd_ip_address_source       (struct cli_def *cli, char *command, char *argv[], int argc)
// int     cmd_ip_address_destination  (struct cli_def *cli, char *command, char *argv[], int argc)
// int     cmd_ip_version              (struct cli_def *cli, char *command, char *argv[], int argc)
// int     cmd_ip_ttl                  (struct cli_def *cli, char *command, char *argv[], int argc)
// int     cmd_ip_protocol             (struct cli_def *cli, char *command, char *argv[], int argc)
// int     cmd_ip_hlen                 (struct cli_def *cli, char *command, char *argv[], int argc)
// int     cmd_ip_len                  (struct cli_def *cli, char *command, char *argv[], int argc)
// int     cmd_ip_id                   (struct cli_def *cli, char *command, char *argv[], int argc)
// int     cmd_ip_offset               (struct cli_def *cli, char *command, char *argv[], int argc)
// int     cmd_ip_sum                  (struct cli_def *cli, char *command, char *argv[], int argc)
// int     cmd_ip_tos                  (struct cli_def *cli, char *command, char *argv[], int argc)
// int     cmd_ip_dscp                 (struct cli_def *cli, char *command, char *argv[], int argc)
// int     cmd_ip_rsv                  (struct cli_def *cli, char *command, char *argv[], int argc)
// int     cmd_ip_df                   (struct cli_def *cli, char *command, char *argv[], int argc)
// int     cmd_ip_mf                   (struct cli_def *cli, char *command, char *argv[], int argc)
// int     cmd_ip_option               (struct cli_def *cli, char *command, char *argv[], int argc)



// ip-address source default|<IP>|rand|range
// 
//   default
//   random
//   A.B.C.D
//   A.B.C.D  /24
//   A.B.C.D  E.F.G.H
int cmd_ip_address_source (struct cli_def *cli, char *command, char *argv[], int argc)
{
   u_int8_t IP1[4], IP2[4];
   u_int32_t ip1, ip2;
   unsigned int prefix;
   u_int32_t mask, invmask;
   int i,r;

   if ( (strcmp(argv[argc-1],"?")==0) || (argc>2) )
     {
	cli_print(cli, "A.B.C.D     configure a source IP address\n");
	cli_print(cli, "Optionally you may specify\r");
	cli_print(cli, "- a range of addresses, such as: 192.168.0.0 /16\r");
	cli_print(cli, "                             or: 192.168.0.1 192.168.255.255\r");
	cli_print(cli, "- 'random' for a randomly generated source address\r");
	cli_print(cli, "- 'default' for the interface default settings\n");
	return CLI_OK;
     }
   
   switch (argc)
     {
      case 1:
	if (mz_strcmp(argv[0], "default", 3)==0)
	  {
	     // find index of device_list with the device configured in clipkt:
	     i=0;
	     while (strncmp(device_list[i].dev, clipkt->device, 10) && (i<device_list_entries)) i++;
	     clipkt->ip_src = device_list[i].ip_mops[3] 
	                    + device_list[i].ip_mops[2] * 256
	                    + device_list[i].ip_mops[1] * 256 * 256 
			    + device_list[i].ip_mops[0] * 256 * 256 * 256;
	     clipkt->ip_src_israndom = 0;
	     clipkt->ip_src_isrange = 0;
	  }
	else if (mz_strcmp(argv[0], "random", 3)==0)
	  {
	     clipkt->ip_src_israndom = 1;
	     clipkt->ip_src_isrange = 0;
	  }
	else if (mops_pdesc_ip (IP1, argv[0])==0) // check if format is really an IP address
	  { 
	     clipkt->ip_src =  str2ip32(argv[0]);
	     clipkt->ip_src_israndom = 0;
	     clipkt->ip_src_isrange = 0;
	  }
	else // wrong input
	  {
	     cli_print(cli,"Invalid address/keyword\n");
	  }
	break;
      case 2: // MUST be either like '10.1.1.0 /24' or '10.1.1.1 10.1.1.254'
	if (mops_pdesc_ip (IP1, argv[0])==0) // check if format is really an IP address
	  { 
	     clipkt->ip_src_start = str2ip32(argv[0]);
	     if (strlen(argv[1])<4) // probably prefix?
	       {
		  r=sscanf(argv[1],"/%u",&prefix);
		  if ((r==EOF) || (r==0) || (prefix<1) || (prefix>31))
		    cli_print(cli, "Invalid prefix!\n");
		  else
		    {
		       mask = 0xffffffff;
                       mask <<= (32-prefix);
		       invmask = 0xffffffff - mask; 
		       ip1 = ((str2ip32 (argv[0])) & mask) +1; // the '+1' is to ensure that we do not start with the net-id
		       ip2 = ip1 | invmask;        
		       clipkt->ip_src_start    = ip1;
		       clipkt->ip_src_stop     = ip2;
		       clipkt->ip_src_isrange  = 1;
		       clipkt->ip_src_israndom = 0;
		    }
	       }
	     else if (mops_pdesc_ip (IP2, argv[1])==0) // probably 2nd IP address?
	       {
		  if (str2ip32(argv[1]) > clipkt->ip_src_start)
		    {
		       clipkt->ip_src_stop = str2ip32(argv[1]);
		       clipkt->ip_src_isrange  = 1;
		       clipkt->ip_src_israndom = 0;
		    }
		  else
		    {
		       cli_print(cli, "Invalid range! The second IP address must be greater than the first!\n");
		    }
	       }
	     else 
	       {
		  cli_print(cli, "Second parameter must be either a valid IP address or a prefix length \n");
	       }
	  }
	else // first string is not a valid IP address
	  {
	     cli_print(cli, "First parameter must be a valid IP address\n");
	  }
	break;
      default:
	cli_print(cli, "Invalid format!\n");
     }
   
   return CLI_OK;
}



// ip-address destination <IP>|range
int cmd_ip_address_destination (struct cli_def *cli, char *command, char *argv[], int argc)
{
   u_int8_t IP1[4], IP2[4];
   u_int32_t ip1, ip2;
   unsigned int prefix;
   u_int32_t mask, invmask;
   int r;

   if ( (strcmp(argv[argc-1],"?")==0) || (argc>2) )
     {
	cli_print(cli, "A.B.C.D     configure a destination IP address\n");
	cli_print(cli, "Optionally specify a range of addresses, such as: 192.168.0.0 /16\r");
	cli_print(cli, "                                              or: 192.168.0.1 192.168.255.255\n");
	return CLI_OK;
     }
   
   switch (argc)
     {
      case 1:
	if (mops_pdesc_ip (IP1, argv[0])==0)  // check if format is really an IP address
	  { 
	     clipkt->ip_dst =  str2ip32(argv[0]);
	     clipkt->ip_dst_isrange = 0;
	  }
	else // wrong input
	  {
	     cli_print(cli,"Invalid address/range\n");
	  }
	break;
      case 2: // MUST be either like '10.1.1.0 /24' or '10.1.1.1 10.1.1.254'
	if (mops_pdesc_ip (IP1, argv[0])==0) // check if format is really an IP address
	  { 
	     clipkt->ip_dst_start = str2ip32(argv[0]);
	     if (strlen(argv[1])<4) // probably prefix?
	       {
		  r=sscanf(argv[1],"/%u",&prefix);
		  if ((r==EOF) || (r==0) || (prefix<1) || (prefix>31))
		    cli_print(cli, "Invalid prefix!\n");
		  else
		    {
                       mask = 0xffffffff;
		       mask <<= (32-prefix);
		       invmask = 0xffffffff - mask; 
		       ip1 = ((str2ip32 (argv[0])) & mask) +1; // the '+1' is to ensure that we do not start with the net-id
		       ip2 = ip1 | invmask;        
		       clipkt->ip_dst_start    = ip1;
		       clipkt->ip_dst_stop     = ip2;
		       clipkt->ip_dst_isrange  = 1;
		    }
	       }
	     else if (mops_pdesc_ip (IP2, argv[1])==0) // probably 2nd IP address?
	       {
		  if (str2ip32(argv[1]) > clipkt->ip_dst_start)
		    {
		       clipkt->ip_dst_stop = str2ip32(argv[1]);
		       clipkt->ip_dst_isrange  = 1;
		    }
		  else
		    {
		       cli_print(cli, "Range requirement: The second IP address must be greater than the first!\n");
		    }
	       }
	     else 
	       {
		  cli_print(cli, "Second parameter must be either a valid IP address or a prefix length \n");
	       }
	  }
	else // first string is not a valid IP address
	  {
	     cli_print(cli, "First parameter must be a valid IP address\n");
	  }
	break;
      default:
	cli_print(cli, "Invalid IP or range specification!\n");
     }
   
   return CLI_OK;   
}




int cmd_ip_version (struct cli_def *cli, char *command, char *argv[], int argc)
{
   int ver;
   
   if (strncmp(argv[argc-1], "?", 2)==0)
     {
	cli_print(cli, "Specify the IP version (default: 4).\n");
	return CLI_OK;
     }

   ver = (int) str2int(argv[0]);
   
   if (ver>15) 
     {
	cli_print(cli, "Version must be within range 0..15\n");
	return CLI_OK;
     }
   
   clipkt->ip_version = ver;
   
   return CLI_OK;
}



int cmd_ip_ttl (struct cli_def *cli, char *command, char *argv[], int argc)
{
   int ttl;
   
   if (strncmp(argv[argc-1], "?", 2)==0)
     {
	cli_print(cli, "Specify the TTL (default: 255).\n");
	
	return CLI_OK;
     }

   ttl = (int) str2int(argv[0]);
   
   if (ttl>255) 
     {
	cli_print(cli, "TTL must be within range 0..255\n");
	return CLI_OK;
     }
   
   clipkt->ip_ttl = ttl;

   
   return CLI_OK;
}



int cmd_ip_protocol (struct cli_def *cli, char *command, char *argv[], int argc)
{
   int proto;
   
   if (strncmp(argv[argc-1], "?", 2)==0)
     {
	cli_print(cli, "Specify the protocol number (default: 0).\n");
	
	return CLI_OK;
     }

   proto = (int) str2int(argv[0]);
   
   if (proto>255) 
     {
	cli_print(cli, "The protocol number must be within range 0..255\n");
	return CLI_OK;
     }
   
   clipkt->ip_proto = proto;
   
   return CLI_OK;
}





int cmd_ip_hlen (struct cli_def *cli, char *command, char *argv[], int argc)
{
   int ihl;
   
   if (strncmp(argv[argc-1], "?", 2)==0)
     {
	cli_print(cli, "Specify the header length in multiple of 4 bytes.\n");
	
	return CLI_OK;
     }
   
   ihl = (int) str2int(argv[0]);
   
   if (ihl>15) 
     {
	cli_print(cli, "The IHL must be within range 0..15\n");
	return CLI_OK;
     }
   
   clipkt->ip_IHL = ihl;
   
   return CLI_OK;
}





int cmd_ip_len (struct cli_def *cli, char *command, char *argv[], int argc)
{
   int len;
   
   if (strncmp(argv[argc-1], "?", 2)==0)
     {
	cli_print(cli, "Specify the total packet length (0..65535).\n");
	
	return CLI_OK;
     }

   len = (int) str2int(argv[0]);
   
   if (len>65535) 
     {
	cli_print(cli, "The packet length must be within range 0..65535\n");
	return CLI_OK;
     }
   
   clipkt->ip_len = len;

   return CLI_OK;
}





int cmd_ip_id (struct cli_def *cli, char *command, char *argv[], int argc)
{

   u_int32_t id;
   
   if (strncmp(argv[argc-1], "?", 2)==0)
     {
	cli_print(cli, "Specify the packet identification number (0..4294967295).\n");
	return CLI_OK;
     }

   if (mz_strcmp(argv[0], "hex", 2)==0)
     {
	id = xstr2int (argv[1]);
     }
   else
     {
	id = str2int (argv[0]);
     }
   
   clipkt->ip_id = id;
   
   return CLI_OK;
}






int cmd_ip_offset (struct cli_def *cli, char *command, char *argv[], int argc)
{
   
	int offset;
   
	if (strncmp(argv[argc-1], "?", 2)==0) {
		cli_print(cli, "Specify the fragment offset in multiples of 8 bytes.\n");
		return CLI_OK;
	}
   
	offset = (int) str2int(argv[0]);
	
	if (offset>8191) {
		cli_print(cli, "The fragment offset must be within range 0..8191\n");
		return CLI_OK;
	}
   
	clipkt->ip_frag_offset = offset;
	
	return CLI_OK;
}





int cmd_ip_sum (struct cli_def *cli, char *command, char *argv[], int argc)
{
   int sum;
   
   if (strncmp(argv[argc-1], "?", 2)==0)
     {
	cli_print(cli, "Specify the IP checksum in hexadecimal or use the keyword 'auto'.\r");
	cli_print(cli, "By default, the checksum is computed automatically.\n");
	return CLI_OK;
     }

   if (mz_strcmp(argv[0], "auto", 2)==0)
     {
	clipkt->ip_sum_false=0;
	return CLI_OK;
     }
   
   sum = (int) xstr2int(argv[0]);
   
   if (sum>0xffff) 
     {
	cli_print(cli, "The checksum must be within range 0..ffff\n");
	return CLI_OK;
     }
   
   clipkt->ip_sum = (u_int16_t) sum;
   clipkt->ip_sum_false=1;
   
   return CLI_OK;
}







int cmd_ip_tos (struct cli_def *cli, char *command, char *argv[], int argc)
{
   char *tmp;
   
   if (strncmp(argv[argc-1], "?", 2)==0)
     {
	cli_print(cli, "Specify the Type of Service field: <IPP> [<ToS>] [MBZ]\n");
	cli_print(cli, "  - IP precedence (IPP) 0..7\r");
	cli_print(cli, "  - ToS: delay/throughput/reliability/cost 0..15\r");
	cli_print(cli, "  - MBZ ('must be zero' - however, not with Mausezahn...)\r");
	cli_print(cli, "Or, alternatively, configure the whole byte in hex.\n");
	cli_print(cli, "EXAMPLES:\n");
	cli_print(cli, "  5          ... IPP = 5\r");
	cli_print(cli, "  5 9        ... IPP = 5 and ToS = 9\r");
	cli_print(cli, "  5 MBZ      ... IPP = 5 and MBZ is set\r");
	cli_print(cli, "  5 9 MBZ    ... All three fields configured\r");
	cli_print(cli, "  hex a8     ... the whole byte is set to 10101000\r");
	cli_print(cli, "  10101000   ... the whole byte in binary\n");
	return CLI_OK;
     }
   
   if ((argc==1) && (mz_strisbinary(argv[0])==8))
     {
	clipkt->ip_tos = (u_int8_t) str2bin8 (argv[0]);
	return CLI_OK;
     }
   
   if ((argc==2) && (mz_strcmp(argv[0], "hex", 2)==0))
     {
	tmp = argv[1];
	
	if (strlen(tmp)!=2) 
	  {
	     cli_print(cli, "You must specify a 2-digit hexadecimal value\n");
	     return CLI_OK;
	  }
	
	if (!(isxdigit(tmp[0])) || (!(isxdigit(tmp[1]))))
	  {
	     cli_print(cli, "Non-hexadecimal value!\n");
	     return CLI_OK;
	  }
	
	clipkt->ip_tos = (u_int8_t) xstr2int (tmp);
	return CLI_OK;
     }
   
   switch (argc)
     {
      case 1:
	if (mz_strcmp(argv[0], "mbz", 1)==0)
	  {
	     mops_ip_tos(clipkt, -1, -1, 1);
	  }
	else
	  {
	     if (mops_ip_tos(clipkt, (int)str2int(argv[0]), -1, 0))
	       cli_print(cli, "Invalid IP Precedence value\n");
	  }
	break;
	
      case 2:
	if (mz_strcmp(argv[1], "mbz", 1)==0)
	  {
	     if (mops_ip_tos(clipkt, (int)str2int(argv[0]), -1, 1))
	       cli_print(cli, "Invalid IP Precedence value\n");
	  }
	else
	  {
	     if (mops_ip_tos(clipkt, (int)str2int(argv[0]), (int)str2int(argv[1]), 0))
	       cli_print(cli, "Invalid values\n");
	  }
	break;
	
      case 3:
	if (mz_strcmp(argv[2], "mbz", 1)!=0)
	  cli_print(cli, "In this case the 3rd argument must be 'mbz'\n");
	else
	  if (mops_ip_tos(clipkt, (int)str2int(argv[0]), (int)str2int(argv[1]),  1))
	    cli_print(cli, "Invalid values\n");
	break;
     }
   
   return CLI_OK;
}







int cmd_ip_dscp (struct cli_def *cli, char *command, char *argv[], int argc)
{
   if ((argc!=1) || (strncmp(argv[argc-1], "?", 2)==0))
     {
	cli_print(cli, "Specify the Type of Service field using the DSCP format.\r");
	cli_print(cli, "Multiple notations are supported.\n");
	cli_print(cli, "Examples:\r");
	cli_print(cli, "    AF32        .... specify AF codepoint with class 3 and drop probability 2\r");
	cli_print(cli, "    EF          .... specify Expedited Forwarding\r");
	cli_print(cli, "    CS7         .... specify Code Selector 7\r");
	cli_print(cli, "    101110      .... specify the DSCP in binary\r");
	cli_print(cli, "    56          .... specify the DSCP in decimal\r");
	cli_print(cli, "\r");
	return CLI_OK;
     }
   
   switch (mops_ip_dscp(clipkt, argv[0]))
     {
      case -1:
	cli_print(cli, "Invalid DSCP specification (use '?')\n");
	break;
      case 1:
	cli_print(cli, "Invalid AF code point (use '?')\n");
	break;
      case 2:
	cli_print(cli, "Invalid Code Selector (CS0..CS7)\n");
	break;
      case 3:
	cli_print(cli, "Invalid DSCP value (0..63)\n");
	break;
     }
   
   return CLI_OK;
}





int cmd_ip_rsv (struct cli_def *cli, char *command, char *argv[], int argc)
{
   
   if (strncmp(argv[argc-1], "?", 2)==0)
     {
	cli_print(cli, "Set or unset the reserved flag.\n");
	return CLI_OK;
     }
   
   if (argc!=1)
     {
	cli_print(cli, "Use the 'set' or 'unset' keywords.\n");
	return CLI_OK;
     }
   
	
   if (mz_strcmp(argv[0], "set", 1)==0)
     {
	clipkt->ip_flags_RS = 1;
	return CLI_OK;
     }
       
   if (mz_strcmp(argv[0], "unset", 1)==0)
     {
	clipkt->ip_flags_RS = 0;
	return CLI_OK;
     }
   
   cli_print(cli, "Unknown keyword. Use the 'set' or 'unset' keywords.\n");
   
   return CLI_OK;
   
}





int cmd_ip_df (struct cli_def *cli, char *command, char *argv[], int argc)
{
   
   if (strncmp(argv[argc-1], "?", 2)==0)
     {
	cli_print(cli, "Set or unset the don't fragment flag.\n");
	
	return CLI_OK;
     }

   if (argc!=1)
     {
	cli_print(cli, "Use the 'set' or 'unset' keywords.\n");
	return CLI_OK;
     }

   
   if (mz_strcmp(argv[0], "set", 1)==0)
     {
	clipkt->ip_flags_DF = 1;
	return CLI_OK;
     }
   
   if (mz_strcmp(argv[0], "unset", 1)==0)
     {
	clipkt->ip_flags_DF = 0;
	return CLI_OK;
     }
   
   cli_print(cli, "Unknown keyword. Use the 'set' or 'unset' keywords.\n");

   
   return CLI_OK;
   
}





int cmd_ip_mf (struct cli_def *cli, char *command, char *argv[], int argc)
{
   
   if (strncmp(argv[argc-1], "?", 2)==0)
     {
	cli_print(cli, "Set or unset the more fragments flag.\n");
	
	return CLI_OK;
     }

   if (argc!=1)
     {
	cli_print(cli, "Use the 'set' or 'unset' keywords.\n");
	return CLI_OK;
     }

   
   if (mz_strcmp(argv[0], "set", 1)==0)
     {
	clipkt->ip_flags_MF = 1;
	return CLI_OK;
     }
       
   if (mz_strcmp(argv[0], "unset", 1)==0)
     {
	clipkt->ip_flags_MF = 0;
	return CLI_OK;
     }

   cli_print(cli, "Unknown keyword. Use the 'set' or 'unset' keywords.\n");
   
   return CLI_OK;
   
}


int cmd_ip_fragsize (struct cli_def *cli, char *command, char *argv[], int argc)
{
	u_int32_t fragsize=0; 
	
	if (strncmp(argv[argc-1], "?", 2)==0) {
		cli_print(cli, "Enable fragmentation by configuring a fragment size.\n");
		cli_print(cli, "Note that the fragment size specifies the number of bytes in the IP payload\r");
		cli_print(cli, "and NOT the assumed MTU on that link. The total packet size of each fragment\r");
		cli_print(cli, "will be 20 bytes larger (=size of IP header if no IP options are used).\n");
		cli_print(cli, "WARNING: The fragment size SHOULD be a multiple of 8 bytes if you expect\r");
		cli_print(cli, "         a valid result.\n");
		cli_print(cli, "ARGUMENTS: <frag-size>\n");
		return CLI_OK;
	}
	
	if (argc!=1) {
		cli_print(cli, "Specify the fragment size in bytes.\n");
		return CLI_OK;
	}

       
	fragsize = (u_int32_t) str2int(argv[0]);
	
	if ((fragsize<0) || (fragsize>8000)) { 
		cli_print(cli, "The fragment size must be within range 0..8000\n");
		return CLI_OK;
	}
	
	if (fragsize%8) {
		cli_print(cli, "Warning: The fragment-size is not a multiple of 8.\n");
	}
	
	clipkt->ip_fragsize = fragsize;

	return CLI_OK;
   
}



int cmd_ip_fragoverlap (struct cli_def *cli, char *command, char *argv[], int argc)
{
	u_int32_t overlap=0; 
	
	if (strncmp(argv[argc-1], "?", 2)==0) {
		cli_print(cli, "Specify how many bytes should overlap when IP fragmentation is enabled.\n");
		cli_print(cli, "NOTE: The number of overlap bytes is either 0 (default, no overlap) or\r");
		cli_print(cli, "      a multiple of 8 bytes but smaller than frag-size.\n");
		cli_print(cli, "ARGUMENTS: <overlap>\n");
		return CLI_OK;
	}
	
	if (argc!=1) {
		cli_print(cli, "Specify how many bytes should overlap between successive IP fragments.\n");
		return CLI_OK;
	}

       
	overlap = (u_int32_t) str2int(argv[0]);
	
	if (clipkt->ip_fragsize == 0) {
		cli_print(cli, "Please configure the fragment size first.\n");
		return CLI_OK;
	}
	
	if ((overlap>clipkt->ip_fragsize) || (overlap%8)) {
		cli_print(cli, "The overlap MUST be a multiple of 8 and MUST NOT exceed frag-size!\n");
		return CLI_OK;
	}
	
	clipkt->ip_frag_overlap = overlap;

	return CLI_OK;
}





int cmd_ip_option (struct cli_def *cli, char *command, char *argv[], int argc)
{
	int val=0;
	
	if ((strncmp(argv[argc-1], "?", 2)==0) || (argc==0)) {
		cli_print(cli, "Add or delete IP options.\n");
		cli_print(cli, "You can only add one option after the other; if you want to configure multiple\r");
		cli_print(cli, "options then repeat this command. The options are added to the IP header in the\r");
		cli_print(cli, "same order as you configure them.\n");
		cli_print(cli, "Currently the following options are supported:\n");
		cli_print(cli, "router-alert [<value>]   ... signal transit routers to examine the content of this\r");
		cli_print(cli, "                             packet.\r");
		cli_print(cli, "\n");
		cli_print(cli, "clear  ..................... remove all options from the packet\n");
		return CLI_OK;
	}
   
	if (mz_strcmp(argv[0], "router-alert", 3)==0) {
		switch (argc) {
		 case 1:
			val=0;
			break;
		 case 2:
			val = (int) str2int(argv[1]);
			break;
		 default:
			cli_print(cli, "Too many arguments!\n");
			return CLI_OK;
		}
		if (mops_ip_option_ra (clipkt, val)) {
			cli_print(cli, "Value must be within 0..65535\n");
			return CLI_OK;
		}
		    
	} else if (mz_strcmp(argv[0], "loose-source-route", 3)==0) {
		cli_print(cli, "Currently not implemented\n");
		return CLI_OK;
	} else if (mz_strcmp(argv[0], "record-route", 3)==0) {
		cli_print(cli, "Currently not implemented\n");
		return CLI_OK;
	}
	
	else if (mz_strcmp(argv[0], "clear", 2)==0) {
		mops_ip_option_remove_all (clipkt);
	}
   
   return CLI_OK;
}



// By default we use ARP to determine the destination MAC and therefore support
// automatic (in)direct delivery of IP packets. Alternatively the user may turn
// this off and may configure an arbitrary destination MAC address
// 
int cmd_ip_delivery (struct cli_def *cli, char *command, char *argv[], int argc)
{
	char str[16];
	if (strncmp(argv[argc-1], "?", 2)==0) {
		cli_print(cli, "Enable or disable IP auto-delivery.\n");
		sprintf(str, "%s", (clipkt->auto_delivery_off) ? "DISABLED" : "ENABLED");
		cli_print(cli, "Currently, IP auto-delivery is %s\n", str);
		return CLI_OK;
	}
	
	if (argc!=1) {
		cli_print(cli, "Argument missing. Enter either 'enable' or 'disable'\n");
		return CLI_OK;
	}
	
	if (mz_strcmp(argv[0], "enable", 1)==0) 
		clipkt->auto_delivery_off=0;
	else if (mz_strcmp(argv[0], "disable", 1)==0)
		clipkt->auto_delivery_off=1;
	else {
		cli_print(cli, "Unknown keyword.  Enter either 'enable' or 'disable'\n");
		return CLI_OK;
	}
	
	sprintf(str, "%s", (clipkt->auto_delivery_off) ? "DISABLED" : "ENABLED");
	cli_print(cli, "IP auto-delivery is now %s\n", str);
		
	return CLI_OK;
   
}



int cmd_ip_end(struct cli_def *cli, char *command, char *argv[], int argc)
{
   char prompt[16];
   sprintf(prompt, "pkt-%i",clipkt->id);
   cli_set_configmode(cli, MZ_MODE_PACKET, prompt);
   return CLI_OK;
}

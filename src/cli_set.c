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


#include "mz.h"
#include "cli.h"


int cmd_set(struct cli_def *cli, char *command, char *argv[], int argc)
{
   libnet_t       *l;
   unsigned int time_factor;   
   int i, cnt, found_dev;
   char *dum;
   unsigned char *x;

	
   if (argc < 2) {
       cli_print(cli, "Specify a variable to set:\r\n");
       cli_print(cli, "device      specify the primary network device\r");
	    
       cli_print(cli, "NOTE: The following options are non-MOPS and deprecated:\n");
	    
       cli_print(cli, "a|sa        specify a MAC source address\r");
       cli_print(cli, "b|da        specify a MAC destination address\r");
       cli_print(cli, "A|SA        specify a IP source address\r");
       cli_print(cli, "B|DA        specify a IP destination address\r");
       cli_print(cli, "c|count     specify a packet count value\r");
       cli_print(cli, "d|delay     specify an interpacket delay (usec, msec, or sec)\r");
       cli_print(cli, "P|payload   specify an ASCII payload\r");
       cli_print(cli, "H|hexload   specify a hexadecimal payload\r");
       cli_print(cli, "p|padding   specify a number of padding bytes (total for raw, added otherwise)\r");
       cli_print(cli, "Q|vlan      specify one ore more 802.1Q vlan tags\r");
       cli_print(cli, "M|mpls      specify one ore more MPLS labels\r");
       cli_print(cli, "\n");
	return CLI_OK;
    }
   
   // set primary device
   if  (strncmp(argv[0], "device", 2)==0) 
     {
	if (strncmp(argv[1],"?",1)==0)
	  {
	     cli_print(cli,"Specify the primary network device (use 'show dev' for a list)\n");
	  }
	else
	  {
	     if (strlen(argv[1])) 
	       {
		  found_dev = 0;
		  for (i=0; i<device_list_entries; i++)
		    {
		       if (strncmp(device_list[i].dev, argv[1], 16)==0) 
			 { 
			    found_dev=1;
			    break;
			 }
		    }
		  if (found_dev)
		    {
		       strncpy(tx.device, argv[1], 16);
		    }
		  else
		    cli_print(cli, "Unknown device, will stick on %s\n", tx.device);
	       }
	     else
	       cli_print(cli, "Nothing specified, will stick on %s\n", tx.device);
	  }
     }
	
	
   // set source MAC address
   else if ( (strncmp(argv[0], "a", 10)==0) ||
	     (strncmp(argv[0], "sa", 10)==0) )
     {
	if (strncmp(argv[1],"?",1)==0)
	  {
	     cli_print(cli,"Specify a source MAC address (format: XX:XX:XX:XX:XX:XX)\n");
	  }
	else
	  {
	     strncpy(tx.eth_src_txt, argv[1], 32);
	     if (check_eth_mac_txt(ETH_SRC))
	       {
		  cli_print(cli, "Invalid MAC address! Format: XX:XX:XX:XX:XX:XX\r");
		  cli_print(cli, "Current setting: sa = %02x:%02x:%02x:%02x:%02x:%02x\r", 
			    tx.eth_src[0], tx.eth_src[1], tx.eth_src[2],
			    tx.eth_src[3], tx.eth_src[4], tx.eth_src[5]);
	       }
	     
	     tx.packet_mode = 0;

	  }
     }
   
   // set destination MAC address
   else if ( (strncmp(argv[0], "b", 10)==0) ||
	     (strncmp(argv[0], "da", 10)==0) )
     {
	if (strncmp(argv[1],"?",1)==0)
	  {
	     cli_print(cli,"Specify a destination MAC address (format: XX:XX:XX:XX:XX:XX)\n");
	  }
	else
	  {
	     strncpy(tx.eth_dst_txt, argv[1], 32);
	     if (check_eth_mac_txt(ETH_DST))
	       {
		  cli_print(cli, "Invalid MAC address! Format: XX:XX:XX:XX:XX:XX\r");
		  cli_print(cli, "Current setting: da = %02x:%02x:%02x:%02x:%02x:%02x\r", 
			    tx.eth_dst[0], tx.eth_dst[1], tx.eth_dst[2],
			    tx.eth_dst[3], tx.eth_dst[4], tx.eth_dst[5]);
	       }
	     
	     tx.packet_mode = 0;
	  }
     }
   
   // set source IP address
   else if ( (strncmp(argv[0], "A", 10)==0) ||
	     (strncmp(argv[0], "SA", 10)==0) )
     {
	if (strncmp(argv[1],"?",1)==0)
	  {
	     cli_print(cli,"Specify a source IP address, a FQDN, 'rand', or a range\n");
	  }
	else
	  {
	     if (strcmp(argv[1], "rand") == 0)
	       {
		  tx.ip_src_rand = 1;
		  tx.ip_src_h  = (u_int32_t) ( ((float) rand()/RAND_MAX)*0xE0000000); //this is 224.0.0.0
// TODO:	  mops_hton32 (&tx.ip_src_h, &tx.ip_src);
	       }
	     else if (get_ip_range_src(argv[1])) // returns 1 when no range has been specified
	       {
		  l = libnet_init (LIBNET_LINK_ADV, tx.device, NULL);
		  if (l == NULL)
		    {
		       cli_print(cli, "Error: could not access the network device!\n");
		       return CLI_OK;
		    }
		  // name2addr4 accepts a DOTTED DECIMAL ADDRESS or a FQDN:
		  tx.ip_src = libnet_name2addr4 (l, argv[1], LIBNET_RESOLVE);
		  x = (unsigned char *) &tx.ip_src;
		  cli_print(cli, "Set source IP address to %i.%i.%i.%i\n",
			    *x,*(x+1),*(x+2),*(x+3));
// TODO:	  mops_hton32 (&tx.ip_src, &tx.ip_src_h);
		  libnet_destroy(l);
	       }
	  }
     }
   
   // set destination IP address
   else if ( (strncmp(argv[0], "B", 10)==0) ||
	     (strncmp(argv[0], "DA", 10)==0) )
     {
	if (strncmp(argv[1],"?",1)==0)
	  {
	     cli_print(cli,"Specify a destination IP address, a FQDN, or a range\n");
	  }
	else
	  {
	     if (get_ip_range_dst(argv[1])) // returns 1 when no range has been specified
	       {
		  l = libnet_init (LIBNET_LINK_ADV, tx.device, NULL);
		  if (l == NULL)
		    {
		       cli_print(cli, "Error: could not access the network device!\n");
		       return CLI_OK;
		    }
		  // name2addr4 accepts a DOTTED DECIMAL ADDRESS or a FQDN:
		  tx.ip_dst = libnet_name2addr4 (l, argv[1], LIBNET_RESOLVE);
		  x = (unsigned char *) &tx.ip_src;
		  cli_print(cli, "Set destination IP address to %i.%i.%i.%i\n",
			    *x,*(x+1),*(x+2),*(x+3));
// TODO:          mops_hton32 (&tx.ip_dst, &tx.ip_dst_h);
		  libnet_destroy(l);
	       }
	  }
     }
   
   // set packet count
   else if ( (strncmp(argv[0], "c", 10)==0) ||
	     (strncmp(argv[0], "count", 10)==0) )
     {
	if (strncmp(argv[1],"?",1)==0)
	  {
	     cli_print(cli,"Specify a packet count value\n");
	  }
	else
	  {
	     cnt = (unsigned int) str2int (argv[1]);
	     if (cnt==0)
	       {
		  cli_print(cli, "Warning: A packet count of zero means an infinite number of packets.\r");
		  cli_print(cli, "Infinite packets are only supported via MOPS (use the 'packet' command\r");
		  cli_print(cli, "in global configuration mode) or when running Mausezahn from the shell.\n");
		  cli_print(cli, "Note: The count value has NOT been changed.\n");
	       }
	     else
	       {
		  tx.count = cnt;
	       }
	  }
     }
   
   // set interpacket delay
   else if ( (strncmp(argv[0], "d", 10)==0) ||
	     (strncmp(argv[0], "delay", 10)==0) )
     {
	if (strncmp(argv[1],"?",1)==0)
	  {
	     cli_print(cli,"Specify an interpacket delay (usec, msec, or sec)\n");
	  }
	else
	  {
	     // determine whether seconds or msecs are used
	     // default is usec!!!
	     time_factor=1;
	     if (exists(argv[1],"s") || exists(argv[1],"sec")) time_factor=1000000;
	     if (exists(argv[1],"m") || exists(argv[1],"msec")) time_factor=1000;
	     dum = strtok(argv[1],"ms");
	     tx.delay = strtol(dum, (char **)NULL, 10) * time_factor;
	     if ((errno == ERANGE && (tx.delay == LONG_MAX || tx.delay == LONG_MIN))
		 || (errno != 0 && tx.delay == 0)) 
	       {
		  cli_print(cli, "Value out of range!\n");
	       }
	     if (tx.delay<0) tx.delay=0; // no delay
	     
	     cli_print(cli, "Set interpacket delay to %u usec\n", tx.delay);
	  }

     }
   
   // set ASCII payload
   else if ( (strncmp(argv[0], "P", 10)==0) ||
	     (strncmp(argv[0], "payload", 10)==0) )
     {
	if (strncmp(argv[1],"?",1)==0)
	  {
	     cli_print(cli,"Specify an ASCII payload enclosed in quotes\n");
	  }
	else
	  {
	     strncpy((char *)tx.ascii_payload, argv[1], MAX_PAYLOAD_SIZE);
	     tx.ascii=1;
	  }
     }
   
   
   // set HEX payload
   else if ( (strncmp(argv[0], "H", 10)==0) ||
	     (strncmp(argv[0], "hexload", 10)==0) )
     {
	if (strncmp(argv[1],"?",1)==0)
	  {
	     cli_print(cli,"Specify a hexadecimal payload (using ':' or '.' as delimiters)\n");
	  }
	else
	  {
	     tx.hex_payload_s = str2hex (argv[1], tx.hex_payload, 8192);
	     if (tx.hex_payload_s==0)
	       cli_print(cli, "Invalid hexadecimal string. Try something like aa:bb:cc:45:99:00:de:ad:be:ef: ...\n");
	  }
     }
   
   
   // set MPLS labels
   else if ( (strncmp(argv[0], "M", 10)==0) ||
	     (strncmp(argv[0], "mpls", 10)==0) )
     {
	if (strncmp(argv[1],"?",1)==0)
	  {
	     cli_print(cli,"Specify one or more MPLS labels\n");
	  }
	else
	  {
	     if (strlen(argv[1])) // TODO: Better verification of 802.1Q syntax
		 {
		    strncpy(tx.mpls_txt, argv[1], 128);
		    tx.mpls=1;
		 }
	  }
     }
   
   
   // set 802.1Q tags
   else if ( (strncmp(argv[0], "Q", 10)==0) ||
	     (strncmp(argv[0], "vlan", 10)==0) )
     {
	if (strncmp(argv[1],"?",1)==0)
	  {
	     cli_print(cli,"Specify one or more 802.1Q VLAN tags (and optionally 801.1P values)\n");
	  }
	else
	  {
	     if (strlen(argv[1])) // TODO: Better verification of 802.1Q syntax
		 {
		    strncpy(tx.dot1Q_txt, argv[1], 32);
		    tx.dot1Q=1;
		 }
	  }
     }
   
   
   // set padding
   else if ( (strncmp(argv[0], "p", 10)==0) ||
	     (strncmp(argv[0], "padding", 10)==0) )
     {
	if (strncmp(argv[1],"?",1)==0)
	  {
	     cli_print(cli,"Specify a number of padding bytes\n");
	  }
	else
	  {
	     tx.padding = (unsigned int) str2int(argv[1]);
	     if (tx.padding > MAX_PAYLOAD_SIZE)
	       {
		  cli_print(cli, "Note: Padding too big! However, let's try and see what happens...\n");
	       }
	  }
     }


   
   // DEFAULT ANSWER:
   else
     {
	cli_print(cli, "Unknown variable '%s'\n",argv[0]);
     }
   
    return CLI_OK;
}

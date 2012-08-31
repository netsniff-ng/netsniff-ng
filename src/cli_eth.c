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





int cmd_packet_mac_address_source (struct cli_def *cli, char *command, char *argv[], int argc)
{
   int i,j;
   
   if ( (strcmp(argv[argc-1],"?")==0) || (argc>1) )
     {
	cli_print(cli, "XX:XX:XX:XX:XX:XX     Configure a source MAC address\n");
	cli_print(cli, "Optionally you may use randomly generated (unicast)\r");
	cli_print(cli, "MAC addresses, using the keyword 'random'\n");
	return CLI_OK;
     }

   if (argc==1)
     {
	if (mz_strcmp(argv[0], "random", 3)==0)
	  {
	     clipkt->eth_src_israndom = 1;
	     return CLI_OK;
	  }
	
	if (mz_strcmp(argv[0], "default", 3)==0)
	  {
	     // find index of device_list with the device configured in clipkt:
	     i=0;
	     while (strncmp(device_list[i].dev, clipkt->device, 10) && (i<device_list_entries)) i++;
	     for (j=0;j<6;j++) clipkt->eth_src[j] = device_list[i].mac_mops[j];
	     clipkt->eth_src_israndom = 0;
	     return CLI_OK;
	  }
	
	if (mops_pdesc_mac(clipkt->eth_src, argv[0]))
	  {
	     cli_print(cli,"Invalid MAC address (use format: XX:XX:XX:XX:XX:XX)\n");
	  }
	else // MAC was OK
	  {
	     clipkt->eth_src_israndom = 0;
	  }
     }
   else
     cli_print(cli, "Invalid MAC format!\n");
   

   return CLI_OK;
}



int cmd_packet_mac_address_destination (struct cli_def *cli, char *command, char *argv[], int argc)
{

   if ( (strcmp(argv[argc-1],"?")==0) || (argc>1) )
     {
	cli_print(cli, "XX:XX:XX:XX:XX:XX     Configure a destination MAC address\n");
	return CLI_OK;
     }
   if (argc==1)
     {
	if (mz_strcmp(argv[0], "bcast", 2)==0)
	  {
	     mops_pdesc_mac (clipkt->eth_dst, "ff:ff:ff:ff:ff:ff");
	     return CLI_OK;
	  }
	else if (mz_strcmp(argv[0], "pvst", 2)==0)
	  {
	     mops_pdesc_mac (clipkt->eth_dst, "01:00:0C:CC:CC:CD");
	     return CLI_OK;
	  }
	else if (mz_strcmp(argv[0], "cisco", 2)==0)
	  {
	     mops_pdesc_mac (clipkt->eth_dst, "01:00:0C:CC:CC:CC");
	     return CLI_OK;
	  }
	else if (mz_strcmp(argv[0], "stp", 2)==0)
	  {
	     mops_pdesc_mac (clipkt->eth_dst, "01:80:C2:00:00:00");
	     return CLI_OK;
	  }

	if (mops_pdesc_mac(clipkt->eth_dst, argv[0]))
	  {
	     cli_print(cli,"Invalid MAC address (use format: XX:XX:XX:XX:XX:XX)\n");
	  }
     }
   else
     cli_print(cli, "Invalid MAC format!\n");

   return CLI_OK;
}






int cmd_eth_type (struct cli_def *cli, char *command, char *argv[], int argc)
{
   unsigned long int t32;
   
   if ( (strcmp(argv[argc-1],"?")==0) || (argc>1) )
     {
	cli_print(cli, "Specify the Ethernet type field in hexadecimal format.\n");
	cli_print(cli, "For example:\n");
	cli_print(cli, "  800   ......... IP\r");
	cli_print(cli, "  806   ......... ARP\r");
	cli_print(cli, "  835   ......... RARP\r");
	cli_print(cli, " 8100   ......... 802.1Q\r");
	cli_print(cli, " 888E   ......... 802.1X\r");
	cli_print(cli, "\n");
	return CLI_OK;
     }
   
   if (argc==1)
     {
	t32 = xstr2int(argv[0]);
	if (t32>0xffff) 
	  {
	     cli_print(cli, "EtherType must not exceed ffff.\n");
	     return CLI_OK;
	  }
	if (t32<0x800) 
	  {
	     cli_print(cli, "WARNING: 'Officially' the EtherType must be greater or equal 800.\n");
	  }
	
	clipkt->eth_type = (u_int16_t) t32;
     }
   else
     {
	cli_print(cli, "Only one parameter accepted.\n");
     }
   
   return CLI_OK;
}




int cmd_eth_length (struct cli_def *cli, char *command, char *argv[], int argc)
{
   unsigned long int t32;
   
   if ( (strcmp(argv[argc-1],"?")==0) || (argc>1) )
     {
	cli_print(cli, "Specify the 802.3 length field in decimal notation.\r");
	cli_print(cli, "\n");
	return CLI_OK;
     }

      if (argc==1)
     {
	t32 = str2int(argv[0]);
	if (t32>0xffff) 
	  {
	     cli_print(cli, "The length field must not exceed 65535.\n");
	     return CLI_OK;
	  }
	if (t32>0x7ff) 
	  {
	     cli_print(cli, "WARNING: 'Officially' the 802.3 length field must not be greater than 1522.\n");
	  }
	
	clipkt->eth_len = (u_int16_t) t32;
     }
   else
     {
	cli_print(cli, "Only one parameter accepted.\n");
     }

   
   
   return CLI_OK;
}





int cmd_eth_llc (struct cli_def *cli, char *command, char *argv[], int argc)
{

   if ( (strcmp(argv[argc-1],"?")==0) || (argc>1) )
     {
	cli_print(cli, "Specify the IEEE 802.2 Logical Link Control (LLC) in hexadecimal format.\n");
	return CLI_OK;
     }
   
   // DSAP-SSAP-Ctrl
   // ***** TODO *****
   cli_print(cli, "Not supported in this version.\n");
   
   return CLI_OK;
}




int cmd_eth_snap (struct cli_def *cli, char *command, char *argv[], int argc)
{

   u_int8_t
     oui[16], 
     etp[16],
     t8[16] = {0xAA, 0xAA, 0x03};
   
   
   if ( (strcmp(argv[argc-1],"?")==0) || (argc>1) )
     {
	cli_print(cli, "Specify the SNAP header (OUI+Type) in hexadecimal format\r");
	cli_print(cli, "Example: 00:00:0e 08:00\r");
	cli_print(cli, "\n");
	return CLI_OK;
     }
   
   if (argc!=2)
     {
	cli_print(cli, "Two arguments required: 3-byte OUI and 2-byte EtherType\n");
	return CLI_OK;
     }
   
   if (str2hex(argv[0], oui, 15)!=3)
     {
	cli_print(cli, "Three bytes required for the OUI\n");
	return CLI_OK;
     }
   
   if (str2hex(argv[1], etp, 15)!=2)
     {
	cli_print(cli, "Two bytes required for the EtherType\n");
	return CLI_OK;
     }
   
   
   memcpy(&clipkt->eth_snap[0], &t8, 3);
   memcpy(&clipkt->eth_snap[3], &oui, 3);
   memcpy(&clipkt->eth_snap[6], &etp, 2);
   clipkt->eth_snap_s = 8;


   
   return CLI_OK;
}

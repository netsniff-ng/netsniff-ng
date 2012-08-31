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
#include "mops.h"


int transmit (struct cli_def *cli, char *command, char *argv[], int argc)
{
   int i;
   char argstr[10000];

   argstr[0]='\0';
   
   if (argc>1)
     {
	for (i=1; i<argc; i++)
	  {
	     if ((strlen(argv[i])+strlen(argstr))>10000)
	       {
		  cli_print(cli, "Argument list too long!\n");
		  return CLI_OK;
	       }
	     if (strncmp(argv[i], "?", 1)==0)
	       {
		  strcat(argstr, ",help");
	       }
	     else
	       strncat(argstr, argv[i], 5000); // TODO: This is ugly!
	  }
	// TEST: cli_print(cli, "argc=%i, got '%s'\n", argc, argstr);
     }
   
   
   if (argv[0] == NULL) // raw hex string given
     {
	mode = BYTE_STREAM;
     }
   else if (strcmp(argv[0],"arp")==0)
     {
	mode = ARP;
     }
   else if (strcmp(argv[0],"bpdu")==0)
     {
	mode = BPDU;
     }
   else if (strcmp(argv[0],"ip")==0)
     {
	mode = IP;
     }
   else if (strcmp(argv[0],"udp")==0)
     {
	mode = UDP;
     }
   else if (strcmp(argv[0],"icmp")==0)
     {
	mode = ICMP;
     }
   else if (strcmp(argv[0],"tcp")==0)
     {
	mode = TCP;
     }
   else if (strcmp(argv[0],"dns")==0)
     {
	mode = DNS;
     }
   else if (strcmp(argv[0],"cdp")==0)
     {
	mode = CDP;
     }
   else if (strcmp(argv[0],"syslog")==0)
     {
	mode = SYSLOG;
     }
   else if (strcmp(argv[0],"lldp")==0)
     {
	mode = LLDP;
	tx.packet_mode=0; // create whole frame by ourself
     }
   else if (strcmp(argv[0],"rtp")==0)
     {
	mode = RTP;
     }
   else if (strcmp(argv[0],"raw")==0)
     {
	strncpy(tx.arg_string, argstr, MAX_PAYLOAD_SIZE);
	send_eth();
     }
   else if (strcmp(argv[0],"?")==0)
     {
	cli_print(cli, 
		"|  The following packet types are currently implemented:\n"
		"|\n"
		"|  arp            ... sends ARP packets\n"
		"|  bpdu           ... sends BPDU packets (STP)\n"
		"|  cdp            ... sends CDP messages\n"
		"|  ip             ... sends IPv4 packets\n"
		"|  udp            ... sends UDP datagrams\n"
		"|  tcp            ... sends TCP segments\n"
		"|  icmp           ... sends ICMP messages\n"
		"|  dns            ... sends DNS messages\n"
		"|  rtp            ... sends RTP datagrams\n"
		"|  syslog         ... sends Syslog messages\n"
		"|  lldp           ... sends LLDP datagrams\n"
		"|\n"
		"|  raw            ... raw layer 2 mode (specify whole frame in hex)\n"
		"\n"
		);
	return CLI_OK;	
     }
   else
     {
	cli_print(cli, "Unknown packet type '%s'\r", argv[0]);
     }


   if (mode)
     {
	strncpy(tx.arg_string, argstr, MAX_PAYLOAD_SIZE);
	tx_switch(cli);
     }
   
   return CLI_OK;
}

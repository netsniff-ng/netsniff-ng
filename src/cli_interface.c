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




// Enter interface config mode:
//   
int enter_interface (struct cli_def *cli, char *command, char *argv[], int argc)
{
   int i, j=0;
   char prompt[10];
   
   if ( (strcmp(argv[argc-1],"?")==0) || (argc>1) )
     {
	cli_print(cli, "Specify an interface to configure\n");
	return CLI_OK;
     }

   if (argc)
     {
	for (i=0; i<device_list_entries; i++)
	  {
	     if (strncmp(device_list[i].dev, argv[0], 16)==0)
	       {
		  j=1;
		  sprintf(prompt, "if-%s", device_list[i].dev);
		  clidev = i;
		  break;
	       }
	  }
	
	if (j)
	  {
	     cli_set_configmode(cli, MZ_MODE_INTERFACE, prompt);
	  }
	else
	  {
	     cli_print(cli, "Unknown device!\n");
	  }
     }
   else
     {
	cli_print(cli, "Specify an interface to configure\n");
     }
   
   return CLI_OK;
}



int conf_ip_address (struct cli_def *cli, char *command, char *argv[], int argc)
{
   if ( (strcmp(argv[argc-1],"?")==0) || (argc>1) )
     {
	cli_print(cli, "A.B.C.D      Specify a default interface IP address\n");
	return CLI_OK;
     }
   
   if (argc)
     {
	if (mops_pdesc_ip (device_list[clidev].ip_mops, argv[0]))
	  { 
	     cli_print(cli,"Invalid IP address (use format: A.B.C.D)\n");
	  }
     }
   else
     cli_print(cli, "A.B.C.D      Specify a default interface IP address\n");
   
   return CLI_OK;
}



int conf_mac_address (struct cli_def *cli, char *command, char *argv[], int argc)
{
   if ( (strcmp(argv[argc-1],"?")==0) || (argc>1) )
     {
	cli_print(cli, "XX:XX:XX:XX:XX:XX      Configure a default interface MAC address\n");
	return CLI_OK;
     }
   
   if (argc)
     {
	if (mops_pdesc_mac (device_list[clidev].mac_mops, argv[0]))
	  { 
	     cli_print(cli,"Invalid MAC address (use format: XX:XX:XX:XX:XX:XX)\n");
	  }
     }
   else
     cli_print(cli, "A.B.C.D      Specify a default interface IP address\n");
   
   return CLI_OK;
}



int conf_tag_dot1q (struct cli_def *cli, char *command, char *argv[], int argc)
{
   if ( (strcmp(argv[argc-1],"?")==0) || (argc>1) )
     {
	cli_print(cli, "Specify one or more 802.1Q (and optionally 802.1P) tags\n");
	return CLI_OK;
     }
   cli_print(cli, "Not supported in this version\n");
   return CLI_OK;
}

int conf_tag_mpls (struct cli_def *cli, char *command, char *argv[], int argc)
{
   if ( (strcmp(argv[argc-1],"?")==0) || (argc>1) )
     {
	cli_print(cli, "Specify one or more MPLS labels (and parameters)\n");
	return CLI_OK;
     }
   cli_print(cli, "Not supported in this version\n");
   return CLI_OK;
}





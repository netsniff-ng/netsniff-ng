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



int cmd_port_source (struct cli_def *cli, char *command, char *argv[], int argc)
{
	u_int32_t t32=0;
	int validport=0;
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc>2) ) {
		cli_print(cli, "Specify the source port number:\n");
		cli_print(cli, " <port> [<end-port>]\r");
		cli_print(cli, " random [norandom]\r");
		cli_print(cli, "\n");
		return CLI_OK;
	}
   
	if (mz_strcmp(argv[0], "random",1)==0) {
		clipkt->sp_isrand = 1;
		clipkt->sp_isrange = 0;
	} else if  (mz_strcmp(argv[0], "norandom",1)==0) {
		clipkt->sp_isrand = 0;
	} else {
		if (!mz_strisnum(argv[0])) {
			cli_print(cli, "Unknown keyword\n");
			return CLI_OK;
		}
		t32 = str2int(argv[0]);
		if (t32>65535) {
			cli_print(cli, "Port number cannot exceed 65535\n");
			return CLI_OK;
		} else {
			clipkt->sp= (u_int16_t) t32;
			validport=1;
			clipkt->sp_isrange = 0;
		}
	}
	
	if ((argc==2) && (validport)) {
		if (!mz_strisnum(argv[1])) {
			cli_print(cli, "Invalid number\n");
			return CLI_OK;
		}
		t32 = str2int(argv[1]);
		if (t32>65535) {
			cli_print(cli, "Port number cannot exceed 65535\n");
		} else {
			clipkt->sp_start = clipkt->sp;
			clipkt->sp_stop  = (u_int16_t) t32;
			clipkt->sp_isrange = 1;
		}
	}
   
	return CLI_OK;
}




int cmd_port_destination (struct cli_def *cli, char *command, char *argv[], int argc)
{
	u_int32_t t32=0;
	int validport=0;
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc>2) ) {
		cli_print(cli, "Specify the destination port number\r");
		cli_print(cli, " <port> [<end-port>]\r");
		cli_print(cli, " random [norandom]\r");
		cli_print(cli, "\n");
		return CLI_OK;
	}

	if (mz_strcmp(argv[0], "random",1)==0) {
		clipkt->dp_isrand = 1;
		clipkt->dp_isrange = 0;
	} else if  (mz_strcmp(argv[0], "norandom",1)==0) {
		clipkt->dp_isrand = 0;
	} else {
		if (!mz_strisnum(argv[0])) {
			cli_print(cli, "Unknown keyword\n");
			return CLI_OK;
			
		}
		t32 = str2int(argv[0]);
		if (t32>65535) {
			cli_print(cli, "Port number cannot exceed 65535\n");
			return CLI_OK;
		} else {
			clipkt->dp= (u_int16_t) t32;
			validport=1;
			clipkt->dp_isrange = 0;
		}
	}
	
	if ((argc==2) && (validport)) {
		if (!mz_strisnum(argv[1])) {
			cli_print(cli, "Invalid number\n");
			return CLI_OK;
		}
		t32 = str2int(argv[1]);
		if (t32>65535) {
			cli_print(cli, "Port number cannot exceed 65535\n");
		} else {
			clipkt->dp_start = clipkt->dp;
			clipkt->dp_stop  = (u_int16_t) t32;
			clipkt->dp_isrange = 1;
		}
	}

	return CLI_OK;
}



int cmd_udp_sum (struct cli_def *cli, char *command, char *argv[], int argc)
{
   int sum;
   
   if ( (strcmp(argv[argc-1],"?")==0) || (argc>1) )
     {
	cli_print(cli, "Specify the UDP checksum:\n");
	cli_print(cli, " - either in hexadecimal format (0-ffff)\r");
	cli_print(cli, " - or use the keyword 'auto' (default)\r");
	cli_print(cli, " - or use the keyword 'unset'\r");
	cli_print(cli, "\r");
	cli_print(cli, "By default, the checksum is computed automatically. The keyword\r");
	cli_print(cli, "'unset' signals the receiver that the checksum has not be computed\r");
	cli_print(cli, "and should be ignored.\n");
	return CLI_OK;
     }
   
   if (mz_strcmp(argv[0], "auto", 2)==0)
     {
	clipkt->udp_sum_false=0;
	return CLI_OK;
     }
   
   if (mz_strcmp(argv[0], "unset", 2)==0)
     {
	clipkt->udp_sum_false=1;
	clipkt->udp_sum = 0xffff;
	return CLI_OK;
     }
   
   sum = (int) xstr2int(argv[0]);
   
   if (sum>0xffff) 
     {
	cli_print(cli, "The checksum must be within range 0..ffff\n");
	return CLI_OK;
     }
   
   clipkt->udp_sum = (u_int16_t) sum;
   clipkt->udp_sum_false=1;
   
   return CLI_OK;
}



int cmd_udp_len (struct cli_def *cli, char *command, char *argv[], int argc)
{

   if ( (strcmp(argv[argc-1],"?")==0) || (argc>1) )
     {
	cli_print(cli, "Specify the UDP length\r");
	cli_print(cli, "\n");
	return CLI_OK;
     }
   
   cli_print(cli, "Not supported in this version.\n");
   
   return CLI_OK;
}


int cmd_udp_end(struct cli_def *cli, char *command, char *argv[], int argc)
{
   char prompt[16];
   sprintf(prompt, "pkt-%i",clipkt->id);
   cli_set_configmode(cli, MZ_MODE_PACKET, prompt);
   return CLI_OK;
}

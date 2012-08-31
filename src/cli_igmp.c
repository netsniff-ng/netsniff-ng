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


int cmd_igmpv2_genquery (struct cli_def *cli, char *command, char *argv[], int argc)
{
	int mrt, sum;
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc>2) ) {
		cli_print(cli, "Configure a IGMPv2 general query.\n");
		cli_print(cli, "ARGUMENTS: [<MRT> [<checksum>]]\n");
		cli_print(cli, "<MRT>        ... maximum response time in 100 msec units (default: 10 s)\r");
		cli_print(cli, "<checksum>   ... user-defined checksum (usually wrong by intention) in \r");
		cli_print(cli, "                 hexadecimal notation (e. g. 'c7b3').\n");
		return CLI_OK;
	}
   
	if (argc>=1) {
		if (mz_strisnum(argv[0])==0) {
			cli_print(cli, "Maximum response time must only contain numbers!\n");
			return CLI_OK;
		}
		mrt = (int) str2int(argv[0]);
	} else mrt = 100; // default: 10 s
	
	if (argc==2) {
		if (mz_strishex(argv[1])==0) {
			cli_print(cli, "Checksum must only contain hexadecimal numbers!\n");
			return CLI_OK;
		}
		sum = (int) xstr2int(argv[1]);
		if (sum>0xffff) {
			cli_print(cli, "Checksum must be a 2-byte value!\n");
			return CLI_OK;
		}

	} else sum = -1;

	clipkt->ip_dst = str2ip32("224.0.0.1");
	clipkt->ip_ttl = 1;
	clipkt->ndelay.tv_sec = 125;
	clipkt->ndelay.tv_nsec = 0;
	if (mops_create_igmpv2 (clipkt, 0, IGMP_GENERAL_QUERY, mrt, sum, 0)) 
		cli_print(cli, "Invalid parameters!\n");

	return CLI_OK;
}


int cmd_igmpv2_specquery (struct cli_def *cli, char *command, char *argv[], int argc)
{
	int mrt=100, sum=-1;
	u_int8_t IP[4];
	u_int32_t mip=0;
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc>3) ) {
		cli_print(cli, "Configure a IGMPv2 group-specific query.\n");
		cli_print(cli, "ARGUMENTS: <IP-address> [<MRT> [<checksum>]]\n");
		cli_print(cli, "<IP-Address>  ... multicast group to be queried (can be ANY IP address!)\r");
		cli_print(cli, "<MRT>         ... maximum response time in 100 msec units (default: 10 s)\r");
		cli_print(cli, "<checksum>    ... user-defined checksum (usually wrong by intention) in \r");
		cli_print(cli, "                  hexadecimal notation (e. g. 'c7b3').\n");
		return CLI_OK;
	}
   

	if (argc==0) {
		cli_print(cli, "You must at least specify the group address\n");
		return CLI_OK;
	}
	
	if (argc>=1) {
		if (mops_pdesc_ip (IP, argv[0])==0) // check if format is really an IP address
		        mip = str2ip32(argv[0]);
		else {
			cli_print(cli, "Invalid IP address\n");
			return CLI_OK;
		}		
	}
	
	if (argc>=2) {
		if (mz_strisnum(argv[1])==0) {
			cli_print(cli, "Maximum response time must only contain numbers!\n");
			return CLI_OK;
		}
		mrt = (int) str2int(argv[1]);
	}
	
	if (argc==3) {
		if (mz_strishex(argv[2])==0) {
			cli_print(cli, "Checksum must only contain hexadecimal numbers!\n");
			return CLI_OK;
		}
		sum = (int) xstr2int(argv[2]);
		if (sum>0xffff) {
			cli_print(cli, "Checksum must be a 2-byte value!\n");
			return CLI_OK;
		}
	} 

	clipkt->ip_dst = mip;
	clipkt->ip_ttl = 1;
	clipkt->ndelay.tv_sec = 125;
	clipkt->ndelay.tv_nsec = 0;
	if (mops_create_igmpv2 (clipkt, 0, IGMP_GSPEC_QUERY, mrt, sum, mip))
		cli_print(cli, "Invalid parameters!\n");

	return CLI_OK;
}





int cmd_igmpv2_report (struct cli_def *cli, char *command, char *argv[], int argc)
{
	int sum;
	u_int8_t IP[4];
	u_int32_t mip=0;
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc>2) || (argc==0)) {
		cli_print(cli, "Configure a IGMPv2 membership report.\n");
		cli_print(cli, "ARGUMENTS: <IP-Address> [<checksum>]\n");
		cli_print(cli, "<IP-Address>   ... multicast group address to be reported (but ANY IP\r");
		cli_print(cli, "                   address allowed, Mausezahn is really generous...)\r");
		cli_print(cli, "<checksum>     ... user-defined checksum (usually wrong by intention) in \r");
		cli_print(cli, "                   hexadecimal notation (e. g. 'c7b3').\n");
		return CLI_OK;
	}
   
	
	if (argc>=1) {
		if (mops_pdesc_ip (IP, argv[0])==0) // check if format is really an IP address
		        mip = str2ip32(argv[0]);
		else {
			cli_print(cli, "Invalid IP address\n");
			return CLI_OK;
		}
	}
       
	if (argc==2) {
		if (mz_strishex(argv[1])==0) {
			cli_print(cli, "Checksum must only contain hexadecimal numbers!\n");
			return CLI_OK;
		}
		sum = (int) xstr2int(argv[1]);
		if (sum>0xffff) {
			cli_print(cli, "Checksum must be a 2-byte value!\n");
			return CLI_OK;
		}
	} else sum = -1;

	clipkt->ip_dst = mip;
	clipkt->ip_ttl = 1;
	clipkt->ndelay.tv_sec = 1;
	clipkt->ndelay.tv_nsec = 0;

	if (mops_create_igmpv2 (clipkt, 0, IGMP_V2_REPORT, 0, sum, mip))
		cli_print(cli, "Invalid parameters!\n");

	return CLI_OK;
}


int cmd_igmpv2_leave (struct cli_def *cli, char *command, char *argv[], int argc)
{
	int sum;
	u_int8_t IP[4];
	u_int32_t mip=0;
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc>2) || (argc==0)) {
		cli_print(cli, "Configure a IGMPv2 leave group message.\n");
		cli_print(cli, "ARGUMENTS: <IP-Address> [<checksum>]\n");
		cli_print(cli, "<IP-Address>   ... multicast group address that should be left; use\r");
        	cli_print(cli, "                   the special address 0.0.0.0 for a 'general leave'\r");
		cli_print(cli, "<checksum>     ... user-defined checksum (usually wrong by intention) in \r");
		cli_print(cli, "                   hexadecimal notation (e. g. 'c7b3').\n");
		return CLI_OK;
	}
   
	
	if (argc>=1) {
		if (mops_pdesc_ip (IP, argv[0])==0) // check if format is really an IP address
		        mip = str2ip32(argv[0]);
		else {
			cli_print(cli, "Invalid IP address\n");
			return CLI_OK;
		}
	}
       
	if (argc==2) {
		if (mz_strishex(argv[1])==0) {
			cli_print(cli, "Checksum must only contain hexadecimal numbers!\n");
			return CLI_OK;
		}
		sum = (int) xstr2int(argv[1]);
		if (sum>0xffff) {
			cli_print(cli, "Checksum must be a 2-byte value!\n");
			return CLI_OK;
		}
	} else sum = -1;

	clipkt->ip_dst = str2ip32("224.0.0.2");
	clipkt->ip_ttl = 1;
	clipkt->ndelay.tv_sec = 1;
	clipkt->ndelay.tv_nsec = 0;

	if (mops_create_igmpv2 (clipkt, 0, IGMP_LEAVE, 0, sum, mip))
		cli_print(cli, "Invalid parameters!\n");

	return CLI_OK;
}





int cmd_igmpv1_query (struct cli_def *cli, char *command, char *argv[], int argc)
{
	int sum;
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc>1) ) {
		cli_print(cli, "Configure a IGMPv1 query.\n");
		cli_print(cli, "OPTIONAL ARGUMENT: [<checksum>]\n");
		cli_print(cli, "<checksum>   ... user-defined checksum (usually wrong by intention) in \r");
		cli_print(cli, "                 hexadecimal notation (e. g. 'c7b3').\n");
		return CLI_OK;
	}
   
	if (argc==1) {
		if (mz_strishex(argv[0])==0) {
			cli_print(cli, "Checksum must only contain hexadecimal numbers!\n");
			return CLI_OK;
		}
		sum = (int) xstr2int(argv[0]);
		if (sum>0xffff) {
			cli_print(cli, "Checksum must be a 2-byte value!\n");
			return CLI_OK;
		}
	} else sum = -1;

	clipkt->ip_dst = str2ip32("224.0.0.1");
	clipkt->ip_ttl = 1;
	clipkt->ndelay.tv_sec = 125;
	clipkt->ndelay.tv_nsec = 0;
	if (mops_create_igmpv2 (clipkt, 0, IGMP_GENERAL_QUERY, 0, sum, 0))
		cli_print(cli, "Invalid parameters!\n");

	return CLI_OK;
}


int cmd_igmpv1_report (struct cli_def *cli, char *command, char *argv[], int argc)
{
	int sum;
	u_int8_t IP[4];
	u_int32_t mip=0;
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc>2) || (argc==0)) {
		cli_print(cli, "Configure a IGMPv1 membership report.\n");
		cli_print(cli, "ARGUMENTS: <IP-Address> [<checksum>]\n");
		cli_print(cli, "<IP-Address>   ... multicast group address to be reported (but ANY IP\r");
		cli_print(cli, "                   address allowed, Mausezahn is really generous...)\r");
		cli_print(cli, "<checksum>     ... user-defined checksum (usually wrong by intention) in \r");
		cli_print(cli, "                   hexadecimal notation (e. g. 'c7b3').\n");
		return CLI_OK;
	}
   
	
	if (argc>=1) {
		if (mops_pdesc_ip (IP, argv[0])==0) // check if format is really an IP address
		        mip = str2ip32(argv[0]);
		else {
			cli_print(cli, "Invalid IP address\n");
			return CLI_OK;
		}
	} 
       
	if (argc==2) {
		if (mz_strishex(argv[1])==0) {
			cli_print(cli, "Checksum must only contain hexadecimal numbers!\n");
			return CLI_OK;
		}
		sum = (int) xstr2int(argv[1]);
		if (sum>0xffff) {
			cli_print(cli, "Checksum must be a 2-byte value!\n");
			return CLI_OK;
		}
	} else sum = -1;

	clipkt->ip_dst = mip;
	clipkt->ip_ttl = 1;
	clipkt->ndelay.tv_sec = 1;
	clipkt->ndelay.tv_nsec = 0;

	if (mops_create_igmpv2 (clipkt, 0, IGMP_V1_REPORT, 0, sum, mip))
		cli_print(cli, "Invalid parameters!\n");

	return CLI_OK;
}


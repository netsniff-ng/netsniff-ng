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



int launch_bpdu (struct cli_def *cli, char *command, char *argv[], int argc)
{
	int conf=0;
	struct mops_ext_bpdu * pd;
	
	if ( (strncmp(argv[argc-1],"?",2)==0) || (argc>1) ) {
		cli_print(cli, "Launch a(nother) BPDU process:\n");
		cli_print(cli, "<CR>        Per default a TCN-BPDU is sent.\r");
		cli_print(cli, "conf        Use this keyword to emit configuration BPDUs\r");
		cli_print(cli, "            (with this host as root bridge)\n");
		return CLI_OK;
	}

	if (argc==1) {
		if (mz_strcmp(argv[0], "conf", 1)==0) conf=1;
	}
	
	if ((clipkt = mops_alloc_packet(mp_head)) == NULL) { // Problem, memory full?
		cli_print(cli, "Cannot allocate additional memory!\n");
		return CLI_OK;
	}
	
	strncpy (clipkt->packet_name, "sysBPDU", 7);
	// OK, created a new packet
	cli_print(cli, "Allocated new packet %s at slot %i",clipkt->packet_name, clipkt->id);
	mops_set_defaults(clipkt);
	if (mops_ext_add_pdesc (clipkt, MOPS_BPDU))
		cli_print(cli, "Cannot configure BPDU parameters!?\n");
	else  {
		clipkt->use_ETHER = 1;
		clipkt->use_SNAP  = 1;
		clipkt->count = 0;
		clipkt->ndelay.tv_sec  = 2;
		clipkt->ndelay.tv_nsec = 0;
		pd = clipkt->p_desc;
		if (conf) 
			pd->bpdu_type = 0x00;
		else
			pd->bpdu_type = 0x80;
		mops_set_conf(clipkt);
		if (mops_tx_simple (clipkt)) {
			cli_print(cli, "Cannot create sending process.\r");
		}
	}
	
   return CLI_OK;
}



int launch_synflood (struct cli_def *cli, char *command, char *argv[], int argc)
{
	u_int8_t IP[4];
	int valid_ip=0, valid_port=0;
	
	if ( (strncmp(argv[argc-1],"?",2)==0) || (argc>2) || (argc==0)) {
		cli_print(cli, "Launch a(nother) TCP SYN-Flood process:\n");
		cli_print(cli, "<dst-ip-addr>            At least you must specify the destination IP address\r");
		cli_print(cli, "<dst-ip-addr> <port-nr>  Optionally specify the destination port (default: range from 1-1023)\n");
		return CLI_OK;
	}

	if (mops_pdesc_ip (IP, argv[0])==0) { // check if format is really an IP address
		valid_ip=1;
	} else {
		cli_print(cli, "Invalid IP address\n");
		return CLI_OK;
	}
	
	if (argc==2) {
		if (mz_strisnum(argv[1])==0) {
			cli_print(cli, "Invalid port number\n");
			return CLI_OK;
		}
		valid_port = (int) str2int(argv[1]);
		if (valid_port>65535) {
			cli_print(cli, "Invalid port number\n");
			return CLI_OK;
		}
	}
	
	
	if ((clipkt = mops_alloc_packet(mp_head)) == NULL) { // Problem, memory full?
		cli_print(cli, "Cannot allocate additional memory!\n");
		return CLI_OK;
	}
	
	strncpy (clipkt->packet_name, "sysFlood_TCPSYN", 15);
	// OK, created a new packet
	cli_print(cli, "Allocated new packet %s at slot %i",clipkt->packet_name, clipkt->id);
	mops_set_defaults(clipkt);
	clipkt->use_ETHER = 1;
	clipkt->use_IP  = 1;
	clipkt->use_TCP  = 1;
	clipkt->ip_proto = 6;
	clipkt->count = 0;
	clipkt->ip_dst = str2ip32(argv[0]);
	clipkt->ip_src_israndom=1;
	if (valid_port) {
		clipkt->dp = valid_port;
	} else {
		clipkt->dp_isrange=1;
		clipkt->dp_start=1;
		clipkt->dp_stop=1023;
	}
	clipkt->ndelay.tv_sec  = 0;
	clipkt->ndelay.tv_nsec = 0;
	mops_set_conf(clipkt);
	mops_tcp_add_option (clipkt,64,0,0,0,0);
	if (mops_tx_simple (clipkt)) {
		cli_print(cli, "Cannot create sending process.\r");
	}

	return CLI_OK;
}

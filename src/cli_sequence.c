/*
 * Mausezahn - A fast versatile traffic generator
 * Copyright (C) 2010 Herbert Haas
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

// PURPOSE: Enter sequence configuration mode 
// either a) create new or b) edit old or c) delete old sequence
// 
// # sequence MY_SEQUENCE
// # sequence OLD_SEQUENCE delete
// 
int conf_sequence (struct cli_def *cli, char *command, char *argv[], int argc)
{
	struct mz_ll *cur;
	char str[512];
	int ret=0;
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc<1) || (argc>2)) {

		cli_print(cli, "Configure a sequence of packets.\n");
		cli_print(cli, "ARGUMENTS: <sequence_name> [delete]\n");
		
		cli_print(cli, "Current list of packet sequences:\n");
		while (mops_dump_sequence(str)) cli_print(cli, "%s\r", str);
		return CLI_OK;
	}

	switch (argc) {
	 case 1:
		cur = mz_ll_search_name (packet_sequences, argv[0]);
		if (cur==NULL) { // create NEW sequence
			cli_print(cli, "Sequence does not exist; creating new sequence named '%s'\n", argv[0]);
			cur = mops_create_sequence(argv[0]);
			if (cur==NULL) {
				cli_print(cli, "ERROR: Cannot allocate another sequence!\n");
				return CLI_OK;
			}
		} // else ENTER EXISTING (cur already points to it)
		cli_seq = cur;
		cli_set_configmode(cli, MZ_MODE_SEQUENCE, "config-seq");
		break;
		
	 case 2: // otherwise DELETE?
		if (mz_strcmp(argv[1], "delete", 3)==0) {
			ret = mops_delete_sequence(argv[0]);
			switch (ret) {
			 case 1:
				cli_print(cli, "Sequence '%s' does not exist\n", argv[0]);
				break;
			 case 2: 
				cli_print(cli, "Sequence '%s' is currently active! Cannot delete it.\n", argv[0]);
				break;
			 default:
				cli_print(cli, "Sequence '%s' deleted.\n", argv[0]);
			}
		}
		break;
	 default:
		// nothing
		break;
	}
	return CLI_OK;
}


// add packet to current sequence
int sequence_add (struct cli_def *cli, char *command, char *argv[], int argc)
{
	struct mops *mp;
	int ret=0;
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc!=1) ) {

		cli_print(cli, "Add a packet to the current sequence.\n");
		cli_print(cli, "ARGUMENT: <packet name> OR <packet-identifier>\n");
		return CLI_OK;
	}

	// first assume argument is a name
	mp = mops_search_name (mp_head, argv[0]); 
	if (mp==NULL) { // but packet name does not exist
		if (mz_strisnum(argv[0])!=0) // arg is really a number?
			mp = mops_search_id (mp_head, (int) str2int(argv[0]));
		if (mp==NULL) { // also packet ID not found
			cli_print(cli, "Packet does not exist!\n");
			return CLI_OK;
		}
	}
	
	// packet found, so add to current sequence
	ret = mops_add_packet_to_sequence (cli_seq, mp);
	if (ret==1) cli_print(cli, "Cannot add packet (unknown error, maybe report this)!\n");
	if (ret==-1) cli_print(cli, "Cannot add packet: sequence already full!\n");
	if (ret==-2) cli_print(cli, "Cannot add packet with infinite count!\n");
	return CLI_OK;
}


// add a delay
int sequence_delay (struct cli_def *cli, char *command, char *argv[], int argc)
{
	int ret=0, ret2=0;
	struct timespec t;
	char str[128];
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc<1) || (argc>2)) {
		cli_print(cli, "Add a delay to the current sequence.\n");
		cli_print(cli, "ARGUMENTS:  <delay> [hour | min | sec | msec | usec | nsec]\n");
		cli_print(cli, "The default unit is milliseconds (i. e. when no unit is given).\n");
		return CLI_OK;
	}
	
	switch (argc) {
	 case 1:  // only one argument, but may contain an unit (such as '314sec')
		ret = delay_parse(&t, argv[0], NULL);
		break;
		
	 case 2: // user specified two arguments such as '100 msec'
		ret = delay_parse(&t, argv[0], argv[1]);
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
	

	ret2 = mops_add_delay_to_sequence (cli_seq, &t);
	if (ret2==-1) { 
		cli_print(cli, "You must add a packet first.\n");
		return CLI_OK;
	}
	if (ret2==-2) { 
		cli_print(cli, "Cannot add delay (array full).\n");
		return CLI_OK;
	}
	
	sprintf(str, "Delay set to %lu sec and %lu nsec", 
		((struct pseq*) cli_seq->data)->gap[ret2].tv_sec,
		((struct pseq*) cli_seq->data)->gap[ret2].tv_nsec);
	cli_print(cli, "%s\n", str);
	
	return CLI_OK;
}


// remove one packet
int sequence_remove (struct cli_def *cli, char *command, char *argv[], int argc)
{
	int ret=0;
	int i=0;
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc!=1)) {
		cli_print(cli, "Remove a packet (and any associated pause configuration) from the current sequence.\n");
		cli_print(cli, "ARGUMENT: <sequence-list-index> | last | all\n");
		cli_print(cli, "FYI: Use the 'show' command to see the current packet list with indexes.\n");
		return CLI_OK;
	}

	if (mz_strcmp(argv[0], "last", 1)==0) {
		 ret = mops_delete_packet_from_pseq (cli_seq, -1);
	} else if (mz_strcmp(argv[0], "all", 1)==0) {
		ret = mops_delete_all_packets_from_pseq (cli_seq);
		i=1;
	} else { // index number given
		if (mz_strisnum(argv[0])==0) {
			cli_print(cli, "Invalid parameter. Please specify a packet index number or 'last'\n");
			return CLI_OK;
		}
		ret = mops_delete_packet_from_pseq (cli_seq, (int) str2int(argv[0]));
	}
	switch (ret) {
	 case 0: 
		if (i) cli_print(cli, "Removed all entries.\n");
		else cli_print(cli, "Removed one entry.\n");
		break;
	 case 1:
		cli_print(cli, "List empty or invalid packet index.\n");
		break;
	 case 2:
		cli_print(cli, "Packet index too large.\n");
		break;

	}
	return CLI_OK;
}


// show packet list of that sequence
int sequence_show (struct cli_def *cli, char *command, char *argv[], int argc)
{
	char str[512], name[32], layers[16], proto[16];
	struct pseq *seq;
	int i;
	
	if  (strcmp(argv[argc-1],"?")==0)  {
		cli_print(cli, "Shows all packets of the current sequence.\n");
		return CLI_OK;
	}

	if (argc>0) {
		cli_print(cli, "This command has currently no arguments!\n");
		return CLI_OK;
	}
	
	seq = (struct pseq*) cli_seq->data;
	
	if (seq->count==0) {
		cli_print(cli, "Current sequence '%s' has no entries.\n", cli_seq->name);
	}
	else { // show all packets in this sequence
		cli_print(cli, "%i sequence(s) defined.\r", packet_sequences->refcount-1);                 // total info
		snprintf(str,512, "Current sequence '%s' has %i entries:", cli_seq->name, seq->count);    // num entries here
		cli_print(cli, "%s\n", str);
		cli_print(cli, "Nr  PId  PktName          Layers  Protocol  Device");
		for (i=0; i<seq->count; i++) { 
			strncpy (name, seq->packet[i]->packet_name, 13); // only show first 13 chars
			if (strnlen(seq->packet[i]->packet_name, MAX_MOPS_PACKET_NAME_LEN)>13) {
				name[13]=0x00;        
				strcat(name, "...");
			}
			mops_get_proto_info(seq->packet[i], layers, proto);
			snprintf(str,512, "%2i %4i  %-16s %s  %-8s  %-6s", i+1, seq->packet[i]->id, name, layers, proto, seq->packet[i]->device);
			cli_print(cli, "%s\r", str);
			if ((seq->gap[i].tv_sec !=0) || (seq->gap[i].tv_nsec !=0)) { // gap also defined?
				timespec2str(&seq->gap[i], str);
				cli_print(cli, "  \\___ %s pause ___/\r", str);
			}
		}
	}
	return CLI_OK;
}



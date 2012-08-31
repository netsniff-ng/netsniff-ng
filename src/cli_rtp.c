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


int cmd_rtp_version (struct cli_def *cli, char *command, char *argv[], int argc)
{
	struct mops_ext_rtp * pd = clipkt->p_desc;
	int v=2;

	if ( (strcmp(argv[argc-1],"?")==0) || (argc!=1)) {
		cli_print(cli, "Set the RTP version (0..3, default: v2).\n");
		return CLI_OK;
	}
	if (mz_strisnum(argv[0])==0) {
		cli_print(cli, "Invalid number.\n");
		return CLI_OK;
	}
	v = (int) str2int(argv[0]);
	if (v>3) {
		cli_print(cli, "Range exceeded (0..3).\n");
		return CLI_OK;
	}
	pd->v = v;
	return CLI_OK;
}

int cmd_rtp_padding (struct cli_def *cli, char *command, char *argv[], int argc)
{
	struct mops_ext_rtp * pd = clipkt->p_desc;
	char state[8];

	if ( (strcmp(argv[argc-1],"?")==0) || (argc!=1)) {
		cli_print(cli, "Sets or unsets the RTP padding flag (default: disabled).\n");
		cli_print(cli, "Use the keywords 'set' or 'unset'.\n");
		sprintf(state, "%s", (pd->p) ? "SET" : "UNSET");
		cli_print(cli, "Current state of the padding flag: %s\n",state);
		return CLI_OK;
	}
	
	if (mz_strcmp(argv[0], "set", 1)==0) {
		pd->p = 1;
	} else 	if (mz_strcmp(argv[0], "unset", 1)==0) {
		pd->p = 0;
	}
	else {
		cli_print(cli, "Invalid keyword. Use 'set' or 'unset'.\n");
	}
		
	return CLI_OK;
}

int cmd_rtp_xten (struct cli_def *cli, char *command, char *argv[], int argc)
{
	struct mops_ext_rtp * pd = clipkt->p_desc;
	char state[8];

	if ( (strcmp(argv[argc-1],"?")==0) || (argc!=1)) {
		cli_print(cli, "Sets or unsets the RTP extension flag (default: disabled).\n");
		cli_print(cli, "NOTE: This command only sets the extension flag in the RTP header.\r");
		cli_print(cli, "If you really want an extension header use the 'extension' command.\n");
		cli_print(cli, "Use the keywords 'set' or 'unset'.\n");
		sprintf(state, "%s", (pd->x) ? "SET" : "UNSET");
		cli_print(cli, "Current state of the extension flag: %s\n",state);
		return CLI_OK;
	}
	
	if (mz_strcmp(argv[0], "set", 1)==0) {
		pd->x = 1;
	} else 	if (mz_strcmp(argv[0], "unset", 1)==0) {
		pd->x = 0;
	}
	else {
		cli_print(cli, "Invalid keyword. Use 'set' or 'unset'.\n");
	}
		
	return CLI_OK;
}


int cmd_rtp_marker (struct cli_def *cli, char *command, char *argv[], int argc)
{
	struct mops_ext_rtp * pd = clipkt->p_desc;
	char state[8];

	if ( (strcmp(argv[argc-1],"?")==0) || (argc!=1)) {
		cli_print(cli, "Sets or unsets the RTP marker flag (default: disabled).\n");
		cli_print(cli, "Use the keywords 'set' or 'unset'.\n");
		sprintf(state, "%s", (pd->m) ? "SET" : "UNSET");
		cli_print(cli, "Current state of the marker flag: %s\n",state);
		return CLI_OK;
	}
	if (mz_strcmp(argv[0], "set", 1)==0) {
		pd->m = 1;
	} else 	if (mz_strcmp(argv[0], "unset", 1)==0) {
		pd->m = 0;
	}
	else {
		cli_print(cli, "Invalid keyword. Use 'set' or 'unset'.\n");
	}
	return CLI_OK;
}


int cmd_rtp_cc (struct cli_def *cli, char *command, char *argv[], int argc)
{
	struct mops_ext_rtp * pd = clipkt->p_desc;
	int cc=0;

	if ( (strcmp(argv[argc-1],"?")==0) || (argc!=1)) {
		cli_print(cli, "Configure the RTP CSRC count (0..15, default: 0).\n");
		cli_print(cli, "NOTE: This command only configures the CSRC value in the RTP header.\r");
		cli_print(cli, "If you want to add a valid CSRC list use the 'csrc-list' command.\r");
		cli_print(cli, "The main purpose of this command is to create an invalid RTP packet.\r");
		return CLI_OK;
	}
	if (mz_strisnum(argv[0])==0) {
		cli_print(cli, "Invalid number.\n");
		return CLI_OK;
	}
	cc = (int) str2int(argv[0]);
	if (cc>15) {
		cli_print(cli, "Range exceeded (0..15).\n");
		return CLI_OK;
	}
	pd->cc = cc;
	return CLI_OK;
}


int cmd_rtp_pt (struct cli_def *cli, char *command, char *argv[], int argc)
{
	struct mops_ext_rtp * pd = clipkt->p_desc;
	int pt=0;

	if ( (strcmp(argv[argc-1],"?")==0) || (argc!=1)) {
		cli_print(cli, "Configure the RTP payload type (0..127, default: 8 (G.711, A-law)).\n");
		// TODO: provide a list with well-known PT values
		return CLI_OK;
	}
	if (mz_strisnum(argv[0])==0) {
		cli_print(cli, "Invalid number.\n");
		return CLI_OK;
	}
	pt = (int) str2int(argv[0]);
	if (pt>127) {
		cli_print(cli, "Range exceeded (0..127).\n");
		return CLI_OK;
	}
	pd->pt = pt;
	return CLI_OK;
}

int cmd_rtp_ssrc (struct cli_def *cli, char *command, char *argv[], int argc)
{
	struct mops_ext_rtp * pd = clipkt->p_desc;
	unsigned long long int ssrc = 0xcafefeed;

	if ( (strcmp(argv[argc-1],"?")==0) || (argc!=1)) {
		cli_print(cli, "Configure the RTP SSRC (source identifier) (0..ffffffff, default: random!).\n");
		cli_print(cli, "NOTE: The SSRC value is used by another Mausezahn receiver to identify a original\r");
		cli_print(cli, "Mausezahn RTP stream. By default, Mausezahn receivers check for the magic number\r");
		cli_print(cli, "'cafebabe' (hex). Use another number for another RTP stream (e. g. bidirectional\r");
		cli_print(cli, "measurements).\n");
		return CLI_OK;
	}
	
	if (mz_strishex(argv[0])==0) {
		cli_print(cli, "Invalid number.\n");
		return CLI_OK;
	}
	
	ssrc =  xstr2lint(argv[0]);
	if (ssrc>0xffffffff) {
		cli_print(cli, "Range exceeded (0..ffffffff).\n");
		return CLI_OK;
	}
	pd->ssrc = (u_int32_t) ssrc;
	return CLI_OK;
}


int cmd_rtp_sqnr (struct cli_def *cli, char *command, char *argv[], int argc)
{
	struct mops_ext_rtp * pd = clipkt->p_desc;
	unsigned long long int sqnr = 0;

	if ( (strcmp(argv[argc-1],"?")==0) || (argc!=1)) {
		cli_print(cli, "Configure the RTP initial sequence number (0..ffffffff, default: 0).\n");
		return CLI_OK;
	}
	
	if (mz_strishex(argv[0])==0) {
		cli_print(cli, "Invalid number.\n");
		return CLI_OK;
	}
	sqnr =  xstr2lint(argv[0]);
	if (sqnr>0xffffffff) {
		cli_print(cli, "Range exceeded (0..ffffffff).\n");
		return CLI_OK;
	}
	pd->sqnr = (u_int32_t) sqnr;
	return CLI_OK;
}


int cmd_rtp_time (struct cli_def *cli, char *command, char *argv[], int argc)
{
	struct mops_ext_rtp * pd = clipkt->p_desc;
	unsigned long long int t = 0;

	if ( (strcmp(argv[argc-1],"?")==0) || (argc!=1)) {
		cli_print(cli, "Configure the RTP initial timestamp (0..ffffffff, default: 0).\n");
		return CLI_OK;
	}
	
	if (mz_strishex(argv[0])==0) {
		cli_print(cli, "Invalid number.\n");
		return CLI_OK;
	}
	t =  xstr2lint(argv[0]);
	if (t>0xffffffff) {
		cli_print(cli, "Range exceeded (0..ffffffff).\n");
		return CLI_OK;
	}
	pd->tst = (u_int32_t) t;
	return CLI_OK;
}


int cmd_rtp_extension (struct cli_def *cli, char *command, char *argv[], int argc)
{
	struct mops_ext_rtp * pd = clipkt->p_desc;

	if ( (strcmp(argv[argc-1],"?")==0) || (argc!=1)) {
		cli_print(cli, "Configure an RTP extension header (default: none).\n");
		cli_print(cli, "Currently supported RTP extension headers:\n");
		cli_print(cli, "none          Don't use any extension.\r");
		cli_print(cli, "mausezahn     Use the new Mausezahn jitter/RTT measurement extension.\r");
		cli_print(cli, "              (Note that this is incompatible with Mausezahn's direct\r");
		cli_print(cli, "              mode jitter measurement.)\r");
		cli_print(cli, "\n");
		return CLI_OK;
	}

	if (mz_strcmp(argv[0], "none", 1)==0) {
		pd->x_type = 0;
		pd->x = 0; // X bit in header
	} else 	if (mz_strcmp(argv[0], "mausezahn", 1)==0) {
		pd->x_type = 42;
		pd->x = 1; // X bit in header
		pd->ssrc = 0xcafefeed;
	} else {
		cli_print(cli, "Unknown keyword.\n");
		return CLI_OK;
		
	}

	mops_update_rtp (clipkt); // re-build RTP packet (for proper show commands)
	return CLI_OK;
}



int cmd_rtp_source (struct cli_def *cli, char *command, char *argv[], int argc)
{
//	struct mops_ext_rtp * pd = clipkt->p_desc;

	if ( (strcmp(argv[argc-1],"?")==0) || (argc!=1)) {
		cli_print(cli, "Specify a RTP media source.\n");
		return CLI_OK;
	}
	
	// [TODO] -- Allow to use /dev/dsp or a mixer source ...
	// 
	cli_print(cli, "Currently not supported.\n");
	
	return CLI_OK;
}


int cmd_rtp_cclist (struct cli_def *cli, char *command, char *argv[], int argc)
{
	struct mops_ext_rtp * pd = clipkt->p_desc;
	unsigned long long int csrc=0;
	char str[80];
	int i=0, n=0;

	
	if ((strcmp(argv[argc-1],"?")==0) || (argc==0)) {
		cli_print(cli, "Specify a CSRC list consisting of 1-15 CSRC values.\r");
		cli_print(cli, "Each CSRC is a 4-byte value and must be specified in hexadecimal notation,\r");
		cli_print(cli, "hence each value must be within 0..ffffffff.\n");
		return CLI_OK;
	}
	
	if ((n=argc)>15) {
		cli_print(cli, "The CSRC list must not exceed 15 items!\n");
		return CLI_OK;
	}
	
	for (i=0; i<n; i++) {
		if (mz_strishex(argv[i])==0) {
			sprintf(str, "Parameter %i: Invalid number!", i);
			cli_print(cli, "%s\n", str);
			return CLI_OK;
		}
		csrc =  xstr2lint(argv[i]);
		if (csrc>0xffffffff) {
			sprintf(str, "Parameter %i: Range exceeded (0..ffffffff)", i);
			cli_print(cli, "%s\n", str);
			return CLI_OK;
		}
		pd->csrc[i] = (u_int32_t) csrc;
	}
	pd->cc = n; // this one can be accessed and modified to "wrong" values by the user
	pd->cc_real = n;
	
	return CLI_OK;
}




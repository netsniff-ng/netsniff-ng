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


int cmd_lldp_conformance (struct cli_def *cli, char *command, char *argv[], int argc)
{
	struct mops_ext_lldp * pd = clipkt->p_desc;
	

	if ( (strcmp(argv[argc-1],"?")==0) || (argc!=1)) {
		cli_print(cli, "Enables or disables LLDP standard conformance mode.\n");
		cli_print(cli, "Keywords: enable | disable\n");
		cli_print(cli, "Per default, standard LLDP messages are created which require a fixed\r");
		cli_print(cli, "order of the mandatory TLVs. If the standard conformance mode is disabled\r");
		cli_print(cli, "then you can configure an arbitrary sequence of LLDP TLVs. \n");
		cli_print(cli, "Currently, the LLDP standard conformance mode is %s\n", (pd->non_conform) ? "DISABLED" : "ENABLED");
		return CLI_OK;
	}

	if (mz_strcmp(argv[0], "enable", 1)==0) {
		pd->non_conform = 0;
		return CLI_OK;
	}
	

	if (mz_strcmp(argv[0], "disable", 1)==0) {
		pd->non_conform = 1;
		return CLI_OK;
	}
	
	cli_print(cli, "Enter enable or disable\n");
	return CLI_OK;
}


int cmd_lldp_chassis_id (struct cli_def *cli, char *command, char *argv[], int argc)
{
	struct mops_ext_lldp * pd = clipkt->p_desc;
	int subtype = 4;
	char *cid;
	int cl, cidl;
	u_int8_t tmp[512];
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc>2)) {
		cli_print(cli, "Configure a Chassis ID TLV.\n");
		cli_print(cli, "ARGUMENTS: [<subtype>] <chassis-id>\n");
		cli_print(cli, "By default the <subtype> is of kind 'mac address (4)' and the <chassis-id>\r");
		cli_print(cli, "must be a hexadecimal string (e. g. 00:01:ca:fe:de:ad) of max 255 bytes\n");
		return CLI_OK;
	}

	if (argc==2) {
		subtype = (int) str2int(argv[0]);
		if ((subtype>255) || (mz_strisnum(argv[0])==0)) {
			cli_print(cli, "Invalid subtype\n");
			return CLI_OK;
		}
		cid = argv[1];
	} else
		cid = argv[0];

	cl=strnlen(cid, 1024);
	
	if (cl>=1024) {
		cli_print(cli, "Chassis-ID too long\n");
		return CLI_OK;
	} else cidl=str2hex(cid, tmp, 511);

	if (pd->non_conform == 0) {
		pd->chassis_id_subtype = subtype; 
		memcpy((void*) pd->chassis_id, (void*)tmp, cidl);
		pd->chassis_id_len = cidl;
	} else { 
		// non_conform
		mops_lldp_opt_tlv_chassis (clipkt, subtype, cidl, tmp);
	}

	return CLI_OK;
}




int cmd_lldp_port_id (struct cli_def *cli, char *command, char *argv[], int argc)
{
	struct mops_ext_lldp * pd = clipkt->p_desc;
	int subtype = 4;
	char *pid;
	int pl;
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc>2)) {
		cli_print(cli, "Configure a Port ID TLV.\n");
		cli_print(cli, "ARGUMENTS: [<subtype>] <port-id>\n");
		cli_print(cli, "By default the <subtype> is of kind 'Interface name (5)' and the <port-id>\r");
		cli_print(cli, "must be a ascii string (usually the name of the interface e. g. eth3) of\r");
		cli_print(cli, "max 255 bytes.\n");
		return CLI_OK;
	}

	if (argc==2) {
		subtype = (int) str2int(argv[0]);
		if ((subtype>255) || (mz_strisnum(argv[0])==0)) {
			cli_print(cli, "Invalid subtype\n");
			return CLI_OK;
		}
		pid = argv[1];
	} else
		pid = argv[0];

	pl=strnlen(pid, 256);
	
	if (pl>255) {
		cli_print(cli, "Port-ID too long\n");
		return CLI_OK;
	} 


	if (pd->non_conform == 0) {
		pd->port_id_subtype = subtype; 
		memcpy((void*) pd->port_id, (void*) pid, pl);
		pd->port_id_len = pl;
	} else { 
		// non_conform
		mops_lldp_opt_tlv_port (clipkt, subtype, pl, (u_int8_t*) pid);
	}

	return CLI_OK;
}



int cmd_lldp_ttl (struct cli_def *cli, char *command, char *argv[], int argc)
{
	struct mops_ext_lldp * pd = clipkt->p_desc;
	int ttl;
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc!=1)) {
		cli_print(cli, "Configure the LLDP TTL.\n");
		cli_print(cli, "ARGUMENTS: <time-to-live>\n");
		cli_print(cli, "The TTL must be within 0..65535\n");
		return CLI_OK;
	}

	ttl = (int) str2int(argv[0]);
	
	if (mz_strisnum(argv[0])==0) {
		cli_print(cli, "Invalid argument\n");
		return CLI_OK;
	}

	if (ttl>0xffff) {
		cli_print(cli, "TTL must be within 0..65535\n");
		return CLI_OK;
	}

	if (pd->non_conform == 0) {
		pd->TTL = ttl;
	} else { 
		// non_conform
		mops_lldp_opt_tlv_TTL (clipkt, ttl);
	}

	return CLI_OK;
}



int cmd_lldp_vlan (struct cli_def *cli, char *command, char *argv[], int argc)
{
	int vlan;
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc!=1)) {
		cli_print(cli, "Configure the LLDP Port VLAN-ID.\n");
		cli_print(cli, "ARGUMENTS: <vlan-id>\n");
		cli_print(cli, "The vlan-id must be within 0..65535\n");
		return CLI_OK;
	}

	vlan = (int) str2int(argv[0]);
	
	if (mz_strisnum(argv[0])==0) {
		cli_print(cli, "Invalid argument\n");
		return CLI_OK;
	}

	if (vlan>0xffff) {
		cli_print(cli, "The VLAN-ID must be within 0..65535\n");
		return CLI_OK;
	}

	
	mops_lldp_opt_tlv_vlan (clipkt, vlan);

	return CLI_OK;
}



int cmd_lldp_opt_tlv (struct cli_def *cli, char *command, char *argv[], int argc)
{
	int type=0, len=0;
	u_int8_t tmp[512];
	
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc!=3)) {
		cli_print(cli, "Configure an arbitrary optional TLV.\n");
		cli_print(cli, "ARGUMENTS: ascii|hex <type> <value>\n");
		cli_print(cli, "The TLV type must be between 0..127, the value length is up to 511 bytes.\n");
		return CLI_OK;
	}

	
	if (mz_strcmp(argv[0], "ascii", 1)==0) {
		if ((len=strnlen(argv[2],512))>511) {
			cli_print(cli, "<value> must be smaller or equal 511 characters\n");
			return CLI_OK;
		}
		mz_strncpy((char*) tmp, argv[2], 511);
	} else if (mz_strcmp(argv[0], "hex", 1)==0) {
		len=str2hex(argv[2], tmp, 512);
		if (len>511) {
			cli_print(cli, "<value> must be smaller or equal 511 bytes\n");
			return CLI_OK;
		}
	}
	
	type = (int) str2int(argv[1]);
	
	if (mz_strisnum(argv[1])==0) {
		cli_print(cli, "Invalid type\n");
		return CLI_OK;
	}

	if (type>127) {
		cli_print(cli, "<type> must be within 0..127\n");
		return CLI_OK;
	}

	
	if (mops_lldp_opt_tlv (clipkt, type, len, tmp)==0)
		cli_print(cli, "Invalid TLV values\n");

	return CLI_OK;
}




int cmd_lldp_opt_tlv_bad (struct cli_def *cli, char *command, char *argv[], int argc)
{
	int type, len=0, wronglen;
	u_int8_t tmp[512];
	
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc!=4)) {
		cli_print(cli, "Configure an arbitrary optional *BAD* TLV.\n");
		cli_print(cli, "ARGUMENTS: ascii|hex <type> <wrong-length> <value>\n");
		cli_print(cli, "Using this command you can add a custom TLV with a wrong length parameter.\r");
		cli_print(cli, "Such TLV can be used to verify whether LLDP receivers are robust enough\r\r");
		cli_print(cli, "since a too small <wrong-length> could cause a buffer overflow. The TLV type\r");
		cli_print(cli, "must be between 0..127, the <wrong-length> can be within 0..511 (and can be\r");
		cli_print(cli, "also the true length of course\n");
		return CLI_OK;
	}

	
	if (mz_strcmp(argv[0], "ascii", 1)==0) {
		if ((len=strnlen(argv[3],512))>511) {
			cli_print(cli, "<value> must be smaller or equal 511 characters\n");
			return CLI_OK;
		}
		mz_strncpy((char*) tmp, argv[3], 511);
	} else if (mz_strcmp(argv[0], "hex", 1)==0) {
		len=str2hex(argv[3], tmp, 512);
		if (len>511) {
			cli_print(cli, "<value> must be smaller or equal 511 bytes\n");
			return CLI_OK;
		}
	}
	
	type = (int) str2int(argv[1]);
	
	if (mz_strisnum(argv[1])==0) {
		cli_print(cli, "Invalid type\n");
		return CLI_OK;
	}

	if (type>127) {
		cli_print(cli, "<type> must be within 0..127\n");
		return CLI_OK;
	}

	wronglen = (int) str2int(argv[2]);
	
	if (mz_strisnum(argv[2])==0) {
		cli_print(cli, "Invalid length\n");
		return CLI_OK;
	}

	if (wronglen>511) {
		cli_print(cli, "<wrong-length> must be within 0..511\n");
		return CLI_OK;
	}

	if (mops_lldp_opt_tlv_bad (clipkt, type, wronglen, len, tmp)==0)
		cli_print(cli, "Invalid TLV values\n");

	return CLI_OK;
}



int cmd_lldp_opt_org (struct cli_def *cli, char *command, char *argv[], int argc)
{
	int subtype, len=0, oui=0;
	u_int8_t tmp[512];
	
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc!=4)) {
		cli_print(cli, "Configure an organisational TLV.\n");
		cli_print(cli, "ARGUMENTS: ascii|hex <oui> <subtype> <value>\n");
		cli_print(cli, "Using this command you can add an arbitrary organisational TLV. The <oui> represents\r");
		cli_print(cli, "the 'Organisational Unique Identifier' and consists of exactly three bytes in hexadecimal\r");
		cli_print(cli, "format, such as '00005e' The <subtype> is a value between <0..255>, and the length of the\r");
		cli_print(cli, "value is up to 507 bytes.\n");
		return CLI_OK;
	}

	
	if (mz_strcmp(argv[0], "ascii", 1)==0) {
		if ((len=strnlen(argv[3],512))>511) {
			cli_print(cli, "<value> must be smaller or equal 511 characters\n");
			return CLI_OK;
		}
		mz_strncpy((char*) tmp, argv[3], 511);
	} else if (mz_strcmp(argv[0], "hex", 1)==0) {
		len=str2hex(argv[3], tmp, 512);
		if (len>511) {
			cli_print(cli, "<value> must be smaller or equal 511 bytes\n");
			return CLI_OK;
		}
	}

	oui = xstr2int(argv[1]);
	if (mz_strishex(argv[1])==0) {
		cli_print(cli, "Invalid oui value\n");
		return CLI_OK;
	}

	if (oui>0xffffff) {
		cli_print(cli, "<oui> must be within 0..ffffff\n");
		return CLI_OK;
	}
	
	subtype = (int) str2int(argv[2]);
	
	if (mz_strisnum(argv[2])==0) {
		cli_print(cli, "Invalid subtype\n");
		return CLI_OK;
	}

	if (subtype>255) {
		cli_print(cli, "<subtype> must be within 0..255\n");
		return CLI_OK;
	}


	if (mops_lldp_opt_tlv_org (clipkt, oui, subtype, len, tmp)==0)
		cli_print(cli, "Invalid TLV values\n");

	return CLI_OK;
}





int cmd_lldp_endtlv (struct cli_def *cli, char *command, char *argv[], int argc)
{
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc>0)) {
		cli_print(cli, "Add an 'End of LLDP' TLV\n");
		cli_print(cli, "ARGUMENTS: none\n");
		cli_print(cli, "This command allows you to insert an 'End of LLDP' TLV at any\r");
		cli_print(cli, "point within the optional TLV list. You usually want this to\r");
		cli_print(cli, "create an invalid LLDPU to test the receiver.\n");
		return CLI_OK;
	}

	
	mops_lldp_opt_tlv_end (clipkt);

	return CLI_OK;
}


int cmd_lldp_reset (struct cli_def *cli, char *command, char *argv[], int argc)
{
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc>0)) {
		cli_print(cli, "Reset the LLPDU and clear all optional TLVs.\n");
		cli_print(cli, "ARGUMENTS: none\n");
		cli_print(cli, "All optional TLVs are added in the sequence as you configure them.\r");
		cli_print(cli, "Use this command to reset the LLDP and reconfigure all optional\r");
		cli_print(cli, "TLVs again. Additionally the parameters of the mandatory TLVs are\r");
		cli_print(cli, "reset to defaults.\n");
		return CLI_OK;
	}

	mops_init_pdesc_lldp(clipkt);
	
	return CLI_OK;
}




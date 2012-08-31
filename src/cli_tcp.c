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



// NOTE: The port numbers are maintained for both TCP and UDP.
//       See cli_udp.c.


int cmd_tcp_seqnr (struct cli_def *cli, char *command, char *argv[], int argc)
{
	u_int32_t txs;
	unsigned long long int tmp;
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc>3) ) {
		cli_print(cli, "Specify the TCP sequence number (0-4294967295)\n");
		cli_print(cli, "You may specify up to three parameters:\n");
		cli_print(cli, "  <sqnr>\r");
		cli_print(cli, "  <sqnr_start> <sqnr_stop>\r");
		cli_print(cli, "  <sqnr_start> <sqnr_stop> <sqnr_delta>\n");
		cli_print(cli, "If a range is specified without step size 'sqnr_delta' (2nd case)\r");
		cli_print(cli, "then sqnr_delta is per default set to one.\r");
		cli_print(cli, "\n");
		return CLI_OK;
	}
   
	tmp = str2lint(argv[0]);
	if (tmp<=0xffffffff)
		clipkt->tcp_seq = (u_int32_t) tmp;
	else {
		cli_print(cli, "Argument 1 must not exceed 4294967295\n");
		return CLI_OK;
	}
	clipkt->tcp_seq_delta = 0;
	
	if (argc>1) { 
		tmp = str2lint(argv[1]);
		if (tmp<=0xffffffff) {
			clipkt->tcp_seq_start = clipkt->tcp_seq;
			clipkt->tcp_seq_stop = (u_int32_t) tmp;
		} else	{
			cli_print(cli, "Argument 2 must not exceed 4294967295\n");
			return CLI_OK;
		}
		clipkt->tcp_seq_delta = 1;
	}
	
	if (argc>2) {
		tmp = str2lint(argv[2]);
		if (tmp<=0xffffffff) {
			clipkt->tcp_seq_delta = (u_int32_t) tmp;
		} else {
			cli_print(cli, "Argument 3 must not exceed 4294967295\n");
			return CLI_OK;
		}
		
		if (argv[2]==0) {
			cli_print(cli, "Note that a zero step size disables the range feature\n");
			return CLI_OK;
		}
	}
   
	txs = mops_tcp_complexity_sqnr (clipkt);
	cli_print(cli, "FYI: Packet runs through %lu sequence numbers\n", (long unsigned int) txs);
   
	return CLI_OK;
}





int cmd_tcp_acknr (struct cli_def *cli, char *command, char *argv[], int argc)
{
	u_int32_t txs;
	unsigned long long int tmp;
   
	if ( (strcmp(argv[argc-1],"?")==0) || (argc>3) ) {
		cli_print(cli, "Specify the TCP acknowledgement number (0-4294967295)\n");
		cli_print(cli, "You may specify up to three parameters:\n");
		cli_print(cli, "  <acknr>\r");
		cli_print(cli, "  <acknr_start> <acknr_stop>\r");
		cli_print(cli, "  <acknr_start> <acknr_stop> <acknr_delta>\n");
		cli_print(cli, "If a range is specified without step size 'acknr_delta' (2nd case)\r");
		cli_print(cli, "then acknr_delta is per default set to one.\r");
		cli_print(cli, "\n");
		return CLI_OK;
	}

	tmp = str2lint(argv[0]);
	if (tmp<=0xffffffff)
		clipkt->tcp_ack = (u_int32_t) tmp;
	else {
		cli_print(cli, "Argument 1 must not exceed 4294967295\n");
		return CLI_OK;
	}
	clipkt->tcp_ack_delta = 0;
	
	if (argc>1) { 
		tmp = str2lint(argv[1]);
		if (tmp<=0xffffffff) {
			clipkt->tcp_ack_start = clipkt->tcp_ack;
			clipkt->tcp_ack_stop = (u_int32_t) tmp;
		} else	{
			cli_print(cli, "Argument 2 must not exceed 4294967295\n");
			return CLI_OK;
		}
		clipkt->tcp_ack_delta = 1;
	}
	
	if (argc>2) {
		tmp = str2lint(argv[2]);
		if (tmp<=0xffffffff) {
			clipkt->tcp_ack_delta = (u_int32_t) tmp;
		} else {
			cli_print(cli, "Argument 3 must not exceed 4294967295\n");
			return CLI_OK;
		}
		
		if (argv[2]==0) {
			cli_print(cli, "Note that a zero step size disables the range feature\n");
			return CLI_OK;
		}
	}
   
	txs = mops_tcp_complexity_acknr (clipkt);
	cli_print(cli, "FYI: Packet runs through %lu acknowledge numbers\n", (long unsigned int) txs);
 
   
   return CLI_OK;
}






int cmd_tcp_offset (struct cli_def *cli, char *command, char *argv[], int argc)
{
   unsigned int tmp;
   
   if ( (strcmp(argv[argc-1],"?")==0) || (argc>1) )
     {
	cli_print(cli, "Specify the TCP offset (=header length, 0..15) \r");
	cli_print(cli, "\n");
	return CLI_OK;
     }
   
   tmp = (unsigned int) str2int(argv[0]);
   if (tmp<=15)
     clipkt->tcp_offset = (u_int8_t) tmp;
   else
     {
	cli_print(cli, "The TCP offset must not exceed 15\n");
     }
     
   return CLI_OK;
}




int cmd_tcp_res (struct cli_def *cli, char *command, char *argv[], int argc)
{
   int tmp;
   
   if ( (strcmp(argv[argc-1],"?")==0) || (argc>1) )
     {
	cli_print(cli, "Specify the TCP reserved field in binary format (4 bits)\n");
	cli_print(cli, "\n");
	return CLI_OK;
     }
   
   tmp = str2bin8 (argv[0]);
   if ((tmp==-1)||(tmp>15))
     {
	cli_print(cli, "Invalid binary value! Allowed range: 0000 - 1111\n");
     }
   else
     clipkt->tcp_res = (u_int8_t) tmp;     

   return CLI_OK;
}


int cmd_tcp_flags (struct cli_def *cli, char *command, char *argv[], int argc)
{
   int i, j=0;
   char str[64];
	
   if  (strcmp(argv[argc-1],"?")==0)
     {
	cli_print(cli, "Configure a combination of TCP flags at once. All mentioned \r");
	cli_print(cli, "flags are set, while not mentioned flags remain unset.\r");
	cli_print(cli, "Flag keywords: cwr, ece, urg, ack, psh, rst, syn, fin.\r");
        cli_print(cli, "NOTE: The flags command alone resets all flags to zero!\n");
	cli_print(cli, "Example:\n");
	cli_print(cli, " mz(config-pkt-1-tcp)# flags syn fin ack \n");
	cli_print(cli, "\n");
        mops_tcp_flags2str (clipkt, str);
	cli_print(cli,"Current setting is: %s\n",str);
	return CLI_OK;
     }
	
   if (argc>8)
     {
	cli_print(cli, "Up to 8 arguments are allowed using the keywords:\r");
	cli_print(cli, "cwr, ece, urg, ack, psh, rst, syn, fin.\n");
	return CLI_OK;
     }

	clipkt->tcp_ctrl_CWR = 0;
	clipkt->tcp_ctrl_ECE = 0;
	clipkt->tcp_ctrl_URG = 0;
	clipkt->tcp_ctrl_ACK = 0; 
	clipkt->tcp_ctrl_PSH = 0;
	clipkt->tcp_ctrl_RST = 0;
	clipkt->tcp_ctrl_SYN = 0;
	clipkt->tcp_ctrl_FIN = 0;

	
	
   for (i=0; i<argc; i++) {
	   if (mz_strcmp(argv[i], "cwr", 1)==0) {
		   clipkt->tcp_ctrl_CWR = 1;
		   j=1;
	   }
	
	   if (mz_strcmp(argv[i], "ece", 1)==0) {
		   clipkt->tcp_ctrl_ECE = 1;
		   j=1;
	   }

	   if (mz_strcmp(argv[i], "urg", 1)==0) {
		   clipkt->tcp_ctrl_URG = 1;
		   j=1;
	   }
	   
	   if (mz_strcmp(argv[i], "ack", 1)==0) {
		   clipkt->tcp_ctrl_ACK = 1;
		   j=1; 
	   }

	   if (mz_strcmp(argv[i], "psh", 1)==0) {
		   clipkt->tcp_ctrl_PSH = 1;
		   j=1;
	   }
	   
	   if (mz_strcmp(argv[i], "rst", 1)==0) {
		   clipkt->tcp_ctrl_RST = 1;
		   j=1;
	   }
	   
	   if (mz_strcmp(argv[i], "syn", 1)==0) {
		   clipkt->tcp_ctrl_SYN = 1;
		   j=1;
	   }

	   if (mz_strcmp(argv[i], "fin", 1)==0) {
		   clipkt->tcp_ctrl_FIN = 1;
		   j=1;
	   }

	if (!j) {
		cli_print(cli, "Unknown keyword at position %i\n", i+1);
		return CLI_OK;
	}
	   else { // flag matched, continue
		   j=0;
	   }
     }

	mops_tcp_flags2str (clipkt, str);
	cli_print(cli,"Current setting is: %s\n",str);
	
   return CLI_OK;
}



int cmd_tcp_cwr (struct cli_def *cli, char *command, char *argv[], int argc)
{
   char str[64];
	
   if  (strcmp(argv[argc-1],"?")==0)
     {
	cli_print(cli, "Set or unset the TCP Congestion Window Reduced flag (CWR)\r");
	mops_tcp_flags2str (clipkt, str);
	cli_print(cli,"Current setting is: %s\n",str);
      	return CLI_OK;
     }

   if (argc!=1)
     {
	cli_print(cli, "Use the 'set' or 'unset' keywords.\n");
	return CLI_OK;
     }
   
	
	if (mz_strcmp(argv[0], "set", 1)==0)
		clipkt->tcp_ctrl_CWR = 1;
	else if (mz_strcmp(argv[0], "unset", 1)==0)
		clipkt->tcp_ctrl_CWR = 0;
	else 
		cli_print(cli, "Unknown keyword. Use the 'set' or 'unset' keywords.\n");

	mops_tcp_flags2str (clipkt, str);
	cli_print(cli,"Current setting is: %s\n",str);
	
   return CLI_OK;
}



int cmd_tcp_ece (struct cli_def *cli, char *command, char *argv[], int argc)
{
	char str[64];
	
	if  (strcmp(argv[argc-1],"?")==0) {
		cli_print(cli, "Set or unset the TCP ECN-Echo flag (ECE)\r");
		mops_tcp_flags2str (clipkt, str);
		cli_print(cli,"Current setting is: %s\n",str);
		return CLI_OK;
	}

   if (argc!=1) {
	   cli_print(cli, "Use the 'set' or 'unset' keywords.\n");
	   return CLI_OK;
   }
   
	if (mz_strcmp(argv[0], "set", 1)==0)
		clipkt->tcp_ctrl_ECE = 1;
	else if (mz_strcmp(argv[0], "unset", 1)==0)
		clipkt->tcp_ctrl_ECE = 0;
	else
		cli_print(cli, "Unknown keyword. Use the 'set' or 'unset' keywords.\n");
	
	mops_tcp_flags2str (clipkt, str);
	cli_print(cli,"Current setting is: %s\n",str);
	
   return CLI_OK;
}



int cmd_tcp_urg (struct cli_def *cli, char *command, char *argv[], int argc)
{
	char str[64];
	
	if  (strcmp(argv[argc-1],"?")==0) {
		cli_print(cli, "Set or unset the TCP urgent flag (URG)\r");
		mops_tcp_flags2str (clipkt, str);
		cli_print(cli,"Current setting is: %s\n",str);
		return CLI_OK;
     }

	if (argc!=1) {
		cli_print(cli, "Use the 'set' or 'unset' keywords.\n");
		return CLI_OK;
	}
   
	if (mz_strcmp(argv[0], "set", 1)==0)
		clipkt->tcp_ctrl_URG = 1;
	else  if (mz_strcmp(argv[0], "unset", 1)==0)
		clipkt->tcp_ctrl_URG = 0;
	else
		cli_print(cli, "Unknown keyword. Use the 'set' or 'unset' keywords.\n");

	mops_tcp_flags2str (clipkt, str);
	cli_print(cli,"Current setting is: %s\n",str);
	
   return CLI_OK;
}




int cmd_tcp_ack (struct cli_def *cli, char *command, char *argv[], int argc)
{
	char str[64];
	
	if (strcmp(argv[argc-1],"?")==0) {
		cli_print(cli, "Set or unset the TCP acknowledgement flag (ACK)\r");
		mops_tcp_flags2str (clipkt, str);
		cli_print(cli,"Current setting is: %s\n",str);
		return CLI_OK;
	}
	
	if (argc!=1) {
		cli_print(cli, "Use the 'set' or 'unset' keywords.\n");
		return CLI_OK;
	}
	
	
	if (mz_strcmp(argv[0], "set", 1)==0)
		clipkt->tcp_ctrl_ACK = 1;
	else if (mz_strcmp(argv[0], "unset", 1)==0)
		clipkt->tcp_ctrl_ACK = 0;
	else
		cli_print(cli, "Unknown keyword. Use the 'set' or 'unset' keywords.\n");
	
	mops_tcp_flags2str (clipkt, str);
	cli_print(cli,"Current setting is: %s\n",str);
	
   return CLI_OK;
}



int cmd_tcp_psh (struct cli_def *cli, char *command, char *argv[], int argc)
{
	char str[64];
	
	if (strcmp(argv[argc-1],"?")==0) {
		cli_print(cli, "Set or unset the TCP push flag (PSH)\r");
		mops_tcp_flags2str (clipkt, str);
		cli_print(cli,"Current setting is: %s\n",str);
		return CLI_OK;
	}

	if (argc!=1) {
		cli_print(cli, "Use the 'set' or 'unset' keywords.\n");
		return CLI_OK;
	}
	
	if (mz_strcmp(argv[0], "set", 1)==0)
		clipkt->tcp_ctrl_PSH = 1;
	else if (mz_strcmp(argv[0], "unset", 1)==0)
		clipkt->tcp_ctrl_PSH = 0;
	else
		cli_print(cli, "Unknown keyword. Use the 'set' or 'unset' keywords.\n");

	mops_tcp_flags2str (clipkt, str);
	cli_print(cli,"Current setting is: %s\n",str);

   return CLI_OK;
}



int cmd_tcp_rst (struct cli_def *cli, char *command, char *argv[], int argc)
{
	char str[64];
	
	if (strcmp(argv[argc-1],"?")==0) {
		cli_print(cli, "Set or unset the TCP reset flag (RST)\r");
		mops_tcp_flags2str (clipkt, str);
		cli_print(cli,"Current setting is: %s\n",str);
		return CLI_OK;
	}
	
	if (argc!=1) {
		cli_print(cli, "Use the 'set' or 'unset' keywords.\n");
		return CLI_OK;
	}
	
	if (mz_strcmp(argv[0], "set", 1)==0)
		clipkt->tcp_ctrl_RST = 1;
	else if (mz_strcmp(argv[0], "unset", 1)==0)
		clipkt->tcp_ctrl_RST = 0;
	else
		cli_print(cli, "Unknown keyword. Use the 'set' or 'unset' keywords.\n");
	
	mops_tcp_flags2str (clipkt, str);
	cli_print(cli,"Current setting is: %s\n",str);
   
   return CLI_OK;
}



int cmd_tcp_syn (struct cli_def *cli, char *command, char *argv[], int argc)
{
	char str[64];
	
	if (strcmp(argv[argc-1],"?")==0)  {
		cli_print(cli, "Set or unset the TCP synchronisation flag (SYN)\r");
		mops_tcp_flags2str (clipkt, str);
		cli_print(cli,"Current setting is: %s\n",str);
		return CLI_OK;
	}

	if (argc!=1) {
		cli_print(cli, "Use the 'set' or 'unset' keywords.\n");
		return CLI_OK;
	}
	
	if (mz_strcmp(argv[0], "set", 1)==0)
		clipkt->tcp_ctrl_SYN = 1;
	else if (mz_strcmp(argv[0], "unset", 1)==0)
		clipkt->tcp_ctrl_SYN = 0;
	else
		cli_print(cli, "Unknown keyword. Use the 'set' or 'unset' keywords.\n");
	
	mops_tcp_flags2str (clipkt, str);
	cli_print(cli,"Current setting is: %s\n",str);

   return CLI_OK;
}



int cmd_tcp_fin (struct cli_def *cli, char *command, char *argv[], int argc)
{
	char str[64];
	
	if (strcmp(argv[argc-1],"?")==0) {
		cli_print(cli, "Set or unset the TCP finalisation flag (FIN)\r");
		mops_tcp_flags2str (clipkt, str);
		cli_print(cli,"Current setting is: %s\n",str);
		return CLI_OK;
	}

	if (argc!=1) {
		cli_print(cli, "Use the 'set' or 'unset' keywords.\n");
		return CLI_OK;
	}
	
	if (mz_strcmp(argv[0], "set", 1)==0)
		clipkt->tcp_ctrl_FIN = 1;
	else if (mz_strcmp(argv[0], "unset", 1)==0)
		clipkt->tcp_ctrl_FIN = 0;
	else
		cli_print(cli, "Unknown keyword. Use the 'set' or 'unset' keywords.\n");
	
	mops_tcp_flags2str (clipkt, str);
	cli_print(cli,"Current setting is: %s\n",str);

	return CLI_OK;
}



int cmd_tcp_window (struct cli_def *cli, char *command, char *argv[], int argc)
{
   unsigned long int tmp;
     
   if ( (strcmp(argv[argc-1],"?")==0) || (argc>1) )
     {
	cli_print(cli, "Specify the TCP window size (0..65535)\r");
	cli_print(cli, "\n");
	return CLI_OK;
     }
   
   tmp = (unsigned long int) str2int (argv[0]);
   if (tmp<65535)
     {
	clipkt->tcp_win = (u_int16_t) tmp;	
     }
   else
     {
	cli_print(cli, "The TCP window size must not exceed 65535\n");
     }
   
   return CLI_OK;
}



int cmd_tcp_sum (struct cli_def *cli, char *command, char *argv[], int argc)
{
   int sum;
   
   if (strncmp(argv[argc-1], "?", 2)==0)
     {
	cli_print(cli, "Specify the TCP checksum in hexadecimal or use the keyword 'auto'.\r");
	cli_print(cli, "By default, the checksum is computed automatically.\n");
	return CLI_OK;
     }

   if (mz_strcmp(argv[0], "auto", 2)==0)
     {
	clipkt->tcp_sum_false=0;
	return CLI_OK;
     }
   
   sum = (int) xstr2int(argv[0]);
   
   if (sum>0xffff) 
     {
	cli_print(cli, "The checksum must be within range 0..ffff\n");
	return CLI_OK;
     }
   
   clipkt->tcp_sum = (u_int16_t) sum;
   clipkt->tcp_sum_false=1;
   
   return CLI_OK;
}



int cmd_tcp_urgptr(struct cli_def *cli, char *command, char *argv[], int argc)
{

   unsigned long int tmp;
     
   if ( (strcmp(argv[argc-1],"?")==0) || (argc>1) )
     {
	cli_print(cli, "Specify the TCP urgent pointer (0..65535)\r");
	cli_print(cli, "\n");
	return CLI_OK;
     }
   
   tmp = (unsigned long int) str2int (argv[0]);
   if (tmp<65535)
     {
	clipkt->tcp_urg = (u_int16_t) tmp;	
     }
   else
     {
	cli_print(cli, "The TCP urgent pointer must not exceed 65535\n");
     }
   
   return CLI_OK;
}



int cmd_tcp_options (struct cli_def *cli, char *command, char *argv[], int argc)
{
	int mss=0, sack=0, scale=0;
	u_int32_t tsval=0, tsecr=0;
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc>1) ) {
		cli_print(cli, "Specify TCP options\n");
		cli_print(cli, "Option parameters:\n");
		cli_print(cli, "[ mss <0..65535> ] [sack] [tsval <0..4294967295> [tsecr <0..4294967295>]] [nop] [scale <0..14>]\n");
		cli_print(cli, "NOTE: Only a set of default options are supported in this version\r");
		cli_print(cli, "(20 bytes, consisting of MSS=1452 bytes, SACK permitted, a Timestamp,\r");
		cli_print(cli, "NOP, and Window Scale 5)\r");
		cli_print(cli, "\n");
		return CLI_OK;
	}

	if (clipkt->tcp_option_used) {
		// turn off
		clipkt->tcp_option_used = 0; 
	} else { 
		// turn on
		mops_tcp_add_option (clipkt, mss, sack, scale, tsval, tsecr);

		cli_print(cli, "NOTE: Only a set of default options are supported in this version\r");
		cli_print(cli, "(20 bytes, consisting of MSS=1452 bytes, SACK permitted, a Timestamp,\r");
		cli_print(cli, "NOP, and Window Scale 5)\n");
	}

	return CLI_OK;
}



int cmd_tcp_end(struct cli_def *cli, char *command, char *argv[], int argc)
{
   char prompt[16];
   sprintf(prompt, "pkt-%i",clipkt->id);
   cli_set_configmode(cli, MZ_MODE_PACKET, prompt);
   return CLI_OK;
}

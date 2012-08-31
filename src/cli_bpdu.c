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



int cmd_bpdu_id (struct cli_def *cli, char *command, char *argv[], int argc)
{
   struct mops_ext_bpdu * pd = clipkt->p_desc;
   char str[256];
   
   if ( (strcmp(argv[argc-1],"?")==0) || (argc!=1) )
     {
	mz_def16("0x0000", pd->id, str);
	cli_print(cli, "Specify the BPDU identifier (0..65535)\r");
	cli_print(cli, "%s\n", str);	
	cli_print(cli, "\n");
	return CLI_OK;
     }

   if (mops_pdesc_2byte(&pd->id, argv[0], 0, 0, 65535))
     {
	cli_print(cli, "Specify a value between 0 and 65535\n");
     }
     
   return CLI_OK;
}


int cmd_bpdu_version (struct cli_def *cli, char *command, char *argv[], int argc)
{
   struct mops_ext_bpdu * pd = clipkt->p_desc;
   
   if ( (strcmp(argv[argc-1],"?")==0) || (argc!=1) )
     {
	cli_print(cli, "Specify the BPDU version (0..255)\r");
	cli_print(cli, "\n");
	return CLI_OK;
     }

   if (mops_pdesc_1byte(&pd->version, argv[0], 0, 0, 255))
     {
	cli_print(cli, "Specify a value between 0 and 255\n");
     }

   
   return CLI_OK;
}



int cmd_bpdu_type (struct cli_def *cli, char *command, char *argv[], int argc)
{
	struct mops_ext_bpdu * pd = clipkt->p_desc;
	
	if ( (strcmp(argv[argc-1],"?")==0) || (argc!=1) ) {
		cli_print(cli, "Specify the BPDU type, either via keyword or number (0..255)\n");
		cli_print(cli, "Keywords:\n");
		cli_print(cli, "  conf .... Configuration BPDU\r");
		cli_print(cli, "  tcn ..... Topology Change BPDU\r");
		cli_print(cli, "\n");
		return CLI_OK;
	}

	if (mz_strcmp(argv[0], "configuration", 1)==0) {
		pd->bpdu_type = 0x00;
	} else if (mz_strcmp(argv[0], "tcn", 1)==0) {
		pd->bpdu_type = 0x80;
	} else if (mops_pdesc_1byte(&pd->bpdu_type, argv[0], 0, 0, 255)) {
		cli_print(cli, "Specify a value between 0 and 255\n");
	}
   
	return CLI_OK;
}


int cmd_bpdu_flags (struct cli_def *cli, char *command, char *argv[], int argc)
{
   struct mops_ext_bpdu * pd = clipkt->p_desc;
   int i;
   char str[16];
   
   if ( (strcmp(argv[argc-1],"?")==0) || (argc>8) )
     {
	cli_print(cli, "Specify the BPDU flags by keyword.\r");
	cli_print(cli, "Note that not-mentioned flags will be set to zero!\n");
	cli_print(cli, "General keywords:\n");
	cli_print(cli, "  ack     .... Topology Change Acknowledgement\r");
	cli_print(cli, "  tcn     .... Topology Change Notification\r");
	cli_print(cli, "\r");
	cli_print(cli, "RSTP-specific keywords:\n");
	cli_print(cli, "  agree   .... Agreement\r");
	cli_print(cli, "  prop    .... Proposal\r");
	cli_print(cli, "  fwd     .... Forward State\r");
	cli_print(cli, "  learn   .... Learn State\r");
	cli_print(cli, "\r");
	cli_print(cli, "  Port roles:\n");
	cli_print(cli, "  unknown .... Unknown\r");
	cli_print(cli, "  alt     .... Alternate or Backup\r");
	cli_print(cli, "  root    .... Root\r");
	cli_print(cli, "  desg    .... Designated\r");
	cli_print(cli, "\n");
	return CLI_OK;
     }

   //    7     6    5   4        3   2     1      0
   // tcnack agree fwd learn     X   X  proposal TCN
   // where XX is 00 unknown
   //             01 alternate or backup
   //             10 root
   //             11 designated
   
   if (argc)
     {
	pd->flags = 0x00; // always reset to zero (= normal Configuration BPDU)
	
	for (i=0; i<argc; i++)
	  {
	     if (mz_strcmp(argv[i], "ack", 2)==0) pd->flags |= 0x80;
	     else
	       if (mz_strcmp(argv[i], "tcn", 2)==0) pd->flags |= 0x01;
	     else
	       if (mz_strcmp(argv[i], "agree", 2)==0) pd->flags |= 0x40;
	     else
	       if (mz_strcmp(argv[i], "fwd", 2)==0) pd->flags |= 0x20;
	     else
	       if (mz_strcmp(argv[i], "learn", 2)==0) pd->flags |= 0x10;
	     else
	       if (mz_strcmp(argv[i], "proposal", 2)==0) pd->flags |= 0x02;
	     else
	       if (mz_strcmp(argv[i], "unknown", 2)==0) pd->flags &= 0xf3;
	     else
	       if (mz_strcmp(argv[i], "alt", 2)==0) { pd->flags &= 0xf7; pd->flags |= 0x04; } 
	     else
	       if (mz_strcmp(argv[i], "root", 2)==0) { pd->flags &= 0xfb; pd->flags |= 0x08; }
	     else
	       if (mz_strcmp(argv[i], "desg", 2)==0) pd->flags |= 0x0c;
	  }
	// Feedback
	char2bits(pd->flags, str);
	cli_print(cli, "Flags: %s\n", str);
     }
   else
     {
	cli_print(cli, "No flags configured (use '?')\n");
     }
      
   return CLI_OK;
}









int cmd_bpdu_rid (struct cli_def *cli, char *command, char *argv[], int argc)
{

	struct mops_ext_bpdu * pd = clipkt->p_desc;   
	char p[64], e[64];
	int pri, esi, r;
   
	if ( (strcmp(argv[argc-1],"?")==0) || (argc>2) )
	{
		cli_print(cli, "Specify the BPDU root identifier, using the following format:\n");
		cli_print(cli, " <priority>[:ext-sys-id] [interface | MAC-Address]\n");
		cli_print(cli, "  <priority>          ....... priority (0-15)\r");
		cli_print(cli, "  <ext-sys-id>        ....... extended system-id (0-4095)\n");
		cli_print(cli, "Optionally the MAC address of the root bridge can be given, either directly as arbitrary\r");
		cli_print(cli, "address (format: XX:XX:XX:XX:XX:XX) or by referring to an existing interface.\n");
		cli_print(cli, "Per default the MAC address of the default interface is used and a priority of zero.\n");
		cli_print(cli, "\n");
		return CLI_OK;
	}

	if (argc==0) {
		cli_print(cli, "Please specify at least the priority (use ?)\n");
		return CLI_OK;
	}
   
	mz_tok(argv[0], ":", 2, p, e);
	
	pri = (int) str2int(p);
	if (e!=NULL)
		esi = (int) str2int(e);
	else
		esi = 0;
	
	if (argc==1) // no MAC given
	{
		r = mops_create_bpdu_bid (clipkt, pri, esi, NULL, 1); // 1 means RID (0 means BID)
	}
	else
		r = mops_create_bpdu_bid (clipkt, pri, esi, argv[1], 1); // 1 means RID (0 means BID)
	
	
	// Check return value
	switch (r)
	{
	 case 1:
		cli_print(cli, "Priority must be within 0..15\n");
		return CLI_OK;
		break;
	 case 2:
		cli_print(cli, "Extended System-ID must be within 0..4095\n");
		return CLI_OK;
		break;
	 case 3:
		cli_print(cli, "Invalid MAC address or interface\n");
		return CLI_OK;
		break;
	 case 4:
		cli_print(cli, "Invalid format - use ?\n");
		return CLI_OK;
		break;
	}
	
	
	
	//---------
	// Verify:
	bs2str(pd->root_id, p, 8);
	cli_print(cli, "RID is now %s\n", p);
	// -------
	// 
	return CLI_OK;
}






int cmd_bpdu_pc (struct cli_def *cli, char *command, char *argv[], int argc)
{
   struct mops_ext_bpdu * pd = clipkt->p_desc;   
   unsigned long long int i;
   
   if ( (strcmp(argv[argc-1],"?")==0) || (argc>1) )
     {
	cli_print(cli, "Specify the BPDU root path cost (0..4294967295)\r");
	cli_print(cli, "\n");
	return CLI_OK;
     }

   if (argc==0)
     {
	cli_print(cli, "Missing argument (use ?)\n");
	return CLI_OK;
     }
   
   i = str2lint (argv[0]);
   if (i>0xffffffff)
     {
	cli_print(cli, "Range exceeded (0..4294967295)\n");
     }
   else
     pd->root_pc = (u_int32_t) i;
     
   return CLI_OK;
}




int cmd_bpdu_bid (struct cli_def *cli, char *command, char *argv[], int argc)
{

   struct mops_ext_bpdu * pd = clipkt->p_desc;   
   char p[64], e[64];
   int pri, esi, r;
   
   if ( (strcmp(argv[argc-1],"?")==0) || (argc>2) )
     {
	cli_print(cli, "Specify the BPDU bridge identifier, using the following format:\n");
	cli_print(cli, " <priority>[:ext-sys-id] [interface | MAC-Address]\n");
	cli_print(cli, "  <priority>          ....... priority (0-15)\r");
	cli_print(cli, "  <ext-sys-id>        ....... extended system-id (0-4095)\n");
	cli_print(cli, "Optionally the MAC address of the root bridge can be given, either directly as arbitrary\r");
	cli_print(cli, "address (format: XX:XX:XX:XX:XX:XX) or by referring to an existing interface.\n");
	cli_print(cli, "Per default the MAC address of the default interface is used and a priority of zero.\n");
	cli_print(cli, "\n");
	return CLI_OK;
     }
    

   if (argc==0)
     {
	cli_print(cli, "Please specify at least the priority (use ?)\n");
	return CLI_OK;
     }
   
   mz_tok(argv[0], ":", 2, p, e);
   
   pri = (int) str2int(p);
   if (e!=NULL)
     esi = (int) str2int(e);
   else
     esi = 0;
   
   if (argc==1) // no MAC given
     {
	r = mops_create_bpdu_bid (clipkt, pri, esi, NULL, 0); // 0 means BID (1 means RID)
     }
   else
     r = mops_create_bpdu_bid (clipkt, pri, esi, argv[1], 0); // 0 means BID (1 means RID)

   
   // Check return value
   switch (r)
     {
      case 1:
	cli_print(cli, "Priority must be within 0..15\n");
	return CLI_OK;
	break;
      case 2:
	cli_print(cli, "Extended System-ID must be within 0..4095\n");
	return CLI_OK;
	break;
      case 3:
	cli_print(cli, "Invalid MAC address or interface\n");
	return CLI_OK;
	break;
      case 4:
	cli_print(cli, "Invalid format - use ?\n");
	return CLI_OK;
	break;
     }
   

   
   //---------
   // Verify:
   bs2str(pd->bridge_id, p, 8);
   cli_print(cli, "BID is now %s\n", p);
   // -------
   // 
   return CLI_OK;
}





int cmd_bpdu_pid (struct cli_def *cli, char *command, char *argv[], int argc)
{
   struct mops_ext_bpdu * pd = clipkt->p_desc;   
   u_int32_t i;
     
   if ( (strcmp(argv[argc-1],"?")==0) || (argc>1) )
     {
	cli_print(cli, "Specify the BPDU port identifier (0..65535)\r");
	cli_print(cli, "\n");
	return CLI_OK;
     }

   if (argc==0)
     {
	cli_print(cli, "Missing argument (use ?)\n");
	return CLI_OK;
     }
   
   i = (u_int32_t) str2int (argv[0]);
   
   if (i>0xffff)
     {
	cli_print(cli, "The port identifier must be within 0..65535\n");
	return CLI_OK;
     }
   
   pd->port_id = (u_int16_t) i;
   
   return CLI_OK;
}

//
//
//  NOTE:
//
//    All timers are multiples of 1/256 sec. Thus times range from 0 to 255 seconds.
//
//

int cmd_bpdu_age (struct cli_def *cli, char *command, char *argv[], int argc)
{
   struct mops_ext_bpdu * pd = clipkt->p_desc;   
   u_int32_t i;
   char str[256];
   
   if ( (strcmp(argv[argc-1],"?")==0) || (argc>2) )
     {
	mz_def16("0", pd->message_age, str);
	
	cli_print(cli, "Specify the message age:\n");
	cli_print(cli, " - either in seconds (0..256) e. g. '14 sec'\r");
	cli_print(cli, " - or as multiples of 1/256 seconds (0..65535)\n");
	cli_print(cli, "%s\n", str);
	cli_print(cli, "\n");
	return CLI_OK;
     }

   if (argc==0)
     {
	cli_print(cli, "Missing argument (use ?)\n");
	return CLI_OK;
     }

   i = (u_int32_t) str2int (argv[0]);
   
   if (argc==1) // absolute
     {
	if (i>0xffff)
	  cli_print(cli, "The age must be within 0..65535\n");
	else
	  pd->message_age = (u_int16_t) i;
     }
   else if (mz_strcmp(argv[1], "seconds", 1)==0) // in seconds
     {
	if (i>256)
	  cli_print(cli, "The age must be within 0..256 seconds\n");
	else
	  {
	     if (i==256)
	       i = 0xffff; // since 256*256=65536 which exceeds 0xffff but 65535/256 = 255.996
	     else
	       i = i * 256;
	     
	     pd->message_age = (u_int16_t) i;
	  }

     }
   else
     cli_print(cli, "Invalid argument\n");

   return CLI_OK;
   
}







int cmd_bpdu_maxage (struct cli_def *cli, char *command, char *argv[], int argc)
{
   struct mops_ext_bpdu * pd = clipkt->p_desc;   
   u_int32_t i;
   char str[256];
   
   if ( (strcmp(argv[argc-1],"?")==0) || (argc>2) )
     {
	mz_def16("20 seconds", pd->max_age, str);
	
	cli_print(cli, "Specify the maximum message age:\n");
	cli_print(cli, " - either in seconds (0..256) e. g. '20 sec'\r");
	cli_print(cli, " - or as multiples of 1/256 seconds (0..65535)\n");
	cli_print(cli, "%s\n", str);
	cli_print(cli, "\n");
	return CLI_OK;
     }
   
   if (argc==0)
     {
	cli_print(cli, "Missing argument (use ?)\n");
	return CLI_OK;
     }

   i = (u_int32_t) str2int (argv[0]);
   
   if (argc==1) // absolute
     {
	if (i>0xffff)
	  cli_print(cli, "The max age must be within 0..65535\n");
	else
	  pd->max_age = (u_int16_t) i;
     }
   else if (mz_strcmp(argv[1], "seconds", 1)==0) // in seconds
     {
	if (i>256)
	  cli_print(cli, "The max age must be within 0..256 seconds\n");
	else
	  {
	     if (i==256)
	       i = 0xffff; // since 256*256=65536 which exceeds 0xffff but 65535/256 = 255.996
	     else
	       i = i * 256;
	     
	     pd->max_age = (u_int16_t) i;
	  }

     }
   else
     cli_print(cli, "Invalid argument\n");

   return CLI_OK;
   
}





int cmd_bpdu_hello (struct cli_def *cli, char *command, char *argv[], int argc)
{
   struct mops_ext_bpdu * pd = clipkt->p_desc;   
   u_int32_t i;
   char str[256];
   
   if ( (strcmp(argv[argc-1],"?")==0) || (argc>2) )
     {
	mz_def16("2 seconds", pd->hello_time, str);
	
	cli_print(cli, "Specify the hello interval:\n");
	cli_print(cli, " - either in seconds (0..256) e. g. '2 sec'\r");
	cli_print(cli, " - or as multiples of 1/256 seconds (0..65535)\n");
	cli_print(cli, "%s\n", str);	cli_print(cli, "\n");
	return CLI_OK;
     }

   if (argc==0)
     {
	cli_print(cli, "Missing argument (use ?)\n");
	return CLI_OK;
     }

   
   i = (u_int32_t) str2int (argv[0]);
   
   if (argc==1) // absolute
     {
	if (i>0xffff)
	  cli_print(cli, "The hello interval must be within 0..65535\n");
	else
	  pd->hello_time = (u_int16_t) i;
     }
   else if (mz_strcmp(argv[1], "seconds", 1)==0) // in seconds
     {
	if (i>256)
	  cli_print(cli, "The hello interval must be within 0..256 seconds\n");
	else
	  {
	     if (i==256)
	       i = 0xffff; // since 256*256=65536 which exceeds 0xffff but 65535/256 = 255.996
	     else
	       i = i * 256;
	     
	     pd->hello_time = (u_int16_t) i;
	  }

     }
   else
     cli_print(cli, "Invalid argument\n");

   return CLI_OK;

}

int cmd_bpdu_fwd (struct cli_def *cli, char *command, char *argv[], int argc)
{
   struct mops_ext_bpdu * pd = clipkt->p_desc;   
   u_int32_t i;
   char str[256];
   
   if ( (strcmp(argv[argc-1],"?")==0) || (argc>2) )
     {
	mz_def16("15 seconds", pd->f_delay, str);
	
	cli_print(cli, "Specify the forward delay:\n");
	cli_print(cli, " - either in seconds (0..256) e. g. '15 sec'\r");
	cli_print(cli, " - or as multiples of 1/256 seconds (0..65535)\n");
	cli_print(cli, "%s\n", str);
	cli_print(cli, "\n");
	return CLI_OK;
     }

   if (argc==0)
     {
	cli_print(cli, "Missing argument (use ?)\n");
	return CLI_OK;
     }

   
   i = (u_int32_t) str2int (argv[0]);
   
   if (argc==1) // absolute
     {
	if (i>0xffff)
	  cli_print(cli, "The forward delay must be within 0..65535\n");
	else
	  pd->f_delay = (u_int16_t) i;
     }
   else if (mz_strcmp(argv[1], "seconds", 1)==0) // in seconds
     {
	if (i>256)
	  cli_print(cli, "The forward delay must be within 0..256 seconds\n");
	else
	  {
	     if (i==256)
	       i = 0xffff; // since 256*256=65536 which exceeds 0xffff but 65535/256 = 255.996
	     else
	       i = i * 256;
	     
	     pd->f_delay = (u_int16_t) i;
	  }

     }
   else
     cli_print(cli, "Invalid argument\n");

   return CLI_OK;

}



int cmd_bpdu_mode (struct cli_def *cli, char *command, char *argv[], int argc)
{
   struct mops_ext_bpdu * pd = clipkt->p_desc;
   
   if ( (strcmp(argv[argc-1],"?")==0) || (argc>1) )
     {
	cli_print(cli, "Specify the BPDU mode using the keywords:\n");
	cli_print(cli, " stp    ...... IEEE 802.1d (traditional CST)\r");
	cli_print(cli, " rstp   ...... IEEE 802.1w (Rapid STP)\r");
	cli_print(cli, " mstp   ...... IEEE 802.1s (Multiple STP)\r");
	cli_print(cli, " pvst   ...... Cisco Per-VLAN STP\r");
	cli_print(cli, " rpvst  ...... Cisco Per-VLAN RSTP\r");
	cli_print(cli, "\n");
	return CLI_OK;
     }

   if (argc==0)
     {
	cli_print(cli, "Missing argument (use ?)\n");
	return CLI_OK;
     }

   
   if (mz_strcmp(argv[0], "stp", 1)==0)
     {
	pd->version=0;
	pd->rstp=0;
	pd->pvst=0;
	pd->mstp=0;
     }
   else if (mz_strcmp(argv[0], "rstp", 2)==0)
     {
	pd->version=2;
	pd->rstp=1;
	pd->mstp=0;
     }
   else if (mz_strcmp(argv[0], "mstp", 1)==0)
     {
	pd->version=3;
	pd->mstp=1;
     }
   else if (mz_strcmp(argv[0], "pvst", 1)==0)
     {
	pd->version=0;
	pd->pvst=1;
	pd->rstp=0;
	pd->mstp=0;
     }
   else if (mz_strcmp(argv[0], "rpvst", 2)==0)
     {
	pd->version=2;
	pd->rstp=1;
	pd->pvst=1;
	pd->mstp=0;
     }
   
   
   // TODO: also change version to 2 if RSTP, 0 if legacy 
   
   
   return CLI_OK;
}




int cmd_bpdu_vlan(struct cli_def *cli, char *command, char *argv[], int argc)
{
   u_int32_t i;
   
   if ( (strcmp(argv[argc-1],"?")==0) || (argc>1) )
     {
	cli_print(cli, "Specify the VLAN number for PVST+ messages (0..4095)\n");
	cli_print(cli, "\n");
	return CLI_OK;
     }
   
   if (argc==0)
     {
	cli_print(cli, "Missing argument (use ?)\n");
	return CLI_OK;
     }

   i = (u_int32_t) str2int(argv[0]);
   
   if (i>65535)
     {
	cli_print(cli, "VLAN number is definitely too large! (0..65535 at maximum)\n");
	return CLI_OK;
     }

   if (i>4095)
     {
	cli_print(cli, "Warning: Invalid VLAN number (0..4095) - but let's try it...\n");
     }
   
   mops_create_bpdu_trailer(clipkt, (u_int16_t) i);
   
   return CLI_OK;
}



int cmd_bpdu_end(struct cli_def *cli, char *command, char *argv[], int argc)
{
   char prompt[16];
   sprintf(prompt, "pkt-%i",clipkt->id);
   cli_set_configmode(cli, MZ_MODE_PACKET, prompt);
   return CLI_OK;
}


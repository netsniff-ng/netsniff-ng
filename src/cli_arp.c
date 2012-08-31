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


// ISSUES:
// 
// - Currently only IP/MAC resolution supported (i.e. hw_size=6, pr_size=4)
// - Add macro support: commands like request/response should set all params correctly




int cmd_arp_hwtype (struct cli_def *cli, char *command, char *argv[], int argc)
{
   struct mops_ext_arp * pd = clipkt->p_desc;
     
   if ( (strncmp(argv[argc-1],"?",1)==0) || (argc!=1) )
     {
	cli_print(cli,"Specify the hardware type (0-ffff, default 1=Eth)\n");
     }
   else if (mops_pdesc_2byte(&pd->hw_type, argv[0], 1, 0, 0xffff))
     {
	cli_print(cli, "Hardware type must be between 0 and ffff\n");
     }
   
   return CLI_OK;
}



int cmd_arp_prtype (struct cli_def *cli, char *command, char *argv[], int argc)
{
   struct mops_ext_arp * pd = clipkt->p_desc;

   if ( (strncmp(argv[argc-1],"?",1)==0) || (argc!=1) )
     {
	cli_print(cli,"Specify the protocol type (0-ffff, default=800=IP)\n");
     }
   else if (mops_pdesc_2byte(&pd->pr_type, argv[0], 1, 0, 0xffff))
     {
	cli_print(cli, "Protocol type must be between 0 and ffff\n");
     }

   return CLI_OK;
}



int cmd_arp_hwaddrsize (struct cli_def *cli, char *command, char *argv[], int argc)
{
   struct mops_ext_arp * pd = clipkt->p_desc;
   
   if ( (strncmp(argv[argc-1],"?",1)==0) || (argc!=1) )
     {
	cli_print(cli,"Specify the hardware address size (0-255, default=6)\n");
     }
   else if (mops_pdesc_1byte(&pd->hw_size, argv[0], 0, 0, 255))
     {
	cli_print(cli, "Hardware size must be between 0 and 255\n");
     }
    
     return CLI_OK;
}


int cmd_arp_praddrsize (struct cli_def *cli, char *command, char *argv[], int argc)
{
   struct mops_ext_arp * pd = clipkt->p_desc;
   
   if ( (strncmp(argv[argc-1],"?",1)==0) || (argc!=1) )
     {
	cli_print(cli,"Specify the protocol address size (0-255, default=4)\n");
     }
   else if (mops_pdesc_1byte(&pd->pr_size, argv[0], 0, 0, 255))
     {
	cli_print(cli, "Protocol size must be between 0 and 255\n");
     }
   
     return CLI_OK;
}


int cmd_arp_opcode (struct cli_def *cli, char *command, char *argv[], int argc)
{
   struct mops_ext_arp * pd = clipkt->p_desc;
  
   if ( (strncmp(argv[argc-1],"?",1)==0) || (argc!=1) )
     {
	cli_print(cli,"Specify the ARP operation code (0-ffff)\n");
	cli_print(cli,"Optional keywords: 'request' (default) or 'response'\n");
     }
   else if (mz_strcmp(argv[0],"request", 3)==0)
     {
	cli_print(cli, "Set ARP mode to request\n");
	pd->opcode = 1;
     }
   else if (mz_strcmp(argv[0],"response", 3)==0)
     {
	cli_print(cli, "Set ARP mode to response\n");
	pd->opcode = 2;
     }
   else
     {
	cli_print(cli, "Invalid ARP mode\n");
     }
   
   return CLI_OK;
}



int cmd_arp_smac (struct cli_def *cli, char *command, char *argv[], int argc)
{
   struct mops_ext_arp * pd = clipkt->p_desc;
   
   if ( (strncmp(argv[argc-1],"?",1)==0) || (argc!=1) )
     {
	cli_print(cli,"Specify a source MAC address (format: XX:XX:XX:XX:XX:XX)\n");
     }
   else 
     {   
	if (mops_pdesc_mac(pd->sender_mac, argv[0]))
	  {
	     cli_print(cli,"Invalid MAC address (use format: XX:XX:XX:XX:XX:XX)\n");
	  }
     }
   return CLI_OK;
}



int cmd_arp_sip (struct cli_def *cli, char *command, char *argv[], int argc)
{
   struct mops_ext_arp * pd = clipkt->p_desc;
   
   if ( (strncmp(argv[argc-1],"?",1)==0) || (argc!=1) )
     {
	cli_print(cli,"Specify a source IP address (format: A.B.C.D)\n");
     }
   else if (mops_pdesc_ip (pd->sender_ip, argv[0]))
     { 
	cli_print(cli,"Invalid IP address (use format: A.B.C.D)\n");
     }

   return CLI_OK;
}



int cmd_arp_tmac (struct cli_def *cli, char *command, char *argv[], int argc)
{
   struct mops_ext_arp * pd = clipkt->p_desc;
   
   if ( (strncmp(argv[argc-1],"?",1)==0) || (argc!=1) )
     {
	cli_print(cli,"Specify a target MAC address (format: XX:XX:XX:XX:XX:XX)\n");
     }
   else if (mops_pdesc_mac(pd->target_mac, argv[0]))
     {
	cli_print(cli,"Invalid MAC address (use format: XX:XX:XX:XX:XX:XX)\n");
     }

   return CLI_OK;
}



int cmd_arp_tip (struct cli_def *cli, char *command, char *argv[], int argc)
{
   struct mops_ext_arp * pd = clipkt->p_desc;
   
   if ( (strncmp(argv[argc-1],"?",1)==0) || (argc!=1) )
     {
	cli_print(cli,"Specify a target IP address (format: A.B.C.D)\n");
     }
   else if (mops_pdesc_ip (pd->target_ip, argv[0]))
     { 
	cli_print(cli,"Invalid IP address (use format: A.B.C.D)\n");
     }

   return CLI_OK;
}



int cmd_arp_trailer (struct cli_def *cli, char *command, char *argv[], int argc)
{
   struct mops_ext_arp * pd = (MOPS_EXT_ARP) clipkt->p_desc;
   
   if ( (strncmp(argv[argc-1],"?",1)==0) || (argc!=1) )
     {
	cli_print(cli,"Specify the trailer length (0-2000, default=18)\n");
     }
   else if (mops_pdesc_2byte(&pd->trailer, argv[0], 0, 0, 2000))
     {
	cli_print(cli, "Trailer must be between 0 and 2000\n");
     }
   
   return CLI_OK;
}



int cmd_arp_end(struct cli_def *cli, char *command, char *argv[], int argc)
{
   char prompt[16];
   sprintf(prompt, "pkt-%i",clipkt->id);
   cli_set_configmode(cli, MZ_MODE_PACKET, prompt);
   return CLI_OK;
}


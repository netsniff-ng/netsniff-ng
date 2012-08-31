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

int cmd_dns_query(struct cli_def *cli, char *command, char *argv[], int argc)
{
     
     return CLI_OK;
}


int cmd_dns_answer(struct cli_def *cli, char *command, char *argv[], int argc)
{
     
     return CLI_OK;
}


int cmd_dns_ttl(struct cli_def *cli, char *command, char *argv[], int argc)
{
     
     return CLI_OK;
}


int cmd_dns_end(struct cli_def *cli, char *command, char *argv[], int argc)
{
   char prompt[16];
   sprintf(prompt, "pkt-%i",clipkt->id);
   cli_set_configmode(cli, MZ_MODE_PACKET, prompt);
   return CLI_OK;
}


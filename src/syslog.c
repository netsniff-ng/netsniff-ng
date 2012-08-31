/*
 * Mausezahn - A fast versatile traffic generator
 * Copyright (C) 2008,2009 Herbert Haas
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

#define MZ_SYSLOG_HELP \
   		"| Syslog type: Send (traditional) Syslog packets via UDP.\n" \
		"|\n" \
		"| Parameters:\n" \
		"|\n" \
		"|  severity, sev  0-7            .... Severity level from Emergency (0) to Debug (7)\n" \
		"|  facility, fac  0-23           .... Facility number\n" \
		"|\n" \
		"|  time           hh:mm:ss       .... Local time, 24-hour format\n" \
		"|  month, mon     Mmm            .... Current month, 1-12\n" \
		"|  day            dd             .... Current day, 0-31\n" \
		"|\n" \
		"|  host           max 314 bytes  .... Name or IP Address of sending host\n" \
		"|\n" \
		"| Defaults:\n" \
		"|\n" \
		"|  Per default the severity \"Warning\" (4), the facility \"Security\" (4), and the\n" \
		"|  current time stamp is used. If no host is given, host is set to \"MZ\"\n"  \
		"|\n" \
		"| You can define the Syslog message itself using the -P flag. For example:\n" \
		"|\n" \
		"|   mz eth0 -t syslog sev=3 -P \"You have been mausezahned.\"\n" \
		"|\n" \
		"| By the way, mz (by intention) does not check if your timestamp is valid according\n" \
                "| calendar rules. It is generally recommended to follow the Darwin Era Calendar ;-)\n" \
		"|\n"



// RFC 3164 states that a Syslog message consists of three parts: PRI, HEADER, and MSG.
// 
//   1) PRI: contains facility(f) and severity(s), using the syntax "<N>" where N = f * 8 + s
// 
//   2) HEADER: contains a timestamp and a sender-ID (name or IP), for example "May 25 23:42:42 Mausezahnhost"
//      Note that instead of leading zeroes a space must be used for the day e. g. "May  5".
//      However leading zeroes are required for hour, minutes, seconds, e. g. "01:05:09"
//    
//   3) MSG: consists of TAG and CONTENT field. The TAG identifies the program or process and 
//      must not exceed 32 characters. Typically the TAG and the CONTENT fields are delimited
//      via either a "[", or a colon (:) or a space. The CONTENT field is a simple text.
//      
//  EXAMPLE from RFC 3164:
//  
//      <34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8
//      
//  EXAMPLE from Cisco Router:
//        
//      *Mar 23 13:45:08.727: %ENVMON-3-FAN_FAILED: Fan 2 not rotating
//                  


int create_syslog_packet()
{
	unsigned int pri, sev, fac, day, curday, mon, curmon;
	char  lt[8], host[314];
	char *Months[12] = 
	{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"  };
	
	
	time_t curtime;
	struct tm curtime_broken;
	char argval[MAX_PAYLOAD_SIZE];
	int ca=0, aa;
	
	aa=number_of_args(tx.arg_string);
	
	if ( (getarg(tx.arg_string,"help", NULL)==1) && (mode==SYSLOG) )
	{
		ca++; // counts each argument
		if (mz_port)
		{
			cli_print(gcli, "%s", MZ_SYSLOG_HELP);
			return -1;
		}
		else
		{
			fprintf(stderr,"\n" 
				MAUSEZAHN_VERSION
				"\n%s", MZ_SYSLOG_HELP);
			
			exit(0);
		}
	}
   
   
   if ( (getarg(tx.arg_string,"severity", argval)==1) || 
	(getarg(tx.arg_string,"sev", argval)==1) )
     {
	     ca++; // counts each argument
	     sev = (unsigned int) str2int(argval);
     }
   else
     {		
	     sev = 4;
     }

   if ( (getarg(tx.arg_string,"facility", argval)==1) || 
	(getarg(tx.arg_string,"fac", argval)==1) )
     {
	     ca++; // counts each argument
	     fac = (unsigned int) str2int(argval);
     }
   else
     {
	     fac = 4;
     }

   
   time(&curtime);
   localtime_r (&curtime, &curtime_broken);


   
   if (getarg(tx.arg_string,"time", argval)==1)
     {
	     ca++; // counts each argument
	     strncpy(lt,argval,8);
	     // TODO: check if specified timestamp has valid format, e. g. 15:03:22
     }
   else
     {
	     timestamp_hms (lt);
     }


   
   curmon = curtime_broken.tm_mon; // Note that Jan = 0, ..., Dec = 11 !!!
   
   if ( (getarg(tx.arg_string,"month", argval)==1) || 
	(getarg(tx.arg_string,"mon", argval)==1) )
     {
	ca++; // counts each argument
	mon = (unsigned int) str2int(argval);
	if ( (mon<1) || (mon>12) )
	  {
	     fprintf(stderr, " mz/syslog: Invalid month; will use current month (%i)!\n", curmon+1);
	     mon = curmon;
	  }
     }
   else
     {
	mon = curmon;
     }

   curday = curtime_broken.tm_mday; 
   
   if (getarg(tx.arg_string,"day", argval)==1) 
     {
        ca++; // counts each argument
	day = (unsigned int) str2int(argval);
	if ( (day<1) || (day>31) )
	  {
	     fprintf(stderr, " mz/syslog: Invalid day; will use current day(%i)!\n", curday);
	     day = curday;
	  }
     }
   else
     {
	day = curday;
     }
   

   if (getarg(tx.arg_string,"host", argval)==1)
     {
        ca++; // counts each argument
	strncpy(host,argval,314);  // 314 is just an arbitrary number ;-)
     }
   else
     {
	strcpy(host, "MZ42"); 
     }

  
   // CHECK SURPLUS ARGUMENTS
   if (aa!=ca) {
	   fprintf(stderr, "WARNING: %i unmatched arguments within argument string!\n", aa-ca);
   }
	
	
   // Now put everything together:
   // 
   //  Again the EXAMPLE from RFC 3164:
   //  
   //      <34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8
   //      

   
   pri = 8*fac+sev;

   sprintf((char*) tx.udp_payload, "<%d>%s %2i %s %s ",
	   pri,
	   Months[mon],
	   day,
	   lt,
	   host);

   if (tx.ascii) // ASCII PAYLOAD overrides hex payload
     {
	strncat((char *)tx.udp_payload, (char *)tx.ascii_payload, 2048);
	tx.ascii=0; // avoid that 'create_udp_packet' overwrites this!
     }     
   else
     {
	strcat((char *)tx.udp_payload, "%MZSYS-42-CRN: Main reactor exceeded critical temperature!");
     }
   

   tx.udp_payload_s = strlen((char *)tx.udp_payload);   

   tx.dp = 514;
   tx.sp = 514;
     
   tx.udp_len = 8 + tx.udp_payload_s;
	
   if (verbose)
     {
	fprintf(stderr, "Syslog: %s\n", tx.udp_payload);
     }
   

   return 0;
   
}




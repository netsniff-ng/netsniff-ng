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



////////////////////////////////////////////////////////////////////////////////////////////
//
//  Contains various tools to ease development of new modules:
//  
//  getarg  ............. scans string for arguments and returns assigned value
//  str2int ............. Converts a string into unsigned long int in a safe way
//  str2lint ............ Same as str2int but returns an unsigned long long int
//  xstr2int ............ Same as str2int but expects hex digits
//  xstr2lint ........... Same as above but returns an unsigned long long int
//  get_ip_range_dst .... Parses string for an IP range and sets start/stop addresses
//  get_ip_range_src .... Same for source addresses
//  check_eth_mac_txt ... Scans tx.eth_dst|src_txt and sets tx.eth_dst|src appropriately
//  get_port_range ...... Parses string for a dst|src-port range and sets start/stop values
//  get_tcp_flags ....... Parses string for TCP arguments and sets tx.tcp_control
//  get_mpls_params ..... Parses string for MPLS parameters (label, exp, BOS, TTL)
//  exists .............. Parses a string for a single character and returns "1" if found
//  mz_strisbinary ...... Checks whether string consists only of 0 and 1, returns how many digits total
//  str2bin8 ............ Converts a string containing max 8 binary digits into a number
//  str2bin16 ........... Converts a string containing max 16 binary digits into a number
//  char2bits ........... Converts a char into a string containing ones and zeros
//  getfullpath_cfg ..... Creates a full filename with path to the desired config directory
//  getfullpath_log ..... Creates a full filename with path to the desired logging directory
//  mz_strncpy .......... A safer implementation of strncpy
//  number_of_args ...... Returns number of arguments of the Mausezahn argument string
//  mz_strisnum ......... Returns 1 if string only consists of decimal digits
//  mz_strishex ......... Returns 1 if string only consists of hexadecimal digits
//  mz_strcmp ........... Matches a string or a prefix of it with given min-length 
//                        Example usage: User CLI input
//  mz_tok .............. Decomposes a string into tokens and maps them to args
//                        Example usage: IPv6-addresses, user input for MPLS-tags
//  delay_parse ......... Parses one or two strings for a delay specification and sets a struct timespec
//    
////////////////////////////////////////////////////////////////////////////////////////////

#include "mz.h"



// Scan 'str' for an argument 'arg_name' and returns its value in arg_value
// Return value: number of occurences of arg_name
// Note that if arg_name occurs multiple times, the last found value is returned.
// If last argument (arg_value) is set to NULL it will be ignored.
// Example: 
//   int i;
//   char ip[64];
//   i = getarg ("request, da=10.1.1.2, SYN", "da", ip);
// ...will assign "10.1.1.2" to ip and the occurence i is set to 1.
int getarg(char *str, char *arg_name, char *arg_value)
{
   char tmp[MAX_PAYLOAD_SIZE];
   char *str1, *str2, *token, *subtoken;
   char *saveptr1, *saveptr2;
   int j, occurence=0;
   
   strncpy(tmp,str,MAX_PAYLOAD_SIZE); // only operate on local strings
   
   for (j = 1, str1 = tmp; ; j++, str1 = NULL) 
     {
	
	token = strtok_r(str1, ",", &saveptr1);
	if (token == NULL)
	  break;

	str2 = token; 
	if ( (subtoken = strtok_r(str2, " =", &saveptr2))!=NULL)
	  {
	     if (strcasecmp(subtoken,arg_name)==0)
	       {
		  occurence+=1;
		  //printf("found %s\n",arg_name);
		  if ( (subtoken = strtok_r(NULL, " =", &saveptr2))!=NULL)
		    {
		       // argument has a value!
		       //printf("%s has value: [%s]\n",arg_name, subtoken);
		       if (arg_value!=NULL)
			 {
			    strcpy(arg_value,subtoken);
			 }
		    }
	       }
	  }
	else
	  break;
     }
   return occurence;
}


// Convert str to (unsigned long) int
// Return value: the unsigned long int
unsigned long int str2int(char *str)
{  
   unsigned long int i;
   
   errno=0;
   
   i = strtoul(str, (char **)NULL, 10);

   if ((errno == ERANGE && (i == ULONG_MAX))
       || (errno != 0 && i == 0))
     {
	perror("strtoul");
     }
   
   return i;
}



// Convert str to (unsigned long long) int
// Return value: the unsigned long long int
unsigned long long int str2lint(char *str)
{  
   unsigned long long int i;
   
   errno=0;
   
   i = strtoull(str, (char **)NULL, 10);

   if ((errno == ERANGE && (i == ULLONG_MAX))
       || (errno != 0 && i == 0))
     {
	perror("strtoull");
     }
   
   return i;
}


// Convert hex-str to (unsigned long) int
// Return value: the unsigned long int
unsigned long int xstr2int(char *str)
{  
   unsigned long int i;
   
   errno=0;
   
   i = strtoul(str, (char **)NULL, 16);

   if ((errno == ERANGE && (i == ULONG_MAX))
       || (errno != 0 && i == 0))
     {
	
	perror("strtoul");
     }
   
   return i;
}


// Convert hex-str to (unsigned long long) int
// Return value: the unsigned long long int
unsigned long long int xstr2lint(char *str)
{  
   unsigned long long int i;
   
   errno=0;
   
   i = strtoull(str, (char **)NULL, 16);

   if ((errno == ERANGE && (i == ULLONG_MAX))
       || (errno != 0 && i == 0))
     {
	perror("strtoull");
     }
   
   return i;
}




// Parses string 'arg' for an IP range and finds start and stop IP addresses.
// Return value: 0 upon success, 1 upon failure.
// 
// NOTE: The results are written in the following variables:
// 
//   (u_int32_t) tx.ip_dst_start    ... contains start value 
//   (u_int32_t) tx.ip_dst_stop     ... contains stop value
//   (u_int32_t) tx.ip_dst          ... initialized with start value 
//   int         tx.ip_dst_isrange  ... set to 1 if above values valid
//      
// Possible range specifications:
// 
//   1) 192.168.0.0-192.168.0.12
//   2) 10.2.11.0-10.55.13.2
//   3) 172.18.96.0/19
// 
// That is: 
// 
//   FIRST detect a range by scanning for the "-" OR "/" chars
//   THEN determine start and stop value and store them as normal unsigned integers
// 
int get_ip_range_dst (char *arg)
{

   int 
     i, len, 
     found_slash=0, found_dash=0;

   unsigned int q;
   u_int32_t mask, invmask;
   
   char *start_str, *stop_str;
   
   len = strnlen(arg, 32);
   
   if ( (len>31) || (len<9) ) // 255.255.255.200-255.255.255.255 (31 chars) OR 1.0.0.0/8 (9 chars)
     return 1; // ERROR: no range
   
   // Find "-" or "/"
   for (i=0; i<len; i++)
     {
	if  (arg[i]=='/')  found_slash=1;
	if  (arg[i]=='-')  found_dash=1;
     }

   if ((found_slash) && (found_dash)) 
     exit (1); // ERROR: Wrong range string syntax (cannot use both "/" and "-" !!!
   
   if (found_dash)
     {
	start_str = strtok (arg, "-");
	stop_str = strtok (NULL, "-");

	// These are the start and stop IP addresses of the range:
	tx.ip_dst_start = str2ip32 (start_str);  
	tx.ip_dst_stop = str2ip32 (stop_str);
	tx.ip_dst_h = tx.ip_dst_start; 
	tx.ip_dst = str2ip32_rev (start_str);
	
	if (tx.ip_dst_start < tx.ip_dst_stop)
	  {
	     // Set range flag:
	     tx.ip_dst_isrange = 1;
	     return 0;
	  }
	else
	  {
	     tx.ip_dst_isrange = 0;
	     return 1; // ERROR: stop value must be greater than start value !!!
	  }
     }
   else if (found_slash)
     {
	start_str = strtok (arg, "/");
	stop_str = strtok (NULL, "/"); // Actually contains the prefix length, e. g. "24" 
	
	q = (unsigned int) str2int (stop_str);
	
        mask = 0xffffffff;
        mask <<= (32-q);
        invmask = 0xffffffff - mask; 

	tx.ip_dst_start = (str2ip32 (start_str) & mask) +1; // the '+1' is to ensure that we do not start with the net-id
	tx.ip_dst_stop = tx.ip_dst_start | invmask; 
	tx.ip_dst_h = tx.ip_dst_start; 
	tx.ip_dst = str2ip32_rev (start_str) | 0x01000000; // the '0x01000000' is to ensure that we do not start with the net-id
	tx.ip_dst_isrange = 1;
	return 0;
     }
   
    
   return 1; // ERROR: The specified argument string is not a range!
   
}




// Parses string 'arg' for an IP range and finds start and stop IP addresses.
// Return value: 0 upon success, 1 upon failure.
// 
// NOTE: The results are written in the following variables:
// 
//   (u_int32_t) tx.ip_src_start    ... contains start value 
//   (u_int32_t) tx.ip_src_stop     ... contains stop value
//   (u_int32_t) tx.ip_src          ... initialized with start value
//   int         tx.ip_src_isrange  ... set to 1 if above values valid
//   
// Possible range specifications:
// 
//   1) 192.168.0.0-192.168.0.12
//   2) 10.2.11.0-10.55.13.2
//   3) 172.18.96.0/19
// 
// That is: 
// 
//   FIRST detect a range by scanning for the "-" OR "/" chars
//   THEN determine start and stop value and store them as normal unsigned integers
// 
int get_ip_range_src (char *arg)
{

   int 
     i, len, 
     found_slash=0, found_dash=0;

   unsigned int q;
   u_int32_t mask, invmask;
   
   char *start_str, *stop_str;


   len = strnlen(arg,32);
   
   if ( (len>31) || (len<9) ) // 255.255.255.200-255.255.255.255 (31 chars) OR 1.0.0.0/8 (9 chars)
     return 1; // ERROR: no range
   
   // Find "-" or "/"
   for (i=0; i<len; i++)
     {
	if  (arg[i]=='/')  found_slash=1;
	if  (arg[i]=='-')  found_dash=1;
     }

   if ((found_slash) && (found_dash)) 
     exit (1); // ERROR: Wrong range string syntax (cannot use both "/" and "-" !!!
   
   if (found_dash)
     {
	start_str = strtok (arg, "-");
	stop_str = strtok (NULL, "-");

	// These are the start and stop IP addresses of the range:
	tx.ip_src_start = str2ip32 (start_str);  
	tx.ip_src_stop = str2ip32 (stop_str);
	tx.ip_src_h = tx.ip_src_start;
	tx.ip_src = str2ip32_rev (start_str);
	
	if (tx.ip_src_start < tx.ip_src_stop)
	  {
	     // Set range flag:
	     tx.ip_src_isrange = 1;
	     return 0;
	  }
	else
	  {
	     tx.ip_src_isrange = 0;
	     return 1; // ERROR: stop value must be greater than start value !!!
	  }
     }
   else if (found_slash)
     {
	start_str = strtok (arg, "/");
	stop_str = strtok (NULL, "/"); // Actually contains the prefix length, e. g. "24" 
	
	q = (unsigned int) str2int (stop_str);

        mask = 0xffffffff;
        mask <<= (32-q);
        invmask = 0xffffffff - mask; 
	  
	tx.ip_src_start = (str2ip32 (start_str) & mask) +1; // the '+1' is to ensure that we do not start with the net-id
	tx.ip_src_stop = tx.ip_src_start | invmask; 
	tx.ip_src_h = tx.ip_src_start; 
	tx.ip_src = str2ip32_rev (start_str) | 0x01000000; // the '0x01000000' is to ensure that we do not start with the net-id
	tx.ip_src_isrange = 1;
	return 0;
     }
   
   return 1; // ERROR: The specified argument string is not a range!
   
}


// Scans tx.eth_dst_txt or tx.eth_src_txt and sets the corresponding
// MAC addresses (tx.eth_dst or tx.eth_src) accordingly.
// Argument: What string should be checked, ETH_SRC or ETH_DST.
// 
// Return value: 
//       0 when a MAC address has been set or
//       1 when not set (or wrongly set)
//       
// Currently eth_src|dst_txt can be:
//   'rand', 'own', 'bc'|'bcast', 'stp', 'pvst', 'cisco', 
//  or a real mac address.
// 
// TODO: implement other important MAC addresses
int check_eth_mac_txt(int src_or_dst)
{
   char *eth_mac_txt;
   u_int8_t  *eth_mac;
   int *eth_rand;
   int i;

   // Check argument
   if (src_or_dst == ETH_SRC)
     {
	eth_mac_txt = tx.eth_src_txt;
	eth_mac = tx.eth_src;
	eth_rand = &tx.eth_src_rand;
     }
   else if (src_or_dst == ETH_DST)
     {
	eth_mac_txt = tx.eth_dst_txt;
	eth_mac = tx.eth_dst;	
	eth_rand = &tx.eth_dst_rand;
     }
   else
     {
	return 1; // wrong argument
     }
   
   
   // Did the user really specify a dst-address? 
   if (strnlen(eth_mac_txt, 18)==0)  
     {
	return 1; // No.
     }
   
   
   // Okay, lets check the commandline argument:
   // 
   // Do you want a random MAC?
   // TODO: Consider enforcement of unicast addresses
   if (strncmp(eth_mac_txt, "rand", 4)==0)
     {
	eth_mac[0] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
	eth_mac[1] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
	eth_mac[2] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
	eth_mac[3] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
	eth_mac[4] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
	eth_mac[5] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
	*eth_rand = 1;
     }
   // Do you want your own interface MAC?
   else if (strncmp(eth_mac_txt, "own", 3)==0)
     {
	for (i=0; i<6; i++)
	  {
	     eth_mac[i] = tx.eth_mac_own[i];
	  }
     }
   // Do you want a broadcast MAC?
   else if (strncmp(eth_mac_txt, "bc", 2)==0) // NOTE that this also fetches "bcast"
     {
	str2hex_mac("FF:FF:FF:FF:FF:FF", eth_mac);
     }
   // Do you want the IEEE address 'all bridges' used for STP?
   else if (strncmp(eth_mac_txt, "stp", 3)==0) // 
     {
	str2hex_mac("01:80:C2:00:00:00", eth_mac); // IEEE for all bridges	
     }
   // Do you want the Cisco address e. g. for CDP, VTP?
   else if (strncmp(eth_mac_txt, "cisco", 5)==0) 
     {
	str2hex_mac("01:00:0C:CC:CC:CC", eth_mac); 
     }
   // Do you want the Cisco address e. g. for CDP, VTP?
   else if (strncmp(eth_mac_txt, "pvst", 5)==0)
     {
	str2hex_mac("01:00:0C:CC:CC:CD", eth_mac); 
     }
   // The string MUST contain a mac address
   // TODO: CHECK whether the string has correct format for a mac address!
   else 
     {
	str2hex_mac(eth_mac_txt, eth_mac);
     }

   return 0;
}





// Scans argument for a port number or range and sets 
// the corresponding values in the tx struct:
// 
// a)  tx.sp_start, tx.sp_stop, tx.sp = tx.sp_start
//   
//         ** OR **
//            
// b)  tx.dp_start, tx.dp_stop, tx.dp = tx.dp_start
//   
// Arguments:
// 
//    - 'sp_or_dp' is either SRC_PORT or DST_PORT
//    - 'arg' contains the port range as string such as 1-1024
//    
// Return value: 0 on success, 1 upon failure
// 
int get_port_range (int sp_or_dp, char *arg)
{

   int i, len, found_dash=0;

   u_int32_t tmp1, tmp2;
   
   u_int16_t
     *port,
     *start,
     *stop;
   int 
     *isrange;

   char *start_str, *stop_str;
   
   
   // Check which port to manage
   if (sp_or_dp == DST_PORT)
     {
	port    =  &tx.dp;
	start   =  &tx.dp_start;
	stop    =  &tx.dp_stop;
	isrange =  &tx.dp_isrange;
     }
   else if (sp_or_dp == SRC_PORT)
     {
	port    =  &tx.sp;
	start   =  &tx.sp_start;
	stop    =  &tx.sp_stop;
	isrange =  &tx.sp_isrange;
     }
   else
     {
	return 1;  // error
     }

   
   len = strnlen(arg,12);
   if (len==0) return 1; // error
   
   // Find "-" 
   for (i=0; i<len; i++)
     {
	if  (arg[i]=='-')  found_dash=1;
     }   
   
   if (found_dash)  // range specified
     {
	start_str = strtok (arg, "-");
	stop_str = strtok (NULL, "-");
	
	tmp1 = str2int (start_str);
	if ( (tmp1<0)||(tmp1>65535)) 
	  { 
	     fprintf(stderr," mz/get_port_range: Invalid port range!\n");
	     exit (-1);
	  }
	*start = tmp1;

	tmp2 = str2int (stop_str);
	if ( (tmp2<0)||(tmp2>65535)) 
	  { 
	     fprintf(stderr," mz/get_port_range: Invalid port range!\n");
	     exit (-1);
	  }
	*stop  = tmp2;
	
	if (tmp1>tmp2) // swap start/stop values!
	  {
	     *start = tmp2;
	     *stop  = tmp1;
	  }

	*port = *start;
	*isrange = 1;

	return 0;
     }
   else // single port number
     {
	tmp1 = str2int (arg);
	if ( (tmp1<0)||(tmp1>65535)) tmp1=0;
	*port    = tmp1; 
 	*isrange = 0;
	return 0;
     }
   
   return 1; // error
}




// Scans argument for TCP flags and sets 
// tx.tcp_control accordingly.
// 
// Valid keywords are: fin, syn, rst, psh, ack, urg, ecn, cwr
// Valid delimiters are: | or + or -
// Return value: 0 on success, 1 upon failure
// 
int get_tcp_flags (char*  flags)
{
   char *f;
   
   // From LSB to MSB: fin, syn, reset, push, ack, urg, ecn, cwr
   // ecn...ECN-Echo, cwr...Congestion Window Reduced
   
   if (strnlen(flags,40)==0) return 1; // error
   

   f = strtok (flags, "|+-");
   do 
     {
	if (strncmp(f,"fin",3)==0) 
	  {
	     tx.tcp_control = tx.tcp_control | 1; 
	  }
	else if (strncmp(f,"syn",3)==0)
	  {
	     tx.tcp_control = tx.tcp_control | 2;
	  }
	else if (strncmp(f,"rst",3)==0)
	  {
	     tx.tcp_control = tx.tcp_control | 4;
	  }
	else if (strncmp(f,"psh",3)==0)
	  {
	     tx.tcp_control = tx.tcp_control | 8;
	  }
	else if (strncmp(f,"ack",3)==0)
	  {
	     tx.tcp_control = tx.tcp_control | 16;
	  }
	else if (strncmp(f,"urg",3)==0)
	  {
	     tx.tcp_control = tx.tcp_control | 32;
	  }
	else if (strncmp(f,"ecn",3)==0)
	  {
	     tx.tcp_control = tx.tcp_control | 64;
	  }
	else if (strncmp(f,"cwr",3)==0)
	  {
	     tx.tcp_control = tx.tcp_control | 128;
	  }
	
     } while ( (f=strtok(NULL, "|+-")) != NULL);
   
   return 0;
}



// Scans string 'params' for MPLS parameters 
// and sets tx.mpls_* accordingly.
// 
// CLI Syntax Examples:
// 
// -M help       .... shows syntax
// 
// -M 800        .... label=800
// -M 800:S      .... label=800 and BOS flag set
// -M 800:S:64   .... label=800, BOS, TTL=64
// -M 800:64:S   .... same
// -M 64:77      .... label=64, TTL=77
// -M 64:800     .... INVALID
// -M 800:64     .... label=800, TTL=64
// -M 800:3:S:64 .... additionally the experimental bits are set (all fields required!)
// 
// Note: S = BOS(1), s = NOT-BOS(0)
// 
// Valid delimiters: :-.,+
// Return value: 0 on success, 1 upon failure
int get_mpls_params(char *p)
{

   char *f1, *f2, *f3, *f4;
   char params[256];

   tx.mpls_exp = 0;
   tx.mpls_ttl = 255;
   
   strncpy(params, p, 256);
   
   if (strncmp(params,"help",4)==0)
     {
	fprintf(stderr,"\n"
		MAUSEZAHN_VERSION
		"\n"
		"| MPLS header Syntax: -M label[,label[,label[,...]]]\n"
		"| where each header may consist of the following parameters:\n"
		"|\n"
		"|   label ... the MPLS label (mandatory, 0..1048575)\n"
		"|   exp ..... experimental/CoS (default: 0, allowed values: 0..7)\n"
		"|   TTL ..... Time To Live (default: 255)\n"
		"|   BOS ..... marks bottom-of-stack; per default the last (most inner) header\n"
		"|             will have BOS=1. If desired you can set this flag for any header\n"  
		"|             inbetween but this will lead to an invalid packet. Simply use\n"
	        "|             'S' to set BOS=1, or 's' to set BOS=0. Note that this flag MUST be\n"
                "|             the LAST argument.\n"
		"|\n"
		"| Examples:\n"
		"|\n"
		"|  -M 800        .... label=800\n"
		"|  -M 800:6      .... label=800 and CoS=6\n"
		"|  -M 800:6:55   .... label=800, CoS=6, TTL=55\n"
		"|  -M 800:S      .... label=800 and BOS=1\n"
		"|  -M 800:6:s    .... label=800, CoS=6, and BOS=0\n"
		"|\n"
		"|  multiple headers:\n"
		"|\n"
		"|  -m 30,20:7,800:5:128 ... outer label=800 with CoS=5 and TTL=128,\n"
		"|                           middle label=20 with CoS=7,\n"
		"|                           inner label=30 (this one is closest to L3).\n"
		"|\n"
		"|   Valid delimiters inside a header: : - . +\n"
		"|\n"
		"\n");
	exit (0);
     }
   else
     {

	if ( (f1 = strtok (params, ":-.+")) == NULL )
	  {
	     return 1; // error!
	  }
	
	tx.mpls_label = (u_int32_t) str2int (f1);
	if (tx.mpls_label>1048575) 
	  { 
	     tx.mpls_label = 1048575; // 2^20
	     fprintf(stderr," Warning: MPLS label too big! Reduced to maximum allowed value.\n");
	  }
     }

      
   if ( (f2 = strtok (NULL, ":-.+")) != NULL ) // 2nd param set
     {
	if  (strncmp(f2,"S",1)==0) 
	  {
	     tx.mpls_bos = 1;
	     return 0;
	  }
	else if (strncmp(f2,"s",1)==0) 
	  {
	     tx.mpls_bos = 0;
	     return 0;
	  }
	else
	  {
	     tx.mpls_exp = (u_int8_t) str2int (f2);
	     if (tx.mpls_exp > 7)
	       {
		  tx.mpls_exp = 7;
		  fprintf(stderr," Warning: MPLS CoS too big! Reduced to maximum allowed value.\n");
	       }
	  }
	

	if ( (f3 = strtok (NULL, ":-.+")) != NULL ) // 3rd param set
	  {
	     if  (strncmp(f3,"S",1)==0) 
	       {
		  tx.mpls_bos = 1;
		  return 0;
	       }
	     else if (strncmp(f3,"s",1)==0) 
	       {
		  tx.mpls_bos = 0;
		  return 0;
	       }
	     else 
	       {
		  if ((u_int16_t) str2int (f3)>255)
		    {
		       fprintf(stderr," Warning: MPLS TTL too big! Reduced to maximum allowed value.\n");
		       tx.mpls_ttl = 255;
		    }
		  else
		    {
		       tx.mpls_ttl = (u_int8_t) str2int (f3);
		    }
	       }
	     
	     if ( (f4 = strtok (NULL, ":-.+")) != NULL ) // 4th param set
	       {

		  if  (strncmp(f3,"S",1)==0) 
		    {
		       tx.mpls_bos = 1;
		    }
		  else if (strncmp(f3,"s",1)==0) 
		    {
		       tx.mpls_bos = 0;
		    }

	       }
	     
	  }
     }
   
   
   return 0;
}


// Parses str for occurence of character or sequence ch.
// Returns number of occurences 
int exists(char* str, char* ch)
{
   int i,match;
   
   size_t len_str, len_ch;
   
   len_str = strlen(str);
   len_ch = strlen(ch);
   match=0;
   
   for (i=0; i<len_str; i++)
     {
	if (strcmp(str++,ch)==0) match++;
     }

   return match;
}



// Checks if str consists only of 0 and 1
// 
// RETURN VALUE:
// 
//    0  if invalid chars found or str empty
//    n  if str consists exactly of n binary digits
int mz_strisbinary(char *str)
{
	int i, len, ret=0;
   
	len = strlen(str);
	if (len==0) return 0;
   
	for (i=0; i<len; i++) {
		if ((str[i]=='0') || (str[i]=='1')) {
			ret++;
		} else {
			return 0;
		}
	}
	return ret;
}





// Converts a string containing (max 8) binary digits into a number
// RETURN VALUE:
// 
//  Either the number on success
//  Or -1 upon failure
//  
int str2bin8 (char *str)
{
   int i, n, ret=0;
   
   n=mz_strisbinary(str);
   
   if ((!n) || (n>8)) return -1;
   
   for (i=0; i<n; i++) if (str[i]=='1') ret |= ( 0x01 << (n-1-i) ); 
   return ret;
}




// Converts a string containing (max 16) binary digits into a number
// RETURN VALUE:
// 
//  Either the number on success
//  Or -1 upon failure
//  
long int str2bin16 (char *str)
{
   int i, n;
   long int ret=0;
   
   n=mz_strisbinary(str);
   
   if ((!n) || (n>16)) return -1;
   
   for (i=0; i<n; i++) if (str[i]=='1') ret |= ( 0x01 << (n-1-i) ); // C is great ;-)
   return ret;
}



// Converts a char into a string containing ones and zeros
// 
// EXAMPLE:
// 
//   char c = 0x81; char str[16];
//   char2bits(c, str);
//   printf("%s\n",str); => "1 0 0 0 0 0 0 1"
// 
int char2bits (char c, char *str)
{
   int i,j=1;
   char tmp[]="0 0 0 0 0 0 0 0";

   for (i=0; i<8; i++)
     {
	if (c&j) tmp[14-i*2]='1';
	j=j*2;
     }
   
   strncpy(str, tmp, 15);
   return 0;
}


// Takes filename and prepends valid configuration directory
// 
// 1) prefer configurable mz_default_config_path[]
// 2) otherwise use MZ_DEFAULT_CONFIG_PATH
// 
// NOTE: 'filename' finally holds the full path
// and must therefore be big enough 
// 
// 
// RETURN VALUE: 
//   0 upon success
//   1 upon failure
//   
int getfullpath_cfg (char *filename)
{
	int lenf, lenp;
	char tmp[32];
	
	lenf = strnlen(filename, 32);
	
        // filename not given?
	if ((lenf==0) || (lenf==32)) return 1;
	
	strncpy(tmp, filename, 32);
	
	// Prefer user-defined path if provided:
	lenp = strnlen(mz_default_config_path,255);
	
	if (lenp) {
		if (strncmp(mz_default_config_path+lenp-1, "/",1))
			strncat(mz_default_config_path, "/",1);
		snprintf(filename, 255, "%s%s",mz_default_config_path,tmp);
	}
	else {
		lenp = strlen(MZ_DEFAULT_CONFIG_PATH);
		snprintf(filename, 255, "%s%s",MZ_DEFAULT_CONFIG_PATH,tmp);
	}
	
	if ((lenf+lenp)>255) return 1;
	
	return 0;
}



// Takes filename and prepends valid logging directory
// 
// 1) prefer configurable mz_default_log_path[]
// 2) otherwise use MZ_DEFAULT_LOG_PATH
// 
// NOTE: filename is overwritten and must be big enough to hold full path!
// 
int getfullpath_log (char *filename)
{
	int lenf, lenp;
	char tmp[32];
	
	lenf = strnlen(filename, 32);
	
        // filename not given?
	if ((lenf==0) || (lenf==32)) return 1;
	
	strncpy(tmp, filename, 32);
	
	// Prefer user-defined path if provided:
	lenp = strnlen(mz_default_log_path,255);
	if (lenp) {
		if (strncmp(mz_default_log_path+lenp-1, "/",1)) 
			strncat(mz_default_log_path, "/",1);
		snprintf(filename, 255, "%s%s",mz_default_log_path,tmp);
	}
	else {
		lenp = strlen(MZ_DEFAULT_LOG_PATH);
		snprintf(filename, 255, "%s%s",MZ_DEFAULT_LOG_PATH,tmp);
	}
	
	if ((lenf+lenp)>255) return 1;

	return 0;
}

// Behaves much like strncpy but additionally ensures 
// that dest is always \0-terminated.
// 
// USAGE NOTE: If you know exactly the length n of your string,
// then you must provide n+1 to support the termination character.
//
// EXAMPLE: src="Hello", n=strlen(src)=5, and mz_strncpy(dest, src, n)
// would result in dest={H,e,l,l,\0}.
// Therefore the correct usage is:  
//              mz_strncpy(dest, src, strlen(src)+1);
//                                    =============
// 
// RETURN VALUE: pointer to dest 
char * mz_strncpy(char *dest, const char *src, size_t n)
{
	char *tmp;
	tmp = strncpy(dest, src, n);
	dest[n-1]='\0';
	return tmp;
}




// Helper function to count the number of arguments
// in the Mausezahn argument string (comma separated args)
// 
// RETURN VALUE: Number of arguments
// 
// TODO: Improve it. Use strtok.
// 
int number_of_args (char *str)
{
	int len=0, i=0, commas=1;
	if ((len=strnlen(str,MAX_PAYLOAD_SIZE))<2) return 0; // no valid argument
	for (i=0; i<len; i++) if (str[i]==',') commas++;
	if (str[len-1]==',') commas--; // comma at the end!
	return commas;
}



// Checks if str consists only of digits 0..9
// 
// RETURN VALUE:
// 
//    0  if invalid chars found or str empty
//    n  if str consists exactly of n digits
int mz_strisnum(char *str)
{
	int i, len, ret=0;
   
	len = strlen(str);
	if (len==0) return 0;
   
	for (i=0; i<len; i++) {
		if (isdigit(str[i])) {
			ret++;
		} else {
			return 0;
		}
	}
	return ret;
}


// Checks if str consists only of hex digits 0..9 and a..f
// 
// RETURN VALUE:
// 
//    0  if invalid chars found or str empty
//    n  if str consists exactly of n digits
int mz_strishex(char *str)
{
	int i, len, ret=0;
   
	len = strlen(str);
	if (len==0) return 0;
   
	for (i=0; i<len; i++) {
		if (isxdigit(str[i])) {
			ret++;
		} else {
			return 0;
		}
	}
	return ret;
}


// Returns an 4-byte random number
// 
u_int32_t  mz_rand32 (void)
{
	static unsigned int r=0;
	srand(r);
	r=rand();
	return (r<<16 | r);
}






// Compares user-provided string with a specified string.
// 
// Return value:
//  
//   0  if at least min characters match 
//   1  if at least one character of usr does NOT match the corresponding character in str.
//             
// Note: Case-insensitive!
// Goal: Should be more practical and secure than strcmp (and related)
int mz_strcmp(char* usr_orig, char* str_orig, int min)
{
	int i, same=0, usrlen, max;
	char usr[80], str[80];
	
	usrlen = strlen(usr_orig);
	max = strlen(str_orig);
	
	strncpy(usr, usr_orig, 80);
	strncpy(str, str_orig, 80);
	
	// User provided not enough or too many chars
	if ((usrlen<min) || (usrlen>max)) return 1;
	
	// now check how many bytes really match
	for (i=0; i<usrlen; i++) {
		if (strncasecmp(&usr[i], &str[i], 1)==0) {
			same++;
		}
	}
	
	if (same<usrlen) return 1;
	
	return 0;
}





// PURPOSE:
// 
//  Maps an arbitrary number of tokens from 'str' which are separated by 
//  a character 'delim' into provided arguments.
// 
// USAGE EXAMPLE:
// 
//  char str[]="Am:Dam:Des";
//  char t1[64], t2[64], t3[64], t4[64];
//  
//  mz_tok (str, ":", 4, t1, t2, t3, t4)
// 
//  => t1="Am", t2="Dam", t3="Des", t4=NULL
// 
// NOTE: 
// 
//   1. If the delimiter symbol occurs twice without gap, it is interpreted
//      as 'fill-up' command. To avoid ambiguities this may only occur once.
//      See the IPv6 address format shortcuts as similar example.     
//    
//   2. If there are less tokens than allowed, the arguments are filled up
//      in order, while the remaining are casted to NULL:
// 
//   3. str must be smaller than 4096 bytes!
//   
//   4. To mitigate buffer overflow problems, the maximum token size is 
//      currently limited to 64 bytes. Therefore it is recommended to
//      allocate 64 bytes for each argument.
//       
// RETURN VALUE: Number of returned tokens or -1 upon error

int mz_tok(char * str, char * delim, int anz, ...)
{
   
	va_list ap;
	int i=0, n=0, len, llen, rlen, ltok=0, rtok=0;
	char *d, *l, *r, *token, *saveptr, *arg;
	char str2[4096], delim2[4]="", delim3[4]="";;
	
	if (strlen(delim)!=1) return -1; // delim must contain a single character!
	strncpy(str2, str, 4095);        // protect the original str from strtok => operate on a copy only
	len = strlen(str2);
	
	// Check if some tokens are omitted (::)
	strncpy(delim2, delim, 1); strncat(delim2, delim, 1);  // create the double-delim
	strncpy(delim3, delim2, 2); strncat(delim3, delim, 1); // create the double-delim
	if (strstr(str2, delim3)!=NULL) return -1;             // Error: ':::' occured!
	
	if ( (d=strstr(str2, delim2))!=NULL ) { // delim2 ('::') found
		// Check 3 cases: "::Sat:Sun", "Mon::Sat:Sun", and "Mon:Tue::"
		if (strlen(d)>2) { // '::' is not at the end of str2
			r=d+2;  // r points to beginning of right string
			if (strstr(r, delim2)!=NULL) return -1; // Error: '::' occurs more than once!
			rtok++; // there is at least one token in the right string
			rlen = strlen(r);
			for(i=0;i<rlen;i++) if (strncmp(r++,delim,1)==0) rtok++;
		}
		else
			rlen = 0;
		
		if (rlen<(len-2)) { // '::' is not at the beginning of str2
			l=d-1;  // l points to end of left string 
			ltok++;
			llen = len - rlen - 2;
			for(i=0;i<llen;i++) if (strncmp(l--,delim,1)==0) ltok++;
		}
		//printf("ltok=%i, rtok=%i\n",ltok,rtok);
		if ((ltok+rtok)>anz) return -1; // More tokens than arguments ('::' here leads to ambiguous mapping)
	}
	else
		ltok=len+1; // makes subsequent algorithm to ignore exception handling
	

	
	rtok=anz-rtok; 
	va_start(ap, anz);
	
	token = strtok_r(str2, delim, &saveptr);
	if (token==NULL) { va_end(ap); return n; }
   
	for(i=0; i<anz; i++) {
		arg = va_arg(ap, char *);
		if ( (token==NULL) ||  // less tokens than arguments => assign NULL to the remaining arguments!
		     ((i>=ltok) && (i<rtok))) {
			arg[0] = 0x00;
		}
		else { // we still have tokens...
			n++;
			strncpy(arg, token, 64);
			token = strtok_r(NULL, delim, &saveptr);
		}
	}
	
	va_end(ap);
	return n;
}






// 
// PURPOSE: Simplify reading of user delay specifications.
// Parse 'a' and 'b' and configure a struct timespec, i. e. seconds and nanoseconds.
// 
// Typically 'a' contains only the value and 'b' the unit.
// But if b==NULL then 'a' may also contain the unit such as "100msec"
//
// Allowed units are: nsec, usec, sec, min, hour
//   
// NOTE: If no unit is given then assume msec as default unit
// 
// RETURN VALUE: 0 upon success, 1 upon error (bad arguments)
// 
int delay_parse (struct timespec *t, char *a, char *b)
{
	int i;
	unsigned int sfactor=0, nfactor=1000000; // assume msec as default unit
	unsigned long long delay, sdelay, ndelay;

	if (b==NULL) { // only one argument, but may contain an unit (such as '314sec')
		if (strstr(a, "msec")) {
			nfactor=1000000;
		}
		else if (strstr(a, "usec")) {
			nfactor=1000;
		}
		else if (strstr(a, "nsec")) {
			nfactor=1;
		}
		else if (strstr(a, "sec")) {  // NOTE: This must be the last check since 'sec' is included in previous strings
			sfactor=1;
			nfactor=0;
		}
		else if (strstr(a, "min")) {
			sfactor=60;
			nfactor=0;
		}
		else if (strstr(a, "hour")) {
			sfactor=3600;
			nfactor=0;
		}
		else {  // Unit not found; check for non-digits! 
			// NOTE: we do not currently catch wrong strings that contain sec, usec, or msec.
			// 
			for (i=0; i<strlen(a); i++) {
				if (!isdigit(a[i])) return 1; // invalid unit
			}
			nfactor=1000000; // no unit given => assume msec
		}
	} else { // caller specified two arguments 
		if (mz_strcmp(b,"nsec", 1)==0)
			nfactor=1;
		else if  (mz_strcmp(b,"usec", 1)==0)
			nfactor=1000;
		else if (mz_strcmp(b,"msec", 1)==0)
			nfactor=1000000;
		else if (mz_strcmp(b,"sec", 1)==0) {
			sfactor=1;
			nfactor=0;
		}
		else if (mz_strcmp(b,"min", 1)==0) {
			sfactor=60;
			nfactor=0;
		}
		else if (mz_strcmp(b,"hour", 1)==0) {
			sfactor=3600;
			nfactor=0;
		}
		else return 1; // Invalid unit
	} 

	// Get user-defined actual value:
	delay = strtoull(a, (char **)NULL, 10);
	if ((errno==ERANGE) || (delay>999999999L))  { // see man 2 nanosleep
		return 2; // Value too large! Supported range is from 0 to 999999999
	}

	sdelay = delay * sfactor;
	ndelay = delay * nfactor;
	
	if (ndelay>999999999L) { 
		sdelay = ndelay/1000000000L;
		ndelay = ndelay - (sdelay*1000000000L);
	}
	
	t->tv_sec = sdelay;
	t->tv_nsec = ndelay;
	return 0;
}


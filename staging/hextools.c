/*
 * Mausezahn - A fast versatile traffic generator
 * Copyright (C) 2008 Herbert Haas
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





///////////////////////////////////////////////////////////////////////////////////////////
//
//  Contains various tools for hex-based conversions and manipulation of bytestrings
//  
//  str2hex_mac     ..... converts "00:01:02:0a:ff:ff" into       u_int8_t dst[6] 
//  str2hex         ..... converts "1a 00:00-2f"       into       u_int8_t dst[n] (any length)
//  num2hex         ..... converts "192.16.1.1"        into       u_int8_t dst[4] 
//  bs2str          ..... converts {0,1,10}            into       "00-01-0A"
//  getbytes        ..... a stupid implementation of memcpy - prefer memcpy instead !!!
//  str2ip32        ..... converts "192.168.0.1"       into       3232235521 (u_int32_t)
//  str2ip32_rev    .....          same but assumes network byte order
//  type2str        ..... converts a u_int16_t into a string, e. g. 0x800 into "08:00"
//  
////////////////////////////////////////////////////////////////////////////////////////////


#include "mz.h"



// converts MAC address specified in str into u_int8_t array
// Usage: str2hex_mac ( "00:01:02:aa:ff:ee", src_addr )
// Returns 1 if specified MAC address string is invalid, 0 upon success.
int str2hex_mac(char* str, u_int8_t *addr)
{
   char *hs;
   int i;
   unsigned int test;
   char tmp[32];

   strcpy(tmp,str); // necessary because strtok cannot operate on fixed strings
   
   hs=(char*)strtok(tmp,"-:., ");

   for (i=0; i<6; i++)
     {
	test = (unsigned int) strtol (hs, NULL, 16);
	if (test>0xff) return 1;
	addr[i]=(u_int8_t) strtol (hs, NULL, 16);
	hs = strtok(NULL,"-:., ");
	if ( (hs == NULL ) && (i!=5) )
	     {
		// Not a valid MAC address
		return 1;
	     }
     }
   
   if (hs!=NULL) return 1; // more than 6 bytes
     
   return 0;
}




// Converts ascii hex values (string) into integer array
// For example "1a 00:00-2f" will be converted to {26, 0, 0, 47}
// 
// NOTE: n ist the max number of bytes to be converted
// 
// RETURN VALUE: number of bytes converted 
//               or -1 upon failure
// 
int str2hex(char* str, u_int8_t *hp, int n)
{
	char *hs;
	int curval,i;
	
	
	if (strlen(str)==0) return 0;
	
	char tmp[8192]=""; //for very long payloads 
	
	strncpy(tmp,str,8191); // necessary because strtok cannot operate on fixed strings
	
	hs=(char*)strtok(tmp,"-:., ");
	
	i=0;
	do
	{       n--;
		curval=strtol(hs,NULL,16);
		if (curval>0xff) return -1;
		hp[i]=(u_int8_t) curval;
		i++;
	}
	while ((n) && ((hs=(char*)strtok(NULL,"-:., "))!= NULL));
	
	return i; // return the length of the array
}



// Converts ascii numbers (terminated string) into integer array
// Every byte can be specified as integers {0..255}
// For example "192.16.1.1" will be converted to {C0, 10, 01, 01}
// 
// NOTE: Returns the number of converted bytes!
int num2hex(char* str, u_int8_t *hp)
{
   char *hs;
   int i;
   unsigned int curval;
   
   if (strlen(str)==0) return 0;
   
   char tmp[8192]=""; //for very long payloads 
     
   strncpy(tmp,str,8192); // necessary because strtok cannot operate on fixed strings
   
   hs = (char*) strtok (tmp,"-:., ");

   i=0;
   do
     {
	curval =  (unsigned int) str2int(hs);
	if (curval<256)
	  {
	     hp[i] = (u_int8_t) curval;
	     i++;
	  }
     }
   while ((hs=(char*)strtok(NULL,"-:., "))!= NULL);
   //hp[i]='\0'; // termination not necessary

   return i;
}



// Convert array of integers into string of hex
// E.g. {0,1,10} => "00-01-0A"
// Useful for verification messages. 
int bs2str(u_int8_t *bs, char* str, int len)
{
   int i;
   char t[4];
   
   str[0]='\0';
   
   for (i=0; i<len; i++)
     {
//	if (bs[i]<16) strcat(str,"0"); // enforce two hex digits (e.g. "0a")
	
	sprintf(t,"%02x:",bs[i]);
	strcat(str,t);
     }
   str[strlen(str)-1]='\0'; //remove the last ":"
   return 1;
}


// Extract contiguous sequence of bytes from an array
// NOTE: first element has number 1 !!!
// THIS IS DEPRECATED: PREFER memcpy INSTEAD !!!
int getbytes(u_int8_t *source,
	     u_int8_t *target, 
	     int from,
	     int to)
  
{
   int i;

   // Check wrong arguments
   if  (from<1) 
     {
	return -1;
     }
   
   // copy bytes
   for (i=0; i<(to-from+1); i++)
       {
	  target[i]=source[from-1+i];
       }
   
   return 1;
}


// Converts an  IP address given in 'dotted decimal' into an unsigned 32-bit integer
// Example: "192.168.0.1" => 3232235521
u_int32_t str2ip32 (char* str)
{
	u_int32_t ip = 0;
	unsigned int a,b,c,d;
	int r;
	
	// check whether str really contains an IP address
	if (strlen(str)<3) return 0;
	if (str==NULL) return 0;
	
	if ((r=sscanf(str,"%i.%i.%i.%i",&a,&b,&c,&d))==0) return 0;
	if (r==EOF) return 0;
		
	/* or an alternative method...
	// these are the four bytes of a dotted decimal notation IP address:
	a = (unsigned int) strtol(strtok(str,"."), (char **)NULL, 10);
	b = (unsigned int) strtol(strtok(NULL,"."), (char **)NULL, 10);
	c = (unsigned int) strtol(strtok(NULL,"."), (char **)NULL, 10);
	d = (unsigned int) strtol(strtok(NULL,"."), (char **)NULL, 10);
	*/
	
	if ((a>255)||(b>255)||(c>255)||(d>255)) return 0;
	
	ip = d + 256*c + 256*256*b + 256*256*256*a;
      
	//check with: 
	//printf("str2ip32 got 4 bytes: %i %i %i %i\n",a,b,c,d); 
	//printf("str2ip32 returned %u\n",ip);
	
	return ip;
}


// Converts an  IP address given in 'dotted decimal' into an unsigned 32-bit integer
// This version does the same as str2ip32() but in 'network byte order'
u_int32_t str2ip32_rev (char* str)
{
	u_int32_t ip = 0;
	unsigned int a,b,c,d;
	int r;
	
	// check whether str really contains an IP address
	if (strlen(str)<3) return 0;
	if (str==NULL) return 0;
	
	if ((r=sscanf(str,"%i.%i.%i.%i",&a,&b,&c,&d))==0) return 0;
	if (r==EOF) return 0;
		
	/* or an alternative method...
	// these are the four bytes of a dotted decimal notation IP address:
	a = (unsigned int) strtol(strtok(str,"."), (char **)NULL, 10);
	b = (unsigned int) strtol(strtok(NULL,"."), (char **)NULL, 10);
	c = (unsigned int) strtol(strtok(NULL,"."), (char **)NULL, 10);
	d = (unsigned int) strtol(strtok(NULL,"."), (char **)NULL, 10);
	*/
	
	if ((a>255)||(b>255)||(c>255)||(d>255)) return 0;
	
	ip = a + b*256 + c*256*256 + d*256*256*256;
      
	//check with: 
	//printf("str2ip32 got 4 bytes: %i %i %i %i\n",a,b,c,d); 
	//printf("str2ip32 returned %u\n",ip);
	
	return ip;
}


// Converts a 2-byte value (e. g. a EtherType field)
// into a nice string using hex notation.
// Useful for verification messages.
// Example: type2str (tx.eth_type, msg) may result in msg="08:00"
// Return value: how many hex digits have been found.
int type2str(u_int16_t type, char *str)
{
   char hex[8];
   int i=0;
   
   (void) sprintf (hex, "%x",type);
   i=strlen(hex);
     
   switch (i)
     {
      case 1:
	str[0]='0';
	str[1]='0';
	str[2]=':';
	str[3]='0';
	str[4]=hex[0];
	str[5]='\0';
	break;
      case 2:
      	str[0]='0';
	str[1]='0';
	str[2]=':';
	str[3]=hex[0];
	str[4]=hex[1];
	str[5]='\0';
	break;
      case 3:
      	str[0]='0';
	str[1]=hex[0];
	str[2]=':';
	str[3]=hex[1];
	str[4]=hex[2];
	str[5]='\0';
	break;
      case 4:
	str[0]=hex[0];
	str[1]=hex[1];
	str[2]=':';
	str[3]=hex[2];
	str[4]=hex[3];
	str[5]='\0';
	break;
	
     }
   return i;
}


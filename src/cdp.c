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

/////////////////////////////////////////////////////////////////////
//
//  Send CDP packets
//
/////////////////////////////////////////////////////////////////////


#include "mz.h"
#include "cli.h"


#define MZ_CDP_HELP \
   		"| CDP type: Send arbitrary CDP packets.\n" \
		"| Note:\n" \
		"| - The Ethernet dst and src MAC addresses can be specified but can be also 'rand'.\n" \
		"| - If dst and src are NOT specified then practical defaults are used (src=own MAC, dst=01:00:0C:CC:CC:CC).\n" \
		"|\n" \
		"|  ARGUMENT SYNTAX: -t cdp [arguments]\n" \
		"|\n" \
		"|  ARGUMENTS:\n" \
		"|\n" \
		"|    version ...... 0-255, default: 2\n" \
		"|    ttl     ...... 0-255, default: 180 s\n" \
		"|    sum     ...... 0000-ffff, default: automatically computed\n" \
		"|\n" \
		"|   TLVs:                  Description:                           Example:\n" \
		"|\n" \
		"|    tlv_id        ....... Device ID                              Mausezahn station\n" \
		"|    tlv_address   ....... Sending interface address              10.1.1.2\n" \
		"|    tlv_portid    ....... Port Identifier                        2/23\n" \
		"|    tlv_cap       ....... Capabilities (hex<7f)                  2a\n" \
		"|    tlv_version   ....... Software Version                       ver3.0\n" \
		"|    tlv_platform  ....... Hardware Platform                      WS-C6509-E\n" \
		"|    tlv_vtpdomain ....... VTP Management Domain                  MyVTPdomain\n" \
		"|    tlv_native    ....... Native VLAN number (0-4095)            42\n" \
		"|    tlv_duplex    ....... Full or half duplex                    full\n" \
		"|    tlv_mgmt      ....... Management IP address                  192.168.1.2\n" \
		"|\n" \
		"|    tlv        .......... Create ANY TLV using the format: tlv=<type>/<value>, such as tlv=42/mausezahn\n" \
		"|                    Note: Currently you must omit spaces within <value>! Use underscore instead.\n" \
		"|    tlvhex     .......... Create ANY TLV and specify the value in hexformat, such as tlv=42/ca:fe:ba:be\n" \
		"|    payload|p  .......... Optional additional TLVs or any other bytes specified in hex\n" \
		"|\n" \
		"|    When the tlv* arguments are used, the TLV length parameter is automatically set.\n" \
		"|\n" \
		"|    The capability flags from MSB to LSB are:\n" \
		"|      0 - Repeater - IGMP - Host - Switch - SrcRouteBrdg - TranspBrdg - Router\n" \
		"|\n" \
		"|    Optionally the keyword 'change' will create a different System name TLV every time a CDP\n" \
		"|    packet is sent. This can be used to fill up a CDP database with different test values.\n" \
		"|    Additionally use the '-a rand' command to use different source MAC addresses.\n" \
		"|\n" \
		"| EXAMPLES:\n" \
		"|\n" \
		"|    Announce Device ID 'Espresso3000', Capabilities: Router, native VLAN 301:\n" \
		"|    mz eth0 -t cdp \"tlv_id=Espresso3000, tlv_cap=01, tlv_native=301\"\n" \
		"|\n" \
		"|    Create another TLV using the payload interface (here voice VLAN 400):\n" \
		"|    mz eth0 -t cdp p=00:0e:00:07:01:01:90\n" 

		
		


u_int16_t checksum16 (u_int16_t len, u_int8_t buff[])
{
   
   u_int16_t word16;
   u_int32_t sum=0;
   u_int16_t i;
       
   // make 16 bit words out of every two adjacent 8 bit words in the packet and add them up
   for (i=0; i<len; i=i+2)
     {
	word16 =((buff[i]<<8)&0xFF00)+(buff[i+1]&0xFF);
	sum = sum + (u_int32_t) word16;
     }
   
   // take only 16 bits out of the 32 bit sum and add up the carries
   while (sum>>16)
     sum = (sum & 0xFFFF)+(sum >> 16);
   
   // one's complement the result
   sum = ~sum;
   
   return ((u_int16_t) sum);
}


// Creates a TLV and returns the whole length of the TLV
unsigned int create_tlv (u_int16_t        type,       // The 16-bit TYPE number
			 u_int8_t        *value,      // The VALUE as prepared hex-array
			 unsigned int     value_len,  // needed because VALUE maybe not \0 terminated
			 u_int8_t        *target)     // the RESULT i. e. the complete TLV
{
   unsigned int tlvlen;
   u_int8_t *x;
   
   x = (u_int8_t*) &type;    // set TYPE
   target[0] = *(x+1);
   target[1] = *(x);
   
   tlvlen = value_len + 4;   // set VALUE
   x = (u_int8_t*) &tlvlen; 
   target[2] = *(x+1);
   target[3] = *(x);

   target+=4;
   memcpy((void*) target, (void*) value, (size_t) value_len);
   
   return tlvlen;
}




// NOTE: The Length field indicates the total length, in bytes, of the type, length, and value fields!
//
// Interesting TLVs:
// 
// TYPE VALUE
// 0001 Device-ID 
// 0002 IP Addresses
// 0003 Port ID such as 2/22
// 0004 Capabilities (Len=8, consists of flags only: Router, TBrdg, SRBrdgm, Switch, Host, IGMP, Repeater)
// 0005 SW Version 
// 0006 Platform
// 0009 VTP Domain
// 000a Native VLAN, e.g. 00:0a 00:06 01:2d identifies native VLAN number 301 (=01:2d)
// 000b Duplex
// 000e VoIP VLAN, e.g. 00:0e 00:07 01 01:90 identifies DATA (=01) and VLAN 400 (=01:90)
// 0012 Trust Bitmap
// 0013 Untrusted Port CoS
// 0014 System Name (!!!)
// 0015 System Object Identifier
// 0016 Management Address (!!!), e.g. 0016 0011(=len 17) 00-00-00-01(=one IP only) 01-01-cc-00-04-90-fe-f8-10(=144.254.248.16)
// 0017 Location
// 001a Unknown (???)
// 
// The IP address format is a bit strange as 0016 for example demonstrates...



int send_cdp ()
{
   libnet_t             *l;
   libnet_ptag_t         t;
   char 
     errbuf[LIBNET_ERRBUF_SIZE],
     argval[1024];
   
   u_int8_t 
     packet[MAX_PAYLOAD_SIZE], // this one will finally contain the whole cdp packet (without LLC/SNAP!)
     *x,
     value[1024],   // USE THIS FOR ANYTHING YOU LIKE !!!
     value1[1024],  // This one is reserved for some code - Don't use it again!
     value2[1024],  // This one is reserved for some code - Don't use it again!
     tlv[1024],
     default_id[15] = "Mausezahn rules",
     llcsnap[8]= 
     {
	0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00
     };

   unsigned int
     len=0,    
     len1=0,
     len2=0,
     type1,
     type2;
   
   u_int16_t
     dummy16=0,
     tlv_len=0;
   
   u_int32_t 
     next_pbyte=0, // points to the next free byte in tx.cdp_payload
     dummy32=0,
     packet_s;

   char      
     pld[2048];
   
   
   unsigned int i=0, count, delay;
   int 
     eth_src_rand=0, 
     change_value=0;
   long int j=0;
   
   
   if (tx.dot1Q)
     {
	fprintf(stderr," Note: CDP mode does not support 802.1Q builder.\n");
	exit(1);
     }
   
   if (tx.mpls)
     {
	fprintf(stderr," Note: CDP mode does not support MPLS builder.\n");
	exit(1);
     }


   if (getarg(tx.arg_string,"help", NULL)==1)
     {
	if (mz_port)
	  {
	     cli_print(gcli, "%s", MZ_CDP_HELP);
	     return -1;
	  }
	else
	  {
	     fprintf(stderr,"\n" 
		     MAUSEZAHN_VERSION
		     "\n%s", MZ_CDP_HELP);
	     exit(0);
	  }
	
     }

   ///////////////////////////////////////////////////////////////////////
   // initial defaults:
   if (tx.cdp_ttl==0) tx.cdp_ttl=0xb4; // 180 seconds
   
   if (tx.cdp_version==0) tx.cdp_version = 0x02;
   
   // The ID is the only required TLV
   // If another function already specified it then it must also set the lenght:
   if (tx.cdp_tlv_id_len==0) // not set
     {
	memcpy((void*) tx.cdp_tlv_id, (void*) default_id, 15);
	tx.cdp_tlv_id_len=15;
     }
   
   
   

   ///////////////////////////////////////////////////////////////////////
   //
   // Now check for user arguments:
   

   if ( (getarg(tx.arg_string,"version", argval)==1) || (getarg(tx.arg_string,"ver", argval)==1) )
     {
	if (str2int(argval)>255)
	  {
	     fprintf(stderr," mz/send_cdp: version range exceeded, adjusted to max value.\n");
	     tx.cdp_version = 0xff;
	  }
	else
	  {
	     tx.cdp_version = (u_int8_t) str2int(argval);
	  }
     }

   
   if (getarg(tx.arg_string,"ttl", argval)==1)
     {
	if (str2int(argval)>255)
	  {
	     fprintf(stderr," mz/send_cdp: TTL range exceeded, adjusted to max value.\n");
	     tx.cdp_ttl = 0xff;
	  }
	else
	  {
	     tx.cdp_ttl = (u_int8_t) str2int(argval);
	  }
     }

   if (getarg(tx.arg_string,"sum", argval)==1)
     {

	if (strtol(argval,NULL,16)>65535)
	  {
	     fprintf(stderr," mz/send_cdp: checksum range exceeded, adjusted to max value.\n");
	     tx.cdp_sum = 0xffff;
	  }
	else
	  {
	     tx.cdp_sum = (u_int16_t) strtol(argval,NULL,16);
	  }
     }
   
   ////////
   //
   // Provide a basic interface for the most important TLVs:
   //
   
   if (getarg(tx.arg_string,"tlv_id", argval)==1)
     {
	// simply overwrite current content in tx.cdp_tlv_id
	tx.cdp_tlv_id[0] = '\0';
	strncpy((char*) tx.cdp_tlv_id, argval,2048);
	tx.cdp_tlv_id_len = strlen ((char*)tx.cdp_tlv_id);
     }

   
   //
   // This is something ugly ;-)
   //
   
   if (getarg(tx.arg_string,"change", NULL)==1)
     {
	memcpy((void*) tx.cdp_tlv_id, (void*) "Mausezahn 00000000000", 21);
	tx.cdp_tlv_id_len=21;
	change_value = 1; 
     }
   
   
   //
   // NOW write the ID-TLV;  this is the only REQUIRED TLV !!!
   // and this TLV should be the FIRST one - that's why we 
   // write it immediately here now:
   //  
   tlv_len = create_tlv (1, tx.cdp_tlv_id, tx.cdp_tlv_id_len, tlv);
   memcpy((void*) tx.cdp_payload+next_pbyte, (void*) tlv, tlv_len);
   next_pbyte += tlv_len;
   
   //
   // Now the other TLVs may follow:
   //
   
   //  Format: Type=2, Len=17, NrOfAddr=00:00:00:01, Protocol=01:01:cc:00, AddrLen=4, IP_Address
   // Example: tlv_address = 192.168.1.10
   //    Note: currently only one address supported  
   if (getarg(tx.arg_string,"tlv_address", argval)==1)
     {
	dummy32 = str2ip32 (argval);
	x = (u_int8_t*) &dummy32;
	value[0] = 0x00; // NrOfAddr
	value[1] = 0x00;
	value[2] = 0x00;
	value[3] = 0x01;

	value[4] = 0x01; // Protocol
	value[5] = 0x01;
	value[6] = 0xcc;
	value[7] = 0x00;
	
	value[8] = 0x04; // AddrLen
	
	value[9] = *(x+3);
	value[10] = *(x+2);
	value[11] = *(x+1);
	value[12] = *(x);

	tlv_len = create_tlv (2, value, 13, tlv);
	memcpy((void*) tx.cdp_payload+next_pbyte, (void*) tlv, tlv_len);
	next_pbyte += tlv_len;
     }

   
   
   //  Format: Type=3
   // Example: tlv_portid = 2/23
   //    Note: 
   if (getarg(tx.arg_string,"tlv_portid", argval)==1)
     {
	tlv_len = create_tlv (3, (u_int8_t*) argval, strlen(argval), tlv);
	memcpy((void*) tx.cdp_payload+next_pbyte, (void*) tlv, tlv_len);
	next_pbyte += tlv_len;
     }
   
   //  Format: Type=4
   // Example: "tlv_cap = 2a"    (= 0010 1010)
   //   Flags: MSB=0 - Repeater - IGMP - Host - Switch - SrcRouteBrdg - TranspBrdg - Router(LSB)
   if (getarg(tx.arg_string,"tlv_cap", argval)==1)
     {
	if (strlen(argval)>2)
	  {
	     fprintf(stderr," mz/send_cdp: Capability value must be specified as a two-digit hexadecimal value!\n");
	     exit(1);
	  }
	else
	  {
	     str2hex(argval, value+3, 1020);
	     if (value[3]>0x7f)
	       {
		  fprintf(stderr," mz/send_cdp: Capability value must not exceed 7F(hex)\n");
		  exit(1);
	       }
	  }
	
	value[0]=0x00;
	value[1]=0x00;
	value[2]=0x00;
	tlv_len = create_tlv (4, value, 4, tlv);
	memcpy((void*) tx.cdp_payload+next_pbyte, (void*) tlv, tlv_len);
	next_pbyte += tlv_len;
     }
   
   
   //  Format: Type=5
   // Example: tlv_version = Mausezahn_version_xyz
   //    Note: Avoid spaces, use underscore instead
   if (getarg(tx.arg_string,"tlv_version", argval)==1)
     {
	tlv_len = create_tlv (5, (u_int8_t*) argval, strlen(argval), tlv);
	memcpy((void*) tx.cdp_payload+next_pbyte, (void*) tlv, tlv_len);
	next_pbyte += tlv_len;
     }
   
   
   //  Format: Type=6
   // Example: tlv_platform = WS-C6509-E
   //    Note: 
   if (getarg(tx.arg_string,"tlv_platform", argval)==1)
     {
	tlv_len = create_tlv (6, (u_int8_t*) argval, strlen(argval), tlv);
	memcpy((void*) tx.cdp_payload+next_pbyte, (void*) tlv, tlv_len);
	next_pbyte += tlv_len;
     }

   //  Format: Type=9
   // Example: tlv_vtpdomain = MyVTPdomain
   //    Note: 
   if (getarg(tx.arg_string,"tlv_vtpdomain", argval)==1)
     {
	tlv_len = create_tlv (9, (u_int8_t*) argval, strlen(argval), tlv);
	memcpy((void*) tx.cdp_payload+next_pbyte, (void*) tlv, tlv_len);
	next_pbyte += tlv_len;
     }   
   
   
   //  Format: Type=10, Len=17
   // Example: tlv_native = 100
   //    Note: 
   if (getarg(tx.arg_string,"tlv_native", argval)==1)
     {
	dummy16 = (u_int16_t) str2int(argval);
	if (dummy16>4095)
	  {
	     fprintf(stderr," mz/WARNING: native VLAN value exceeds max value (4095) - hope you know what you do!\n");
	  }
	
	x = (u_int8_t*) &dummy16;
	value[0] = *(x+1);
	value[1] = *(x);
	tlv_len = create_tlv (10, value, 2, tlv);
	memcpy((void*) tx.cdp_payload+next_pbyte, (void*) tlv, tlv_len);
	next_pbyte += tlv_len;
     }
   
   //  Format: Type=11
   // Example: tlv_duplex = full | half 
   //    Note: 
   if (getarg(tx.arg_string,"tlv_duplex", argval)==1)
     {
	if (strncmp(argval,"full",10)==0)
	  {
	     value[0]=0x01;
	  }
	else if (strncmp(argval,"half",10)==0)
	  {
	     value[0]=0x00;
	  }
	else
	  {
	     value[0]=(u_int8_t) str2int(argval);
	     if (!quiet)
	       {
		  fprintf(stderr," mz/Warning: Only keywords 'half' or 'full' supported."
			         " Will interprete input as integer.\n");
	       }
	     
	  }
	
	tlv_len = create_tlv (11, value, 1, tlv);
	memcpy((void*) tx.cdp_payload+next_pbyte, (void*) tlv, tlv_len);
	next_pbyte += tlv_len;
     }
   
   //  Format: Type=22, Len=17, NrOfAddr=00:00:00:01, Protocol=01:01:cc:00, AddrLen=4, IP_Address
   // Example: tlv_mgmt = 10.1.1.99
   //    Note: Same format as tlv_address
   if (getarg(tx.arg_string,"tlv_mgmt", argval)==1)
     {
	dummy32 = str2ip32 (argval);
	x = (u_int8_t*) &dummy32;
	value[0] = 0x00; // NrOfAddr
	value[1] = 0x00;
	value[2] = 0x00;
	value[3] = 0x01;

	value[4] = 0x01; // Protocol
	value[5] = 0x01;
	value[6] = 0xcc;
	value[7] = 0x00;
	
	value[8] = 0x04; // AddrLen
	
	value[9] = *(x+3);
	value[10] = *(x+2);
	value[11] = *(x+1);
	value[12] = *(x);

	tlv_len = create_tlv (22, value, 13, tlv);
	memcpy((void*) tx.cdp_payload+next_pbyte, (void*) tlv, tlv_len);
	next_pbyte += tlv_len;

     }
   
   
   
   //
   // Eventually there are two generic TLV interfaces: tlv and tlvhex
   // 

   if (getarg(tx.arg_string,"tlv", argval)==1)
     {
	// split in TYPE and VALUE
	sscanf(argval, "%u/%s",  &type1, value1);
	len1 = strlen((const char*) value1);
	
     }
   
   if (getarg(tx.arg_string,"tlvhex", argval)==1)
     {
	// split in TYPE and VALUE
	sscanf(argval, "%u/%s",  &type2, pld);
	len2 = str2hex(pld, value2, 1023);
     }

   
   // 
   // Finally the optional payload interface allows to specify subsequent TLVs or any other bytes:
   // 
   if ( (getarg(tx.arg_string,"payload", argval)==1) || (getarg(tx.arg_string,"p", argval)==1))
     {
	len = str2hex (argval, value, 1023);
	memcpy((void*) tx.cdp_payload+next_pbyte, (void*) value, len);
	next_pbyte += len;
     }
   

   
   ///////////////////////////////////////////////////////////////


   
   // Write other TLVs: First the ASCII specified:
   if (len1)
     {
	tlv_len = create_tlv (type1, value1, len1 , tlv);
	memcpy((void*) tx.cdp_payload+next_pbyte, (void*) tlv, tlv_len);
	next_pbyte += tlv_len;
     }
   
   // Write other TLVs: Then the HEX specified:
   if (len2)
     {
	tlv_len = create_tlv (type2, value2, len2 , tlv);
	memcpy((void*) tx.cdp_payload+next_pbyte, (void*) tlv, tlv_len);
	next_pbyte += tlv_len;
     }

   
   tx.cdp_payload_s = next_pbyte;
   
   // CHECK:
   //   bs2str(tx.cdp_payload, pld, tx.cdp_payload_s);
   //   printf("PAYLOAD= %s\n",pld);


////////////////////////////
//   
  
   // Open the link - for the intermediate CDP/LLC frame
   l = libnet_init(LIBNET_LINK_ADV, tx.device, errbuf);
   
   if (l == NULL)
     {
	fprintf(stderr, "%s", errbuf);
	exit(EXIT_FAILURE);
     }
   
   if (check_eth_mac_txt(ETH_DST))  // if '1' then user did not set MAC address (or problem occurred)
     {
	str2hex("01:00:0C:CC:CC:CC", tx.eth_dst, 6);
     }
   
   if (check_eth_mac_txt(ETH_SRC))  // if '1' then user did not set MAC address (or problem occurred)
     {
	// own mac per default (see init.c)
     }

   count = tx.count;
   eth_src_rand = tx.eth_src_rand;
   delay = tx.delay;
   
   // ---------------------------------------------------
   // If you want to change CDP fields during a LOOP then
   // START the loop from HERE:
   //

   ////////////////////////////////////
   // Now create the whole CDP packet:

   packet[0] = tx.cdp_version;            // VERSION
   packet[1] = tx.cdp_ttl;                // TTL
   packet[2] = 0x00;                      // CHECKSUM
   packet[3] = 0x00;
   
   // Now add the TLVs
   memcpy ((void*) packet+4, (void*) tx.cdp_payload, tx.cdp_payload_s);
   packet_s = tx.cdp_payload_s + 4;

   // Check whether packet is an even length (i.e. is a multiple of 16 bits = 2 bytes);
   if (packet_s%2>0) 
     {
	packet[packet_s++]=0x00;
	packet[packet_s++]=0x17;
	packet[packet_s++]=0x00;
	packet[packet_s++]=0x05;
	packet[packet_s++]=0x00;
     }
   
   
   // Now update the checksum:
   if (tx.cdp_sum == 0) // Otherwise user specified the checksum (usually a wrong one ;-))
     {
	tx.cdp_sum = checksum16(packet_s, packet); 
     }
   x = (u_int8_t *) &tx.cdp_sum;          
   packet[2] = *(x+1);
   packet[3] = *(x);
   
   // CHECK the CDP packet
   //bs2str(packet, pld, packet_s);
   //printf("CDP= %s\n",pld);

   
//   printf("Len = %u Checksum = %04x \n", packet_s-8, tx.cdp_sum);
   

   ///////////////////////////////////////////////////////////////
   // Now create the whole tx.eth_payload = LLC/SNAP + CDP packet
   // First the LLC/SNAP header:
   memcpy ((void*) tx.eth_payload, (void*) llcsnap, 8);
   memcpy ((void*) tx.eth_payload+8, (void*) packet, packet_s);
   tx.eth_payload_s = packet_s +8;
   

   // CHECK the whole 802.3 payload
   // bs2str(tx.eth_payload, pld, tx.eth_payload_s);
   // printf("PACKET = %s\n",pld);

   
   t = libnet_build_802_3 (tx.eth_dst, 
			   tx.eth_src,
			   tx.eth_payload_s, 
			   tx.eth_payload,
			   tx.eth_payload_s,
			   l, 
			   0);
   
   
   
   // this is for the statistics:
   mz_start = clock();
   total_d = tx.count;
   
   if (!count) goto AGAIN;

   for (i=0; i<count; i++)
     {
	AGAIN:
	
	if (eth_src_rand)
	  {
	     tx.eth_src[0] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256) & 0xFE; // keeps bcast-bit zero
	     tx.eth_src[1] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
	     tx.eth_src[2] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
	     tx.eth_src[3] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
	     tx.eth_src[4] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
	     tx.eth_src[5] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);

	     t = libnet_build_802_3 (tx.eth_dst, 
				     tx.eth_src,
				     tx.eth_payload_s, 
				     tx.eth_payload,
				     tx.eth_payload_s,
				     l, 
				     t);

	  }

	
	libnet_write(l);
	
	if (verbose)
	  {
	     bs2str(tx.eth_payload+8, pld, tx.eth_payload_s-8);
	     fprintf(stderr," Sent CDP: (Ver=%u, TTL=%u) %s\n", tx.cdp_version, tx.cdp_ttl, pld);
	  }
	
	if (delay) SLEEP (delay);
	
	if (change_value)
	  {
	     // Note: this only works when default_id has been used
	     //       because otherwise the TLV with the ID might be too short!!!

	     // Offset 26-36 contains 00000000000 (of the default id)
	     // ASCII 0x30-0x39 contain numbers 0-9

	     tx.eth_payload[26] = (u_int8_t) (0x30+ ((float) rand()/RAND_MAX)*10);
	     tx.eth_payload[27] = (u_int8_t) (0x30+ ((float) rand()/RAND_MAX)*10);
	     tx.eth_payload[28] = (u_int8_t) (0x30+ ((float) rand()/RAND_MAX)*10);
	     tx.eth_payload[29] = (u_int8_t) (0x30+ ((float) rand()/RAND_MAX)*10);
	     tx.eth_payload[30] = (u_int8_t) (0x30+ ((float) rand()/RAND_MAX)*10);
	     tx.eth_payload[31] = (u_int8_t) (0x30+ ((float) rand()/RAND_MAX)*10);
	     tx.eth_payload[32] = (u_int8_t) (0x30+ ((float) rand()/RAND_MAX)*10);
	     tx.eth_payload[33] = (u_int8_t) (0x30+ ((float) rand()/RAND_MAX)*10);
	     tx.eth_payload[34] = (u_int8_t) (0x30+ ((float) rand()/RAND_MAX)*10);
	     tx.eth_payload[35] = (u_int8_t) (0x30+ ((float) rand()/RAND_MAX)*10);
	     tx.eth_payload[36] = (u_int8_t) (0x30+ ((float) rand()/RAND_MAX)*10);

	     tx.eth_payload[10] = 0x00;  // reset the checksum
	     tx.eth_payload[11] = 0x00;
	     tx.cdp_sum = checksum16(tx.eth_payload_s-8, tx.eth_payload+8); 
	     x = (u_int8_t *) &tx.cdp_sum;          
	     tx.eth_payload[10] = *(x+1);
	     tx.eth_payload[11] = *(x);
	     
	     t = libnet_build_802_3 (tx.eth_dst, 
				     tx.eth_src,
				     tx.eth_payload_s, 
				     tx.eth_payload,
				     tx.eth_payload_s,
				     l, 
				     t);

	     j++;
	     
	  }
	
	if (!count) goto AGAIN;
     }
   
   
   // Destroy contexts
   libnet_destroy(l); 

   

   return t;

   
}

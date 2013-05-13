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
#include "mops.h"
#include "cli.h"


// PURPOSE
// 
//   Determine destination MAC address to provide direct or indirect
//   delivery of IP packets, depending on which is appropriate.
//  
//   Doing this, the caller must provide 
//     1) A pointer to the interface (within the device_list)
//     2) The destination IP address
//     3) A pointer to the destination MAC address 
//
//   If a Class D (multicast) address is given, a proper IEEE multicast MAC
//   address is derived.
//   
// EXAMPLE
//  
//    u_int8_t ip[4], 
//             mac[6];
//   
//    mops_hton4 (mp->ip_src, ip);
//   
//    mops_ip_get_dst_mac(&device_list[0], ip, mac);
//   
// RETURN VALUES
// 
//    0 upon success
//    1 upon error
// 
int mops_ip_get_dst_mac(struct device_struct *dev, u_int8_t *ip, u_int8_t *mac)
{    
	int i;
	u_int8_t dst_net[4];

	if ((dev==NULL)||(ip==NULL)||(mac==NULL)) return 1;

	// Multicast address?
	if ((0xe0 & ip[0]) == 0xe0) {
		mac[0] = 0x01;
		mac[1] = 0x00;
		mac[2] = 0x5e;
		mac[3] = ip[1] & 127;
		mac[4] = ip[2];
		mac[5] = ip[3];
		return 0;
	}
	
	// Is destination network == local network?
	for (i=0; i<4; i++) {
		dst_net[i] = ip[i] & (u_int8_t) dev->mask[i];
	}
	
	if (compare_ip(dst_net, dev->net)==0) { 
		// dst is on local LAN => resolve MAC!
		service_arp(dev->dev, ip, mac);
	} else { // dst is on a remote network => use default gw!
		for (i=0; i<6; i++) mac[i] = dev->mac_gw[i];
	}

	return 0;
}


///////////////////////////////////////////////////////////////////////////////////
//
// PURPOSE
//
//   Accept a DSCP specification as string argument 
//   and configure the IP-ToS field accordingly.
// 
// EXAMPLE STRINGS
// 
//   AF32        .... specify AF codepoint with class 3 and drop probability 2
//   EF          .... specify Expedited Forwarding
//   CS7         .... specify Code Selector 7
//   101110      .... specify the DSCP in binary
//   56          .... specify the DSCP in decimal
//
// RETURN VALUES
// 
//  -1   general bad argument format
//   0   upon success
//   1   Invalid AF format (Format: AFxy, e. g. af31 or AF23)
//   2   Invalid CS format
//   3   Invalid decimal DSCP value
//   
int mops_ip_dscp (struct mops* mp, char *argv)
{
   int i;
   char cs[4], ps[4], str[16];
   u_int8_t c=0, p=0, dscp=0;
   
   if (strlen(argv)==0) return -1;
   strncpy(str,argv,15);
   
   if (strncasecmp(str, "af", 2)==0)    // e.g. 'AF32' or 'af41'
     {
	if (strlen(str)!=4)  return 1; // ERROR: Invalid AF codepoint
	i=sscanf(str, "%*[afAF]%c%c", cs, ps);
	cs[1]=0x00; ps[1]=0x00;
	c=(u_int8_t) str2int(cs);
	p=(u_int8_t) str2int(ps);
	if ((c<1)||(c>4)||(p<1)||(p>3)) return 1;
	// Now create correct ToS-byte representation: This is simple, since if a=3 and b=1
	// we have in binary already a=0000 0011 and b=0000 0001 and with bit-shifting we 
	// get the desired dscp=011 01 000 (the least signfificant three bits are always 0).
	c <<=5;
	p <<=3;
	dscp = c | p;
     }
   else if (strncasecmp(str, "cs", 2)==0)    // e.g. 'CS7' or 'cs4'
     {
	if (strlen(str)!=2)  return 2; // ERROR: Invalid Code Selector
	i=sscanf(str, "%*[afAF]%c", cs);
	cs[1]=0x00;
	c=(u_int8_t) str2int(cs);
	if (c>7) return 2; 
	c <<=5;
	dscp = c; 
     }
   else if (mz_strcmp(str, "ef", 2)==0) // e.g. 'ef' or 'EF'
     {
	dscp = 0xb8;  // = DSCP 46 = 101110 00 or 1011 1000
     }
   else if (mz_strisbinary(str)==6)  // binary, e. g. 101110
     {
	for (i=0; i<6; i++) if (str[i]=='1') dscp |= ( 0x01 << (5-i) ); 
	dscp <<= 2;
     }
   else if (strlen(str)==2) // decimal DSCP value
     {
	if ( !(isdigit(str[0])) || !(isdigit(str[1]))) return 3;
	dscp = (u_int8_t) str2int(str);
	if (dscp>63) return 3;
	dscp <<= 2;
     }
   else return -1;
   
   // TEST: printf("dscp=%02x\n",dscp);
   mp->ip_tos = dscp;
   
   return 0;
}








//
// IP TOS-FIELD FORMAT
//
//      MSB                                       LSB
//       0     1     2     3     4     5     6     7
//    +-----+-----+-----+-----+-----+-----+-----+-----+   Note that the bit numbering is usually from right
//    |                 | Del   Trp   Rel   Cst |     |   to left, but here is the original pic of the RFC
//    |   PRECEDENCE    |          TOS          | MBZ |   1349. Also here, the MSB is left (strangely bit 0)
//    |                 |                       |     |   and the LSB is right (strangely bit 7).
//    +-----+-----+-----+-----+-----+-----+-----+-----+
//      
// ARGUMENTS
//                                               if unused
//   ipp  ... IP Precedence (0..7)                  or -1
//   tos  ... Type of Service (0..15)               or -1
//   mbz  ... if 1 sets MBZ                         or 0
int mops_ip_tos (struct mops* mp, int ipp, int tos, int mbz)
{
   u_int8_t TOS=0;
   
   if (ipp!=-1)
     {
	if (ipp>7) return 1; // Invalid IPP value
	TOS |= (ipp << 5);
     }

   if (tos!=-1)
     {
	if (tos>15) return 2; // Invalid ToS value
	TOS |= (tos << 1);
     }

   if (mbz==1) // not used if mbz is either 0 or -1
     {
	TOS |= 0x01; // set
     }
   
   mp->ip_tos = TOS;
   
   return 0;
}



//
//
// =================== ONLY IP OPTION HANDLING FUNCTION BELOW ================
// 
///////////////////////////////////////////////////////////////////////////////



///////////////////////////////////////////////////////////////////////////////
// 
// There are two cases for the format of an option:
// 
//   Case 1:  A single octet of option-type.
//   Case 2:  An option-type octet, an option-length octet, and the
//            actual option-data octets.
// 
//  The option-length octet counts the WHOLE number of bytes of the option
//
//  The option-type consists of: 
//  
//  +--------+--------+--------+--------+--------+--------+--------+--------+
//  | copied |  option class   |         number (identifies option)         |
//  |  flag  |                 |                                            |
//  +--------+-----------------+--------------------------------------------+
//  
// 
// The following Internet options are defined in RFC 791:
//
//        CLASS NUMBER LENGTH DESCRIPTION
//        ----- ------ ------ -----------
//          0     0      -    End of Option list.  This option occupies only
//                            1 octet; it has no length octet.
//          0     1      -    No Operation.  This option occupies only 1
//                            octet; it has no length octet.
//          0     2     11    Security.  Used to carry Security,
//                            Compartmentation, User Group (TCC), and
//                            Handling Restriction Codes compatible with DOD
//                            requirements.
//          0     3     var.  Loose Source Routing.  Used to route the
//                            internet datagram based on information
//                            supplied by the source.
//          0     9     var.  Strict Source Routing.  Used to route the
//                            internet datagram based on information
//                            supplied by the source.
//          0     7     var.  Record Route.  Used to trace the route an
//                            internet datagram takes.
//          0     8      4    Stream ID.  Used to carry the stream
//                            identifier.
//          2     4     var.  Internet Timestamp.
// 
// 
// Possible options and associated number in mp->ip_option_used
// 
//   1 - Security and handling restrictions (for military applications)
//   2 - Record route
//   4 - Timestamp
//   8 - Loose source routing
//  16 - Strict source routing
//            
//

// *** See RFCs 791, 1071, 1108 ***

// Remove all options
int mops_ip_option_remove_all (struct mops* mp)
{
	mp->ip_option_used = 0;
	mp->ip_option_s = 0;
   return 0;
}


// Add no-option
int mops_ip_option_nop (struct mops* mp)
{
   
   return 0;
}

// Add end of option list 
int mops_ip_option_eol (struct mops* mp)
{
   
   return 0;
}



// Add loose source route option
int mops_ip_option_lsr (struct mops* mp)
{
   
   return 0;
}

// Add strict source route option
int mops_ip_option_ssr (struct mops* mp)
{
   
   return 0;
}

// Add record route option
int mops_ip_option_rr (struct mops* mp)
{
   
   return 0;
}

// Add time stamp option
int mops_ip_option_ts (struct mops* mp)
{
   
   return 0;
}



// Add security option.
//
// This option provides a way for hosts to send security, compartmentation, 
// handling restrictions, and TCC (closed user group) parameters.  The format 
// for this option is as follows:
//
//          +--------+--------+---//---+---//---+---//---+---//---+
//          |10000010|00001011|SSS  SSS|CCC  CCC|HHH  HHH|  TCC   |
//          +--------+--------+---//---+---//---+---//---+---//---+
//           Type=130 Length=11
//
//        Security (S field):  16 bits
//
//          Specifies one of 16 levels of security (eight of which are
//          reserved for future use).
//
//            00000000 00000000 - Unclassified
//            11110001 00110101 - Confidential
//            01111000 10011010 - EFTO
//            10111100 01001101 - MMMM
//            01011110 00100110 - PROG
//            10101111 00010011 - Restricted
//            11010111 10001000 - Secret
//            01101011 11000101 - Top Secret
//            00110101 11100010 - (Reserved for future use)
//            10011010 11110001 - (Reserved for future use)
//            01001101 01111000 - (Reserved for future use)
//            00100100 10111101 - (Reserved for future use)
//            00010011 01011110 - (Reserved for future use)
//            10001001 10101111 - (Reserved for future use)
//            11000100 11010110 - (Reserved for future use)
//            11100010 01101011 - (Reserved for future use)
//
//
//        Compartments (C field):  16 bits
//
//          An all zero value is used when the information transmitted is not 
//          compartmented.  Other values for the compartments field may be obtained 
//          from the Defense Intelligence Agency.
//
//        Handling Restrictions (H field):  16 bits
//
//          The values for the control and release markings are alphanumeric digraphs 
//          and are defined in the Defense Intelligence Agency Manual DIAM 65-19, 
//          "Standard Security Markings".
//
//        Transmission Control Code (TCC field):  24 bits
//
//          Provides a means to segregate traffic and define controlled communities 
//          of interest among subscribers. The TCC values are trigraphs, and are available 
//          from HQ DCA Code 530.
//
//        Must be copied on fragmentation.  This option appears at most
//        once in a datagram.

int mops_ip_option_sec (struct mops* mp)
{
   
   return 0;
}


// Add the IP Router Alert Option - a method to efficiently signal
// transit routers to more closely examine the contents of an IP packet.
// See RFC 2113, and FYI also 3175 (RSVP Aggregation), and RFC 5350 
// (new IANA-defined Router Alert Options (RAO)).
// 
// The Router Alert option has the following format:
//
//     +--------+--------+--------+--------+
//     |10010100|00000100|  2 octet value  |
//     +--------+--------+--------+--------+
//
// Type:
//   Copied flag:  1 (all fragments must carry the option)
//   Option class: 0 (control)
//   Option number: 20 (decimal)
//			
// Length: 4
//	
// Value:  A two octet code with the following values:
//   0 - Router shall examine packet
//   1-65535 - Reserved
//	
// RETURN VALUE: 0 upon success
//               1 upon failure
//               
int mops_ip_option_ra (struct mops* mp, int value)
{
	int ptr;
	u_int16_t val;
	
	if ((mp==NULL) || (value>0xffff)) return 1;

	val = (u_int16_t) value;
	
	ptr = mp->ip_option_s; // add option at the end of existing option list (if any)
	mp->ip_option_used=20;  
	
	// create option header
	mp->ip_option[ptr] = 0x94;

	ptr++;
	mp->ip_option[ptr] = 0x04;

	ptr++;
	mops_hton2 (&val, &mp->ip_option[ptr]);
	ptr+=2;
	mp->ip_option_s=4;
   
	return 0;
}

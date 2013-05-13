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




// -- TOC: --
// int                mops_update             (stuct mops *mp)


#include "mz.h"
#include "mops.h"


   
// This is the very basic MOPS update function. It simply updates the whole
// MOPS frame specified by the pointer mp. If you only want to update specific
// details then please see the other related specialized functions which are
// more effcient.
//
int mops_update (struct mops *mp)
{
	int
		i,    // the standard loop variable; outside a loop fully undetermined!
		t,    // temp
		fp=0; // frame pointer; always points to NEXT byte
	
	char *x;
	u_int8_t  t8=0;  // temp 8 bits
	u_int16_t t16; // temp 16 bits
	
	u_int8_t ip_pseudo_header[12];
	
	
	// set MAC addresses?
	if (mp->use_ETHER)
	{
		for (i=0; i<6; i++)	
		{
			mp->frame[i] = mp->eth_dst[i];
			mp->frame[i+6] = mp->eth_src[i];
		}
		fp = 12; // next byte
	}
	
	
	
	// VLAN tags?
	if (mp->use_dot1Q)
	{
		t = mp->dot1Q_s;
		for (i=0; i<t; i++)	
		{
			mp->frame[fp++] = mp->dot1Q[i];
		}
	}
	
	
	
	// Standard Ethernet or SNAP? (SNAP includes 802.3, see comments in mops.h)
	if (mp->use_SNAP)  // note that if use_SNAP is set, then the 'else if' below is ignored!
	{
		// 802.3 length
		x = (char*) &mp->eth_len;
		mp->frame[fp++] = *(x+1);
		mp->frame[fp++] = *x;
		// SNAP
		t = mp->eth_snap_s;
		for (i=0; i<t; i++)	
		{
			mp->frame[fp++] = mp->eth_snap[i];
		}
	}
	else if (mp->use_ETHER) // add TYPE field (note the ELSE IF here!)
	{
		// EtherType 
		x = (char*) &mp->eth_type;
		mp->frame[fp++] = *(x+1);
		mp->frame[fp++] = *x;
	}
	// alternatively the user specified whole raw frame
   	// 
   	// 
   	// 
	// MPLS?
	if (mp->use_MPLS)
	{
		t = mp->mpls_s;
		for (i=0; i<t; i++)	
		{
			mp->frame[fp++] = mp->mpls[i];
		}
	}
	
	
	
	
	// IP?
	if (mp->use_IP)
	{
		mp->begin_IP = fp; // marks byte position of IP header within frame
		
		// ----- 1st row: -----
		// 
		mp->frame[fp] = (mp->ip_version << 4);          // version
		mp->frame[fp++] |= mp->ip_IHL;                  // IHL           (user value - corrected at end of function if required)
		mp->frame[fp++] = mp->ip_tos;                   // ToS           
		mops_hton2 ( &mp->ip_len, &mp->frame[fp] );     // Total Length  (user value - corrected at end of function if required)
		fp+=2;
		
		// ----- 2nd row: -----
		// 
		mops_hton2 ( &mp->ip_id, &mp->frame[fp] );    // Fragment Identification
		fp+=2;
		
		mops_hton2 ( &mp->ip_frag_offset, &mp->frame[fp] ); // Fragment Identification
		// set flags:
		if (mp->ip_flags_MF)  mp->frame[fp] |= 0x20; else  mp->frame[fp] &= 0xDF; // More Frag
		if (mp->ip_flags_DF)  mp->frame[fp] |= 0x40; else  mp->frame[fp] &= 0xBF; // Don't Frag
		if (mp->ip_flags_RS)  mp->frame[fp] |= 0x80; else  mp->frame[fp] &= 0x7F; // reserved
		fp+=2;
		
		// ----- 3rd row: -----

		mp->frame[fp++] = mp->ip_ttl;                  // TTL
		mp->frame[fp++] = mp->ip_proto;                // Protocol
		mops_hton2 ( &mp->ip_sum, &mp->frame[fp] );    // Checksum (user value - corrected at end of function if required)
		fp+=2;
		
		// ----- 4th and 5th row: -----
		// 
		mops_hton4 ( &mp->ip_src, &mp->frame[fp] );   // SA
		fp+=4;
		mops_hton4 ( &mp->ip_dst, &mp->frame[fp] );   // DA
		fp+=4;
		
		// ----- options -----
		// 
		if (mp->ip_option_used)
		{
			t = mp->ip_option_s;
			for (i=0; i<t; i++)
			{
				mp->frame[fp++] = mp->ip_option[i];
			}
		}
	}
	
	
	
	
	// UDP?
	if (mp->use_UDP)
	{
		mp->begin_UDP = fp; // marks byte position of UDP header within frame
		
		mops_hton2 ( &mp->sp, &mp->frame[fp] );    // Source Port
		fp+=2;
		mops_hton2 ( &mp->dp, &mp->frame[fp] );    // Destination Port
		fp+=2;
		mops_hton2 ( &mp->udp_len, &mp->frame[fp] );    // Length   (user value - corrected at end of function if required)
		fp+=2;
		mops_hton2 ( &mp->udp_sum, &mp->frame[fp] );    // CheckSum (user value - corrected at end of function if required)
		fp+=2;
	}
	
	
	
	// TCP?
	if (mp->use_TCP)
	{
		mp->begin_TCP = fp; // marks byte position of TCP header within frame
	
		// ----- 1st row: -----
		// 
		mops_hton2 ( &mp->sp, &mp->frame[fp] );    // Source Port
		fp+=2;
		mops_hton2 ( &mp->dp, &mp->frame[fp] );    // Destination Port
		fp+=2;
		
		// ----- 2nd and 3rd row: -----
		// 
		mops_hton4 ( &mp->tcp_seq, &mp->frame[fp] );   // SQNR
		fp+=4;
		mops_hton4 ( &mp->tcp_ack, &mp->frame[fp] );   // ACKNR
		fp+=4;
		
		// ----- 4th row: -----
		// 
//		t16 = (mp->tcp_offset<<12) + (mp->tcp_res<<8);  // Data Offset (HLEN) and 4 reserved bits
		t16 = mp->tcp_res<<8;  // Data Offset (HLEN) and 4 reserved bits
		// (user value - corrected at end of function if required)
		// 
		if (mp->tcp_ctrl_CWR) t16 |= 0x0080; else t16 &= 0xff7f; // URG Flag 
		if (mp->tcp_ctrl_ECE) t16 |= 0x0040; else t16 &= 0xffbf; // URG Flag 
		if (mp->tcp_ctrl_URG) t16 |= 0x0020; else t16 &= 0xffdf; // URG Flag 
		if (mp->tcp_ctrl_ACK) t16 |= 0x0010; else t16 &= 0xffef; // ACK Flag
		if (mp->tcp_ctrl_PSH) t16 |= 0x0008; else t16 &= 0xfff7; // PSH Flag
		if (mp->tcp_ctrl_RST) t16 |= 0x0004; else t16 &= 0xfffb; // RST Flag
		if (mp->tcp_ctrl_SYN) t16 |= 0x0002; else t16 &= 0xfffd; // SYN Flag
		if (mp->tcp_ctrl_FIN) t16 |= 0x0001; else t16 &= 0xfffe; // FIN Flag
		
		mops_hton2 ( &t16, &mp->frame[fp] );    // copy HLEN, reserved bits, and flags to frame
		fp+=2;
		
		
		mops_hton2 ( &mp->tcp_win, &mp->frame[fp] );    // Window
		fp+=2;
		
		// ----- 5th row: -----
	 	// 
		mops_hton2 ( &mp->tcp_sum, &mp->frame[fp] );    // Checksum
		fp+=2;
		
		mops_hton2 ( &mp->tcp_urg, &mp->frame[fp] );    // Urgent pointer
		fp+=2;
		
		
		// ----- options: -----
		// 
		if (mp->tcp_option_used) {
			t=mp->tcp_option_s;
			for (i=0; i<t; i++) {
				mp->frame[fp++] = mp->tcp_option[i];
			}
		}
	}

	// Eventually the payload:
	if ((t = mp->msg_s))
	{
		mp->begin_MSG = fp;
		for (i=0; i<t; i++) {
			mp->frame[fp++] = mp->msg[i];
		}
	}
	
	mp->frame_s = fp; // finally set the total frame length
	
	
	//////////////////////////////////////////////////////////////
	// Protect TX subsystem from too short or long packets      //
	// TODO: Consider to support mops-specific limits 
	//       (which are itself limited by these global limits)
	if (fp < min_frame_s) 
		mp->frame_s = min_frame_s;
	else
		if (fp > max_frame_s)
			mp->frame_s = max_frame_s;
	//                                                          //
	//////////////////////////////////////////////////////////////

	

   
	////////////////////////////////////////////////////////////////////////////////
	//
	//   Now update "derivable" fields if required:
	// 
	//      IP: ip_IHL, ip_len, ip_sum 
	//      UDP: udp_len, udp_sum
	//      TCP: tcp_offset, tcp_sum
   	// 
   	// 
	if (mp->use_IP) 
	{
		fp = mp->begin_IP; // marks byte position of IP header within frame
		
		/// HLEN
		if (!mp->ip_IHL_false) { // user has NOT set an own header length
			t8 = 5;
			if (mp->ip_option_used) { // add option length if option exists
				t8 += mp->ip_option_s/4;
			}
			t8 &= 0x0f; // set most significant 4 bits to zero because reserved for IP version
			mp->frame[fp] |= t8; 
		}
		
		/// LEN
		if (!mp->ip_len_false) { // user has NOT set an own total length
			t16 = mp->frame_s-fp;
			mops_hton2 ( &t16, &mp->frame[fp+2] );     // Calculated total Length
		}
		
		/// SUM
		if (!mp->ip_sum_false) { // user has NOT set an own header checksum
			mp->frame[fp+10]=0x00; 
			mp->frame[fp+11]=0x00;
			t16 = mops_sum16 (t8*4, &mp->frame[fp]);
			mops_hton2 ( &t16, &mp->frame[fp+10] );    // Checksum (user value - corrected at end of function if required)
		}
	}
	
	
	if (mp->use_UDP)
	{
		fp = mp->begin_UDP; // marks byte position of UDP header within frame
		
		/// LEN
		if (!mp->udp_len_false) { // user has NOT set an own total length
			t16 = mp->frame_s-fp;
			mops_hton2 ( &t16, &mp->frame[fp+4] );     // Calculated total Length
		}
		
		/// SUM
		//
		// The pseudo  header  conceptually prefixed to the UDP header contains the
		// source  address,  the destination  address,  the protocol,  and the  UDP
		// length. [RFC 768]
		// 
		//                   0      7 8     15 16    23 24    31 
		//                  +--------+--------+--------+--------+
		//                  |          source address           |
		//                  +--------+--------+--------+--------+
		//                  |        destination address        |
		//                  +--------+--------+--------+--------+
		//                  |  zero  |protocol|   UDP length    |
		//                  +--------+--------+--------+--------+
		//
		//
		if (!mp->udp_sum_false) // user has NOT set an own checksum
		{
			// Create IP pseudoheader
			memcpy(&ip_pseudo_header[0], &mp->frame[mp->begin_IP+12], 4); // copy SA to pseudoheader
			memcpy(&ip_pseudo_header[4], &mp->frame[mp->begin_IP+16], 4); // copy DA to pseudoheader
			ip_pseudo_header[8]=0x00;
			ip_pseudo_header[9]=mp->ip_proto;
			memcpy(&ip_pseudo_header[10], &mp->frame[fp+4], 2); // copy UDP length to pseudoheader
			
			mp->frame[fp+6]=0x00; // set checksum to 0x0000
			mp->frame[fp+7]=0x00; 	    
			
			t = 12+mp->frame_s-fp; // udp datagram length (including 12 byte pseudoheader)
			
			// Pad one extra byte if length is odd, and append the 
			// pseudoheader at the end of mp->frame (only for checksum computation)
			if (t%2) 
			{
				t++;
				mp->frame[mp->frame_s]=0x00;
				memcpy(&mp->frame[mp->frame_s+1], ip_pseudo_header, 12); 
			}
			else
				memcpy(&mp->frame[mp->frame_s], ip_pseudo_header, 12); 
			
			t16 = mops_sum16 (t, &mp->frame[fp]);
			mops_hton2 ( &t16, &mp->frame[fp+6] );    
		}
	}
	
	
	
	
	if (mp->use_TCP)
	{
		fp = mp->begin_TCP; // marks byte position of TCP header within frame
		
		/// OFFSET (=HLEN)
		if (!mp->tcp_offset_false) // user has NOT set an own header length
		{
			t8 = 5;
			if (mp->tcp_option_used) {// add option length if option exists
				t8 += mp->tcp_option_s/4;
			}
			t8 <<=4;
			mp->frame[fp+12] |= t8; 
		}
		
		// The TCP checksum is calculated similarily as the UDP checksum (see above).
		// (The TCP length is needed instead of the UDP length of course, although
		// the TCP length is not part of the header)
		// 
		if (!mp->tcp_sum_false)	{
			// Create IP pseudoheader
			memcpy(&ip_pseudo_header[0], &mp->frame[mp->begin_IP+12], 4); // copy SA to pseudoheader
			memcpy(&ip_pseudo_header[4], &mp->frame[mp->begin_IP+16], 4); // copy DA to pseudoheader
			ip_pseudo_header[8]=0x00;
			ip_pseudo_header[9]=mp->ip_proto;
			mp->tcp_len = mp->frame_s-fp; // TCP segment length
			t16 = htons (mp->tcp_len);
			memcpy(&ip_pseudo_header[10], &t16, 2); // copy TCP length to pseudoheader
			
			mp->frame[fp+16]=0x00; // set checksum to 0x0000
			mp->frame[fp+17]=0x00; 	    
			
			t = mp->tcp_len+12; // TCP segment length plus pseudoheader length
			
			// Pad one extra byte if length is odd, and append the 
			// pseudoheader at the end of mp->frame (only for checksum computation)
			if (t%2) {
				t++;
				mp->frame[mp->frame_s]=0x00;
				memcpy(&mp->frame[mp->frame_s+1], ip_pseudo_header, 12); 
			}
			else
				memcpy(&mp->frame[mp->frame_s], ip_pseudo_header, 12); 
			
			t16 = mops_sum16 (t, &mp->frame[fp]);
			mops_hton2 ( &t16, &mp->frame[fp+16] );
		}
	}
	
	
	return 0;
}



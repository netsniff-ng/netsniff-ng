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

// Calculates the number of TCP transmissions based on SQNR range
u_int32_t mops_tcp_complexity_sqnr (struct mops * mp)
{
	u_int32_t a,b,t,result;
   
	a = mp->tcp_seq_start;
	b = mp->tcp_seq_stop;
	t = mp->tcp_seq_delta;
   
	if (!t) return 1; // delta set to zero means no range
   
	if (a<b) // regular case
		result = ceill ((b-a)/t);
	else     // range wraps around
		result = ceill (((0xffffffff-a) + b)/t);
   
	return result;
}


// Calculates the number of TCP transmissions based on SQNR range
u_int32_t mops_tcp_complexity_acknr (struct mops * mp)
{
	u_int32_t a,b,t,result;
   
	a = mp->tcp_ack_start;
	b = mp->tcp_ack_stop;
	t = mp->tcp_ack_delta;
   
	if (!t) return 1; // delta set to zero means no range
   
	if (a<b) // regular case
		result = ceill ((b-a)/t);
	else     // range wraps around
		result = ceill (((0xffffffff-a) + b)/t);
   
	return result;
}




// *****TODO: TCP Options ******

// Remove all options
int mops_tcp_option_remove_all (struct mops* mp)
{
   
   return 0;
}


// Prints current flag settings in the provided string 'str'.
// NOTE that str must be at least 32 bytes! 
// *** BETTER USE 64 bytes (for future compatibility) ***
// 
int mops_tcp_flags2str (struct mops* mp, char *str)
{
	if (mp==NULL) {
		sprintf(str, "(no valid mops)\n");
		return 1;
	}
	
	sprintf(str, "%s-%s-%s-%s-%s-%s-%s-%s",
		(mp->tcp_ctrl_CWR) ? "CRW" : "---",
		(mp->tcp_ctrl_ECE) ? "ECE" : "---",
		(mp->tcp_ctrl_URG) ? "URG" : "---",
		(mp->tcp_ctrl_ACK) ? "ACK" : "---",
		(mp->tcp_ctrl_PSH) ? "PSH" : "---",
		(mp->tcp_ctrl_RST) ? "RST" : "---",
		(mp->tcp_ctrl_SYN) ? "SYN" : "---",
		(mp->tcp_ctrl_FIN) ? "FIN" : "---");
	
	return 0;
}

// Add TCP options
// 
// TODO: currently all params are ignored and a default option combination is added.
// 
int mops_tcp_add_option (struct mops* mp,
			 int mss, 
			 int sack,
			 int scale, 
			 u_int32_t tsval, 
			 u_int32_t tsecr)
{
			 
	u_int8_t tcp_default_options[] = {
	  0x02, 0x04, 0x05, 0xac,                                     // MSS
	  0x04, 0x02,                                                 // SACK permitted
	  0x08, 0x0a, 0x19, 0x35, 0x90, 0xc3, 0x00, 0x00, 0x00, 0x00, // Timestamps
	  0x01,                                                       // NOP
	  0x03, 0x03, 0x05                                            // Window Scale 5
	};

			 
       /*   Kind: 8
            Length: 10 bytes

	    +-------+-------+---------------------+---------------------+
            |Kind=8 |  10   |   TS Value (TSval)  |TS Echo Reply (TSecr)|
            +-------+-------+---------------------+---------------------+
               1       1              4                     4
	* 
	*  The Timestamps option carries two four-byte timestamp fields. The
	*  Timestamp Value field (TSval) contains the current value of the
	*  timestamp clock of the TCP sending the option.
	* 
	* The Timestamp Echo Reply field (TSecr) is only valid if the ACK bit
	* is set in the TCP header; if it is valid, it echos a times- tamp
	* value that was sent by the remote TCP in the TSval field of a
	* Timestamps option. When TSecr is not valid, its value must be zero.
	* The TSecr value will generally be from the most recent Timestamp
	* option that was received; however, there are exceptions that are
	* explained below.
	* 
	* A TCP may send the Timestamps option (TSopt) in an initial <SYN>
	* segment (i.e., segment containing a SYN bit and no ACK bit), and
	* may send a TSopt in other segments only if it re- ceived a TSopt in
	* the initial <SYN> segment for the connection.
	* 
	*/
	
	memcpy((void*) mp->tcp_option, (void*) tcp_default_options, 20);
	mp->tcp_option_s = 20;
	mp->tcp_option_used = 1;
	
	return 0;
}


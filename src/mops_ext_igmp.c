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



// Initialization function - specify defaults here!
// 
int mops_init_pdesc_igmp(struct mops *mp)
{
	struct mops_ext_igmp * pd;

	if (mp->p_desc == NULL) return 1;  // p_desc not properly assigned 
	pd = mp->p_desc;

	pd->version       = 2;
	pd->type          = IGMP_V2_REPORT;
	pd->max_resp_code = 0;
	pd->sum_false     = 0;
	pd->group_addr    = 0; // TODO: consider initialization with well-known mcast address?
	pd->sa_list       = NULL; 
	
	return 0;
}




//     IGMPv2 query and report (see RFC 2236)
//
//          0                   1                   2                   3
//          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	   |      Type     | Max Resp Time |           Checksum            |
//	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	   |                         Group Address                         |
//	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	
//	
//     IGMPv1 query and report (see RFC 1112)	
//
//          0                   1                   2                   3
//	    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	   |Version| Type  |    Unused     |           Checksum            |
//	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	   |                         Group Address                         |
//	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Therefore IGMPv1 only uses IGMP_GENERAL_QUERY or IGMP_V1_REPORT and mrt=0.
//
int mops_create_igmpv2 (struct mops *mp,
			int override,   // normally zero, but if '1' the user want to override defaults
			int igmp_type, // IGMP_GENERAL_QUERY, IGMP_GSPEC_QUERY, IGMP_V2_REPORT, IGMP_V1_REPORT, IGMP_LEAVE
			int  mrt, // max response time (unused == 0 for IGMPv1)
			int  sum, //-1 means auto-compute, other values means 'use this user-defined value'
			u_int32_t group_addr)
{
	struct mops_ext_igmp * pd;

	// --- sanity check params ---
	//   Do we have a valid pointer?
	if (mp->p_desc == NULL) return 1;  // p_desc not properly assigned 
	pd = mp->p_desc;
	if (mrt>255) return 1;
	if (sum>65535) return 1;
	// ---------------------------

	// +++ Set values in pdesc ++++++++++++++++++++++++
	pd->version = 2;
	
	switch (igmp_type) {
	 case IGMP_GENERAL_QUERY:
		pd->type = 0x11;
		pd->group_addr = 0;
		pd->max_resp_code = mrt;
		break;
	 case IGMP_GSPEC_QUERY:
		pd->type = 0x11;
		pd->group_addr = group_addr;
		pd->max_resp_code = mrt;
		break;
	 case IGMP_V2_REPORT:
		pd->type = 0x16;
		pd->group_addr = group_addr;
		if (override) pd->max_resp_code = mrt; else pd->max_resp_code = 0;
		break;
	 case IGMP_V1_REPORT:
		pd->type = 0x12;
		pd->group_addr = group_addr;
		if (override) pd->max_resp_code = mrt; else pd->max_resp_code = 0;
		break;
	 case IGMP_LEAVE:
		pd->type = 0x17;
		pd->group_addr = group_addr;
		if (override) pd->max_resp_code = mrt; else pd->max_resp_code = 0;
		break;
	 default:
		return 1; // unknown type
	}
	
	if (sum==-1) {
		pd->sum_false = 0;
	} else {
		pd->sum_false = 1;
		pd->sum = sum;      // mops_update_igmp() will process this!
	}
	
	// ++++++++++++++++++++++++++++++++++++++++++++++++
	
	return 0;
}









int mops_update_igmp (struct mops * mp)
{
	struct mops_ext_igmp * pd;
   
	pd = mp->p_desc; 
	if (pd==NULL) return 1;  // no valid pointer to a p_desc
	mp->msg_s = 0; // important! Otherwise the msg would get longer and longer after each call!
	u_int16_t sum;
	
	switch (pd->version) {
		
	 case 1:
		break;
		
	 case 2:
		//     IGMPv2 query and report (see RFC 2236)
		//
		//          0                   1                   2                   3
		//          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		//	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//	   |      Type     | Max Resp Time |           Checksum            |
		//	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//	   |                         Group Address                         |
		//	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		//	
		mops_msg_add_byte (mp, pd->type);
	      	mops_msg_add_byte (mp, pd->max_resp_code);
		if (pd->sum_false)
			mops_msg_add_2bytes (mp, pd->sum); // used defined (typically wrong) checksum
		else // must be set to zero before checksum computation
			mops_msg_add_2bytes (mp, 0x0000); 
		mops_msg_add_4bytes (mp, pd->group_addr);
		if (pd->sum_false==0) {
			sum = mops_sum16 (mp->msg_s, mp->msg);
			mops_hton2(&sum, &mp->msg[2]);
		}
		break;
		
	 case 3:
		break;
		
		
	 default:
		return 1;
	}
	
	

	return 0;
}








//         IGMP messages are encapsulated in IPv4 datagrams, with an IP protocol
//	   number of 2.  Every IGMP message described in this document is sent
//	   with an IP Time-to-Live of 1, IP Precedence of Internetwork Control
//	   (e.g., Type of Service 0xc0), and carries an IP Router Alert option
//	   [RFC-2113] in its IP header. 



// 
//
//     IGMPv3 report message (see RFC 3376)
//
//          0                   1                   2                   3
//          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//         |  Type = 0x22  |    Reserved   |           Checksum            |
//         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//         |           Reserved            |  Number of Group Records (M)  |
//         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//         |                                                               |
//         .                                                               .
//         .                        Group Record [1]                       .
//         .                                                               .
//         |                                                               |
//         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//         |                                                               |
//         .                                                               .
//         .                        Group Record [2]                       .
//         .                                                               .
//         |                                                               |
//         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//         |                               .                               |
//         .                               .                               .
//         |                               .                               |
//         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//         |                                                               |
//         .                                                               .
//         .                        Group Record [M]                       .
//         .                                                               .
//         |                                                               |
//         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      
//      
//
//
//     IGMPv3 query message (see RFC 3376)
//             
//          0                   1                   2                   3
// 	    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// 	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 	   |  Type = 0x11  | Max Resp Code |           Checksum            |
// 	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 	   |                         Group Address                         |
// 	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 	   | Resv  |S| QRV |     QQIC      |     Number of Sources (N)     |
// 	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 	   |                       Source Address [1]                      |
// 	   +-                                                             -+
// 	   |                       Source Address [2]                      |
// 	   +-                              .                              -+
// 	   .                               .                               .
// 	   .                               .                               .
// 	   +-                                                             -+
// 	   |                       Source Address [N]                      |
// 	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//	
//			

//
//
//	
//

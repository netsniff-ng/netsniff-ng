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


// Initialization function - specify defaults here!
// 
int mops_init_pdesc_bpdu(struct mops *mp)
{
	struct mops_ext_bpdu * pd;
	int i;
	
   
	if (mp->p_desc == NULL) return 1;  // p_desc not properly assigned 
	pd = mp->p_desc;

	// 1. - Initialize Ethernet header
	str2hex("01:80:C2:00:00:00",mp->eth_dst, 6);
   
	// 2. - Initialize BPDU fields
	pd->id = 0;
	pd->version = 0;           // 0=802.1D, 2=RSTP(802.1w)
	pd->bpdu_type = 0x80;      // 0=conf, 0x80=topology change, 2=RSTP/MSTP
	pd->flags = 0;             // X... .... = TCN ACK
                              // .X.. .... = Agreement
                              // ..X. .... = Forwarding
                              // ...X .... = Learning
			      // .... XX.. = Port Role (e. g. 11=Desgn)
			      // .... ..X. = Proposal
			      // .... ...X = TCN

	i = mops_get_device_index(tx.device);
	if (i!=-1) { // found
		memcpy((void*) &pd->root_id[2], (void*) device_list[i].mac_mops, 6);
		memcpy((void*) &pd->bridge_id[2], (void*) device_list[i].mac_mops, 6);
	} else { 
		str2hex("00:00:00:00:00:00", &pd->root_id[2], 6);
		str2hex("00:00:00:00:00:00", &pd->bridge_id[2], 6);
	}
   
	pd->root_id[0] = 0x00;
	pd->root_id[1] = 0x00;
	
	pd->bridge_id[0] = 0x00;
	pd->bridge_id[1] = 0x00;
	
	pd->root_pc = 0;       // Root Path Cost
	pd->port_id = 0;       // Port Identifier
	pd->message_age = 0;   // All timers are multiples of 1/256 sec. Thus times range from 0 to 256 seconds.
	pd->max_age = 5120;    // 20 seconds 
	pd->hello_time = 512;
	pd->f_delay = 3840;
	
	str2hex("00:00:00:00:00:00:00:00", pd->trailer, 8);
	// either all-zero or 00:00:00:00:02:VLAN(16bit) when PVST+
	pd->rstp = 0; // 1 = RSTP
	pd->pvst = 0; // 1=PVST+ , 0 = 802.1D
	pd->mstp = 0; // 1 = Multiple Instance STP
	
	return 0;
}


/////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// Update functions ////////////////////////////////
//
// **** Here is a summary of mops tool functions: ****
//
// Adds single byte to msg
// int mops_msg_add_byte (struct mops *mp, u_int8_t data);
// 
// Adds bit field in *previous* msg-byte using optional left-shift
// int mops_msg_add_field (struct mops *mp, u_int8_t data, int shift);
// 
// Adds two bytes in network byte order to msg
// int mops_msg_add_2bytes (struct mops *mp, u_int16_t data);
// 
// Adds four bytes in network byte order to msg
// int mops_msg_add_4bytes (struct mops *mp, u_int32_t data);
// 
// Adds string of bytes with lenght len 
// int mops_msg_add_string (struct mops *mp, u_int8_t *str, int len);

int mops_update_bpdu(struct mops * mp)
{
   
   struct mops_ext_bpdu * pd;
   
   pd = mp->p_desc; 
   if (pd==NULL) return 1;  // no valid pointer to a p_desc
   mp->msg_s = 0; // important! Otherwise the msg would get longer and longer after each call!

   
   // NOTE: the length field does not include the trailer!
   if (pd->pvst)
     {
	str2hex("01:00:0C:CC:CC:CD", mp->eth_dst, 6);
	mp->eth_len=50;
	str2hex("aa:aa:03:00:00:0c:01:0b",mp->eth_snap, 8);
	mp->eth_snap_s = 8;
     }
   else
     {
	str2hex("01:80:C2:00:00:00",mp->eth_dst, 6);
	mp->eth_len=38;
	str2hex("42:42:03",mp->eth_snap, 3);
	mp->eth_snap_s = 3;
     }
   
   mops_msg_add_2bytes (mp, pd->id);
   mops_msg_add_byte (mp, pd->version);
   mops_msg_add_byte (mp, pd->bpdu_type);
   
   if (pd->bpdu_type & 0x80) // if TCN then don't add more fields
     {
	   if (pd->pvst) mp->eth_len=12; else mp->eth_len=7;
     }
   else
     {
	mops_msg_add_byte (mp, pd->flags);
	mops_msg_add_string (mp, pd->root_id, 8);
	mops_msg_add_4bytes (mp, pd->root_pc);
	mops_msg_add_string (mp, pd->bridge_id, 8);
	mops_msg_add_2bytes (mp, pd->port_id);
	mops_msg_add_2bytes (mp, pd->message_age);
	mops_msg_add_2bytes (mp, pd->max_age);
	mops_msg_add_2bytes (mp, pd->hello_time);
	mops_msg_add_2bytes (mp, pd->f_delay);
     }
   
   // we always add the trailer
   mops_msg_add_string (mp, pd->trailer, 8);
   
   return 0;
}



// Create RID or BID based on priority, ext-sys-id, and MAC address.
// The last parameter selects BID (0) or RID (1)
// 
// pri .... 0-15
// esi .... 0-4095
// mac .... XX:XX:XX:XX:XX:XX or interface name 
// 
// NOTE: Invalid parameters will result in default values
//  
// RETURN VALUE: Only informational; identifies which parameter
// was errourness, using the following values:
// 
//   0 ... all parameters valid
//   1 ... priority exceeded range 
//   2 ... ext-sys-id exceeded range
//   3 ... invalid MAC address or invalid interface
//   4 ... other

int mops_create_bpdu_bid(struct mops * mp, int pri, int esi, char *mac, int bid_or_rid)
{
	int i;
	struct mops_ext_bpdu * pd = mp->p_desc;   
	u_int8_t rid[8];
	u_int16_t p16;
	
	if ((pri<0)||(pri>15)) return 1;
	if ((esi<0)||(esi>4095)) return 2;
	
	if (mac!=NULL) {
		// first check if an interface is specified:
		i = mops_get_device_index(mac);
		if (i!=-1) { // found
			memcpy((void*) &rid[2], (void*) device_list[i].mac_mops, 6);
		}
		else { // MAC address given?
			if (mops_pdesc_mac(&rid[2], mac)) {
				return 3;
			}
		}
	} else { // mac==NULL
		// use MAC of default interface!
		i = mops_get_device_index(tx.device);
		if (i!=-1) { // found
			memcpy((void*) &rid[2], (void*) device_list[i].mac_mops, 6);
		}
		else {
			str2hex("00:00:00:00:00:00", &rid[2], 6);
			return 4;
		}
	}
   
	// now prepend pri, esi

	p16 = pri;
	p16 <<= 12;
	p16 |= esi;
	
	mops_hton2 (&p16, &rid[0]);
	if (bid_or_rid)
		memcpy((void*) pd->root_id, (void*) rid, 8);
	else
		memcpy((void*) pd->bridge_id, (void*) rid, 8);
	return 0;
}


int mops_create_bpdu_trailer (struct mops * mp, u_int16_t vlan)
{
	struct mops_ext_bpdu * pd = mp->p_desc;
   
	// PVST+ requires a trailer with either all-zero 
	// or 00:00:00:00:02:VLAN(16bit) 

	// trailer already initialized with zeroes
	pd->trailer[0]=0x00;
	pd->trailer[1]=0x00;
	pd->trailer[2]=0x00;
	pd->trailer[3]=0x00;
	pd->trailer[4]=0x02;
	pd->trailer[5]=0x00;
	pd->trailer[6]=0x00;
	mops_hton2 (&vlan, &pd->trailer[5]);
   
   return 0;
}

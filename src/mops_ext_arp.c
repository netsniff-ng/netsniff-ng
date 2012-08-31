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
int mops_init_pdesc_arp(struct mops *mp)
{

   struct mops_ext_arp * pd;
   
   char tmac[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
   
   if (mp->p_desc == NULL) return 1;  // p_desc not properly assigned 

   pd = mp->p_desc;
     
   pd->hw_type   = 0x0001;
   pd->pr_type   = 0x800;
   pd->hw_size   = 6;
   pd->pr_size   = 4;
   pd->opcode    = 0x0001; // request
   memcpy ((void*) pd->sender_mac, (void*) tx.eth_src, 6);
   memcpy ((void*) pd->target_mac, (void*) tmac, 6);
   memcpy ((void*) pd->sender_ip,  (void*) &tx.ip_src, 4);
   memcpy ((void*) pd->target_ip,  (void*) &tx.ip_src, 4);

   pd->trailer = 18; // default is 18 byte trailer to get a 60 byte packet (instead of only 42)
   
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
// 
// Add counter to message
// int mops_msg_add_counter (struct mops *mp,
//			  int         random,  // 1=random, 0=use start/stop/step
// 			  u_int32_t   start,   // HOST BYTE ORDER
// 			  u_int32_t   stop,    // HOST BYTE ORDER
// 			  u_int32_t   step,    // HOST BYTE ORDER
// 			  int         bytes   // number of bytes used (1|2|4) - selects hton2 or hton4
// 			  );
// 
// 


int mops_update_arp(struct mops * mp)
{

   struct mops_ext_arp * pd;
   int i;
   
   pd = mp->p_desc; 
   if (pd==NULL) return 1;  // no valid pointer to a p_desc

   mp->msg_s = 0; // important! Otherwise the msg would get longer and longer after each call!
   
   mops_msg_add_2bytes (mp, pd->hw_type);
   mops_msg_add_2bytes (mp, pd->pr_type);
   mops_msg_add_byte (mp, pd->hw_size);
   mops_msg_add_byte (mp, pd->pr_size);
   mops_msg_add_2bytes (mp, pd->opcode);
   mops_msg_add_string (mp, pd->sender_mac, 6);
   mops_msg_add_string (mp, pd->sender_ip, 4);
   mops_msg_add_string (mp, pd->target_mac, 6);
   mops_msg_add_string (mp, pd->target_ip, 4);

   // Avoid buffer problems:
   if (pd->trailer>2000)
     {
	pd->trailer=2000;
     }
      
   for (i=0; i<pd->trailer; i++)
     {
	mops_msg_add_byte (mp, 0x00);
     }
   
   return 0;
}



// ARP Service: Resolves MAC address of given IP address and interface
// The result is stored in the last argument 'mac'.
// 
// EXAMPLE:
// 
//   u_int8_t mymac[6];
//   int ip[4]={192,186,0,1};
//   
//   service_arp("eth0", ip, mymac);
//   /* now mymac should contain the MAC address */
//   
// RETURN VALUE: 0 upon success
//               1 upon error
//  
int service_arp(char *dev, u_int8_t *ip, u_int8_t *mac)
{
	int i, devind=0, dev_found=0;
        struct mops * mp;
	struct mops_ext_arp * pd;	
	char tmac[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	struct arp_table_struct *cur;
	
	// MOPS framework already available?
	if (mp_head==NULL) return 1;
	
	// Get list index for that device:
	for (i=0; i<device_list_entries; i++) {
		if (strncmp(device_list[i].dev, dev, 16)==0) { 
			devind=i;
			dev_found=1;
			break;
		}
	}
	if (dev_found==0) {
		fprintf(stderr, " Warning: Unknown device (sysARP_service)\n");
		return 1; // ERROR: device name not found !!!!
	} else {
		if (verbose) {
			fprintf(stderr, " sysARP_service triggered through interface %s\n", dev);
		}
	}
	
	// Look up mops table if already a sysARP packet is available
	mp = mops_search_name (mp_head, "sysARP_service");
	if (mp!=NULL) { // entry exists...stop if active!
		if (mops_state(mp)==MOPS_STATE_ACTIVE) {
			if (verbose==2) fprintf(stderr, " Warning: Stop active MOPS (sysARP_service)\n");
			mops_destroy_thread(mp);
		}
	} else {
		// Allocate a new packet
		if ((mp = mops_alloc_packet(mp_head)) == NULL) {
			fprintf(stderr, " sysARP_service: ERROR -- cannot allocate MOPS\n");
			return 1; // Problem, memory full?
		} else {
			strncpy (mp->packet_name, "sysARP_service", 15);
			mp->mz_system=1; // indicates MZ private packet
			if (mops_ext_add_pdesc (mp, MOPS_ARP)) {
				return 1; // error
			} 
		}
	}
	
	// Configure ARP request:
	mops_clear_layers(mp, MOPS_ALL);
	mops_init_pdesc_arp(mp);
	
	mp->verbose = 0; 
	mp->use_ETHER = 1;
	mp->count = 1;
	mp->eth_type = 0x806;
	mz_strncpy(mp->device, dev, 16);

	pd = mp->p_desc;
	memcpy ((void*) pd->sender_mac, (void*) device_list[devind].mac_mops, 6);
	memcpy ((void*) pd->target_mac, (void*) tmac, 6);
	memcpy ((void*) pd->sender_ip,  (void*) device_list[devind].ip_mops, 4);
	pd->target_ip[0]=ip[0];
	pd->target_ip[1]=ip[1];
	pd->target_ip[2]=ip[2];
	pd->target_ip[3]=ip[3];
	
	mops_update_arp(mp);
	mops_set_conf(mp);

	// Send ARP request
	
	if (mops_tx_simple (mp)) {
		fprintf(stderr, " Warning: sysARP_service failed!\n");
		return 1;
	}
	
	usleep(100000); // wait 100 ms
	// Now hopefully we got an ARP response; 
	// look up in ARP cache

	cur=device_list[devind].arp_table;
	while(cur!=NULL) {
		if ((cur->sip[0]==ip[0]) &&
		    (cur->sip[1]==ip[1]) &&
		    (cur->sip[2]==ip[2]) &&
		    (cur->sip[3]==ip[3])) { // entry found!
			for (i=0; i<6; i++) {
				mac[i] = cur->smac[i];
			}
		}
		cur=cur->next;
	}
	
	return 0;
}

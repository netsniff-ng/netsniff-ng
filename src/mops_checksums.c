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




// -- TOC: --
//
// u_int16_t      mops_sum16                  (u_int16_t len, u_int8_t buff[])
// int            mops_get_transport_sum      (struct mops *mp)


//////////////////////////////////////////////////////////////////////////////////
//
//  See also:
//  
//  RFC1071 - Computing the Internet checksum
//  
//////////////////////////////////////////////////////////////////////////////////



// Generic 16-bit checksum code as required for IP and other headers.
// The checksum is calculated over buff[] which is of length len. 
//
// RETURN VALUE: The checksum! (Validated - correct!!!)
// 
// Example:  t16 = mops_sum16 (20, &mp->frame[fp]);
// 
u_int16_t mops_sum16 (u_int16_t len, u_int8_t buff[])
{
   
   u_int16_t word16;
   u_int32_t sum=0;
   u_int16_t i;
       
   // make 16 bit words out of every two adjacent 8 bit words in the packet and add them up
   for (i=0; i<len; i=i+2)
     {
	word16 =((buff[i]<<8)&0xFF00)+buff[i+1];
	sum = sum + (u_int32_t) word16;
     }
   
   // take only 16 bits out of the 32 bit sum and add up the carries
   while (sum>>16)
     sum = (sum & 0xFFFF)+(sum >> 16);
   
   // one's complement the result
   sum = ~sum;
   
   return ((u_int16_t) sum);
}





// sets UDP or TCP checksum within mp[]->frame
//   TODO: copying the whole segment is ugly and slow;
//         make it more efficient and realize it in-place.
//         
int mops_get_transport_sum(struct mops *mp)
{
   u_int8_t buf[MAX_PAYLOAD_SIZE];
   u_int16_t len;
   int udp_used;
   
   u_int16_t sum;
   
   udp_used = mp->use_UDP; // 0 or 1, 0 means TCP
   
   // IP Pseudoheader (12 Bytes)
   mops_hton4(&mp->ip_src, &buf[0]);
   mops_hton4(&mp->ip_dst, &buf[4]);
   buf[9]=0x00;

   
   // Copy segment
   if (udp_used) 
     {
	buf[10]=0x11; // proto UDP (17 dec)
	len = mp->udp_len;
	mops_hton2(&len, &buf[11]);
	memcpy(&buf[13], &mp->frame[mp->begin_UDP], len);
	// reset checksum to zero
	buf[19] = 0x00;
	buf[20] = 0x00;
	sum = mops_sum16(len+12, buf); 
	// insert checksum in UDP header (in frame)
	mops_hton2 (&sum, &mp->frame[(mp->begin_UDP)+7]);

     }
   else
     {
	buf[10]=0x06; // proto TCP
	len = mp->ip_len - mp->ip_IHL;
	mops_hton2((u_int16_t*)&len, &buf[11]);
	memcpy(&buf[13], &mp->frame[mp->begin_TCP], len);
	// reset checksum to zero
	buf[29] = 0x00;
	buf[30] = 0x00;
	sum = mops_sum16(len+12, buf);
	// insert checksum in TCP header (in frame)
	mops_hton2 (&sum, &mp->frame[(mp->begin_TCP)+17]);
     }
   
   
   return 0;
}


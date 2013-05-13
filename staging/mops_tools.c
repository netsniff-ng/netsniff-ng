/*
 * Mausezahn - A fast versatile traffic generator
 * Copyright (C) 2008,2009 Herbert Haas
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

// Inserts value in 'flag' (up to 7 bits are useful) into the target
// with an optional left-shift. For example if flag contains a 4-bit value
// and should be placed within the target in bit positions 3-6 like:
// 
//   7  6  5  4  3  2  1  0   
// +--+--+--+--+--+--+--+--+
// |  |  FLAGS    |  |  |  |
// +--+--+--+--+--+--+--+--+
// 
// then simply call: 
// 
//    (void)  mops_flags ( &target, &flag, 3 );
// 
// Note that shift=0 means no shift. 
inline void mops_flags (u_int8_t *target, u_int8_t *flag, int shift)
{
   *target |= (*flag << shift);
}



inline void mops_hton2 (u_int16_t *host16, u_int8_t *net16)
{
   char *x;
   
   x = (char*) host16;
   
   *(net16++) = *(x+1);
   *net16 = *x;
}


inline void mops_hton4 (u_int32_t *host32, u_int8_t *net32)
{
   char *x;
   
   x = (char*) host32;
   
   *(net32++) = *(x+3);
   *(net32++) = *(x+2);
   *(net32++) = *(x+1);
   *(net32) = *x;
}




// returns new counter index for given packet
// or -1 if all counters used already
int mops_get_counter (struct mops *mp)
{
   int i=0;
   
   while (mp->counter[i].offset)
     {
	i++;
	if (i==MAX_MOPS_COUNTERS_PER_PACKET) // exceeded range
	  return -1;
     }
   return i;
}


// Adds single byte to msg
int mops_msg_add_byte (struct mops *mp, u_int8_t data)
{
   mp->msg[mp->msg_s++] = data;
   return 0;
}


// Adds bit field in *previous* msg-byte using optional left-shift
int mops_msg_add_field (struct mops *mp, u_int8_t data, int shift)
{
   mp->msg[mp->msg_s -1]  |= (data << shift);   
   return 0;
}


// Adds two bytes in network byte order to msg
int mops_msg_add_2bytes (struct mops *mp, u_int16_t data)
{
   char *x;
   x = (char*) &data;
   mp->msg[mp->msg_s++] = *(x+1);
   mp->msg[mp->msg_s++] = *(x);
   return 0;
}


// Adds four bytes in network byte order to msg
int mops_msg_add_4bytes (struct mops *mp, u_int32_t data)
{
   char *x;
   x = (char*) &data;
   mp->msg[mp->msg_s++] = *(x+3);
   mp->msg[mp->msg_s++] = *(x+2);
   mp->msg[mp->msg_s++] = *(x+1);
   mp->msg[mp->msg_s++] = *(x);
   return 0;
}

// Adds string of bytes with lenght len 
int mops_msg_add_string (struct mops *mp, u_int8_t *str, int len)
{
   memcpy((void *) &mp->msg[mp->msg_s], (void *) str, len);
   mp->msg_s += len;
   
   return 0;
}



// Add counter to message
int mops_msg_add_counter (struct mops *mp,
			  int         random,  // 1=random, 0=use start/stop/step
			  u_int32_t   start,   // HOST BYTE ORDER
			  u_int32_t   stop,    // HOST BYTE ORDER
			  u_int32_t   step,    // HOST BYTE ORDER
			  int         bytes   // number of bytes used (1|2|4) - selects hton2 or hton4
			  )
{
   
   int i;
   
   // check if unsupported byte count
   if ( (bytes!=1) &&
	(bytes!=2) &&
	(bytes!=4) ) 
     return 1;
   
   // get new counter 
   i = mops_get_counter(mp);
   if (i==-1) return 1;
   
   // configure counter values
   mp->counter[i].offset = mp->msg_s;
   mp->counter[i].random = random;
   mp->counter[i].start  = start;
   mp->counter[i].stop   = stop;
   mp->counter[i].step   = step;
   mp->counter[i].bytes  = bytes;
   mp->counter[i].cur    = start;
   mp->counter[i].use    = 1;
   
   
   // configure first pointer value
   switch (bytes)
     {
      case 1:
	mops_msg_add_byte(mp, (u_int8_t) start);
	break;
      case 2:
	mops_msg_add_2bytes(mp, (u_int16_t) start);
	break;
      case 4:
	mops_msg_add_4bytes(mp, start);
	break;
      default: // never be reached
	return 1;
     }
   
   return 0;
}



// Compares two IP addresses byte by byte
// returns 0 if identical, 1 if different
// 
// Note that this works independent of endianess
// as long as both addresses have same endianess.
// 
int compare_ip (u_int8_t *ip1, u_int8_t *ip2)
{
   if (*ip1 != *ip2) return 1; 
   if (*(ip1+1) != *(ip2+1)) return 1; 
   if (*(ip1+2) != *(ip2+2)) return 1; 
   if (*(ip1+3) != *(ip2+3)) return 1; 
   
   return 0;
}


// Compares two MAC addresses byte by byte
// returns 0 if identical, 1 if different
int compare_mac (u_int8_t *mac1, u_int8_t *mac2)
{
   if (*mac1 != *mac2) return 1; 
   if (*(mac1+1) != *(mac2+1)) return 1; 
   if (*(mac1+2) != *(mac2+2)) return 1; 
   if (*(mac1+3) != *(mac2+3)) return 1; 
   if (*(mac1+4) != *(mac2+4)) return 1; 
   if (*(mac1+5) != *(mac2+5)) return 1; 

   return 0;
}


// Converts a 'struct timespec' value into a human readable string
// This stringt is written into 'str' which must be at least a 32 byte
// array.
int timespec2str(struct timespec *t, char *str)
{
	unsigned int d=0, h, m, s;
	
	// zero delay
	if ((t->tv_sec==0) && (t->tv_nsec==0)) {
		sprintf(str, "(none)");
		return 0;
	}

	h = t->tv_sec/3600;
	m = (t->tv_sec - h*3600)/60;
	s = t->tv_sec - h*3600 - m*60;
	
	if (h>24) {
		d = h/24;
		h = h - d*24;
		sprintf(str, "%u days %02u:%02u:%02u", d, h, m, s);
		return 0;
	}
	
	if (h|m) 
		sprintf(str, "%02u:%02u:%02u", h, m, s); // ignore nanoseconds if delay is in order of hours
	else if (s)
		sprintf(str, "%u%s sec", s, (t->tv_nsec>1000000) ? "+" : "");
	else if (t->tv_nsec>1000000) 
		sprintf(str, "%u msec", (unsigned int) t->tv_nsec/1000000);
	else if (t->tv_nsec>1000)
		sprintf(str, "%u usec", (unsigned int) t->tv_nsec/1000);
	else
	       	sprintf(str, "%lu nsec", t->tv_nsec);

	return 0;
}


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


// Remove 802.1Q tags from packet mp
//  
// k indicates which tag to be removed (1..n)
// k=0 means: remove all tags!
// 
// RETURN VALUE: 1 upon failure, 0 upon success
int mops_dot1Q_remove (struct mops *mp, int k)
{
	int a,b,n;
     
	if (k==0) {
		mp->dot1Q_s=0;
		mp->use_dot1Q=0;
		return 0;
	}
   
	n = mp->dot1Q_s/4; // n = total number of tags
	if (k>n) return 1;
	
	if (k==1) { // only delete the single tag
		mp->dot1Q_s=0;
		mp->use_dot1Q=0;
		return 0;
	}
   
	// we have more than one tag:
	// 
	if (k==n) { // remove last tag (of several)
		mp->dot1Q_s -=4;
		return 0;
	}
	
	// remove some non-ending tag: 0, 1, 2, 3
	a = (k-1)*4; // target 
	b = k*4;     // source (what should be copied)
	memcpy(&mp->dot1Q[a], &mp->dot1Q[b], (n-k)*4);
	mp->dot1Q_s -=4;
	
	return 0;
}


// Unset CFI in tag k where k=1..n
int mops_dot1Q_nocfi (struct mops *mp, int k)
{
	int n;
	
	n = mp->dot1Q_s/4; // n = total number of tags
	if (k>n) return 1;
	
	mp->dot1Q[((k-1)*4)+2] &=0xef; // unset CFI (0xef = 1110 1111)
	return 0;
}


// Set CFI in tag k where k=1..n
int mops_dot1Q_cfi (struct mops *mp, int k)
{
	int n;
	
	n = mp->dot1Q_s/4; // n = total number of tags
	if (k>n) return 1;
	
	mp->dot1Q[((k-1)*4)+2] |=0x10; // set CFI (0x10 = 0001 0000)
	return 0;
}


// Assign 802.1Q tag with 
//   v ... VLAN  
//   c ... CoS 
//   i ... tag position (starting from zero!)
//   
//   m ... modification: 1 = dot1Q_s is not changed
//   
// NOTE:
//   When called from for-loop to add all tags the total size dot1Q_s
//   is updated continuously, therefore use m=1.
//   
//   But when changing a particular tag within an existing 802.1Q stack
//   the total number of tags does not change, therefore use m=0.
//   
// RETURN VALUE: 0 upon success, 1 upon failure
//  
int mops_dot1Q (struct mops *mp, int i, int m, u_int16_t v, u_int16_t c)
{
	u_int8_t *ptr, c8;
   
	if (i>=MAX_MOPS_DOT1Q_TAGS) return 1;  // max number of tags, see definitions in mops.h
	if ((v>4095)||(c>7)) return 1;         // greater values do not make sense
	
	// Format: 0x8100 CoS-CFI-VLAN
	// where c=CoS, v=VLAN
	c8 = (u_int8_t) c;
	mp->dot1Q[4*i+0]= 0x81;
	mp->dot1Q[4*i+1]= 0x00;
	ptr = (u_int8_t*) &v;
	mp->dot1Q[4*i+3]=*ptr;
	mp->dot1Q[4*i+2]=*(ptr+1);
	mp->dot1Q[4*i+2]^= (c8 << 5);
	
	if (m) {
		mp->dot1Q_s=4*(1+i);  // NOTE: dot1Q_s = current tag position + 1
		if (mp->dot1Q_s) mp->use_dot1Q = 1;
	}
	
	return 0;
}


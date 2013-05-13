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

// Assigns MPLS tag at position i (starting at zero!) with values:
// 
//  m        ... total number of tags (important to set BoS in last tag)
//  Label    ... label value 
//  Exp      ... EXP field (typically CoS)
//  TTL      ... Time To Live
// 
// NOTE: Two usage possibilities!
// 
//   1.) When called from for-loop to add all tags the total size mpls_s
//       is updated continuously and the BoS is set in the last tag. 
//       Therefore set m = total number of tags!
//       
//   2.) But when changing a particular tag within an existing MPLS stack
//       the total number of tags does not change, therefore use m=0.
// 
// RETURN VALUE: 0 upon success, 1 upon failure
// 
int mops_mpls(struct mops *mp, int i, int m, u_int32_t Label, u_int8_t Exp, u_int8_t TTL)
{
   u_int8_t *ptr;

   if ((m) && (i>=m)) return 1; // label index greater than number of labels!
   if (Label > 1048575) return 1;
   if (Exp > 7) return 1;

   // Create binary tag: Label(20) EXP(3) BoS(1) TTL(8)
   Label <<= 4;
   ptr = (u_int8_t *) &Label;
   mp->mpls[4*i+0] = *(ptr+2);
   mp->mpls[4*i+1] = *(ptr+1);
   mp->mpls[4*i+2] = *(ptr+0);
   Exp <<= 1;
   mp->mpls[4*i+2] |= Exp;
   mp->mpls[4*i+3] = TTL;
   
   if ((m) && (i==(m-1)))  // reached last tag!
       {
	  mp->mpls[4*i+2] |= 0x01; // set BoS in last tag
	  mp->mpls_s =4*m;
	  mp->use_MPLS = 1;
	  if ( (mp->eth_type != 0x8847) && (mp->eth_type != 0x8848) )
	    {
	       mp->eth_type_backup = mp->eth_type;
	    }
	  mp->eth_type = 0x8847;
       }
   return 0;
}


// Remove MPLS tags from packet mp
//  
// j indicates which tag to be removed (1..n)
// j=0 means: remove all tags!
// 
// RETURN VALUE: 1 upon failure, 0 upon success
int mops_mpls_remove (struct mops *mp, int j)
{
   int a, b, k;
   

   if (j==0)  // remove all tags
     {
	if (mp->use_MPLS)
	  {
	     mp->mpls_s=0;
	     mp->use_MPLS=0;
	     mp->eth_type = mp->eth_type_backup; // restore original ethertype
	     return 0;
	  }
	else
	  return 1;
     }

   k = mp->mpls_s/4;
   if (j>k) return 1;  	// The packet only consists of k tag(s)
   
   if (k==1) // only delete the single tag
     {	     
	mp->mpls_s=0;
	mp->use_MPLS=0;
	mp->eth_type = mp->eth_type_backup; // restore original ethertype
	return 0;
     }
   
   // if we got here we have more than one tag:

   if (j==k) // remove last tag (of several)
     {
	mp->mpls_s -=4;
	return 0;
     }
   
   // remove some non-ending tag: 0, 1, 2, 3
   a = (j-1)*4; // target 
   b = j*4;     // source (what should be copied)
   memcpy(&mp->mpls[a], &mp->mpls[b], (k-j)*4);
   mp->mpls_s -=4;
   return 0;
}


// Set BOS in tag k where k=1..n
int mops_mpls_bos (struct mops *mp, int k)
{
   int n;
   
   n = mp->mpls_s/4; // n = total number of tags
   if (k>n) return 1;

   mp->mpls[(k-1)*4+2] |= 0x01;
   return 0;
}


// Unset BOS in tag k where k=1..n
int mops_mpls_nobos (struct mops *mp, int k)
{
   int n;
   
   n = mp->mpls_s/4; // n = total number of tags
   if (k>n) return 1;
   
   mp->mpls[(k-1)*4+2] &= 0xfe;
   return 0;
}

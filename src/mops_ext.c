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



// Add protocol descriptor of type ptype
// 
// Smart behaviour: 
// 
//    - If the desired p_desc has been assigned already, we leave everything
//      as it is and return to the calling function (return 0).
//      
//    - If a p_desc of another type has been already assigned, this function 
//      clears and frees everything before assigning another p_desc structure.
// 
int mops_ext_add_pdesc (struct mops *mp, int ptype)
{
   
	// 1. check if desired p_desc is already assigned
	if ( (mp->p_desc != NULL) && (mp->p_desc_type == ptype) ) {
		return 0;  
	}

	// 2. remove older p_desc
	if (mp->p_desc_type != MOPS_NO_PDESC) {
		if (mops_ext_del_pdesc (mp)) return 1;
	}

	// 3. allocate and assign a p_desp
	switch (ptype) {
	 case MOPS_ARP:
		mp->p_desc = ( MOPS_EXT_ARP ) malloc ( sizeof (struct mops_ext_arp ) );
		mp->p_desc_type = MOPS_ARP;
		mops_init_pdesc_arp(mp);
		break;
	 case MOPS_BPDU:
		mp->p_desc = ( MOPS_EXT_BPDU ) malloc ( sizeof (struct mops_ext_bpdu ) );
		mp->p_desc_type = MOPS_BPDU;
		mops_init_pdesc_bpdu(mp);
		break;
	 case MOPS_CDP:
		mp->p_desc = ( MOPS_EXT_CDP ) malloc ( sizeof (struct mops_ext_cdp ) );
		mp->p_desc_type = MOPS_CDP;
		mops_init_pdesc_cdp(mp);
		break;
	 case MOPS_DNS:
		mp->p_desc = ( MOPS_EXT_DNS ) malloc ( sizeof (struct mops_ext_dns ) );
		mp->p_desc_type = MOPS_DNS;
		mops_init_pdesc_dns(mp);
		break;
	 case MOPS_ICMP:
		mp->p_desc = ( MOPS_EXT_ICMP ) malloc ( sizeof (struct mops_ext_icmp ) );
		mp->p_desc_type = MOPS_ICMP;
		mops_init_pdesc_icmp(mp);
		break;
	 case MOPS_IGMP:
		mp->p_desc = ( MOPS_EXT_IGMP ) malloc ( sizeof (struct mops_ext_igmp ) );
		mp->p_desc_type = MOPS_IGMP;
		mops_init_pdesc_igmp(mp);
		break;
	 case MOPS_RTP:
		mp->p_desc = ( MOPS_EXT_RTP ) malloc ( sizeof (struct mops_ext_rtp ) );
		mp->p_desc_type = MOPS_RTP;
		mops_init_pdesc_rtp(mp);
		break;
	 case MOPS_LLDP:
		mp->p_desc = ( MOPS_EXT_LLDP ) malloc ( sizeof (struct mops_ext_lldp ) );
		((struct mops_ext_lldp *)mp->p_desc)->chassis_id = NULL;
		((struct mops_ext_lldp *)mp->p_desc)->port_id = NULL;
		((struct mops_ext_lldp *)mp->p_desc)->optional_tlvs = NULL;
		mp->p_desc_type = MOPS_LLDP;
		mops_init_pdesc_lldp(mp);
		break;
	 case MOPS_SYSLOG:
		mp->p_desc = ( MOPS_EXT_SYSLOG ) malloc ( sizeof (struct mops_ext_syslog ) );
		mp->p_desc_type = MOPS_SYSLOG;
		mops_init_pdesc_syslog(mp);
		break;
	 default:
		return 1; // unknown protocol
	}
   
	if (mp->p_desc == NULL) {
		fprintf (stderr, "mz/mops: could not allocate memory for mops element!\n");
		mp->p_desc_type = MOPS_NO_PDESC;
		return 1;
	}

   return 0;
}


// Delete any protocol descriptor
// 1) Free memory
// 2) Reset p_desc and p_desc_type
// 
int mops_ext_del_pdesc (struct mops *mp)
{

	mp->p_desc_type = MOPS_NO_PDESC;
	if (mp->p_desc==NULL) return 1; // already NULL pointer, nothing to free()
	
	switch (mp->p_desc_type) {
	 case MOPS_ARP:
		free ( (MOPS_EXT_ARP) mp->p_desc );
		break;
	 case MOPS_BPDU:
		free ( (MOPS_EXT_BPDU) mp->p_desc );
		break;
	 case MOPS_CDP:
		free ( (MOPS_EXT_CDP) mp->p_desc );
		break;
	 case MOPS_DNS:
		free ( (MOPS_EXT_DNS) mp->p_desc );
		break;
	 case MOPS_ICMP:
		free ( (MOPS_EXT_ICMP) mp->p_desc );
		break;
	 case MOPS_IGMP:
		free ( (MOPS_EXT_IGMP) mp->p_desc );
		break;
	 case MOPS_RTP:
		free ( (MOPS_EXT_RTP) mp->p_desc );
		break;
	 case MOPS_LLDP:
		if ( ((struct mops_ext_lldp *) mp->p_desc)->chassis_id != NULL)    
			free ( ((struct mops_ext_lldp *) mp->p_desc)->chassis_id);
		if ( ((struct mops_ext_lldp *) mp->p_desc)->port_id != NULL)
			free ( ((struct mops_ext_lldp *) mp->p_desc)->port_id);
		if ( ((struct mops_ext_lldp *) mp->p_desc)->optional_tlvs != NULL)  
			free ( ((struct mops_ext_lldp *) mp->p_desc)->optional_tlvs);
		free ( (MOPS_EXT_LLDP) mp->p_desc );
		break;
	 case MOPS_SYSLOG:
		free ( (MOPS_EXT_SYSLOG) mp->p_desc );
		break;
	 case MOPS_NO_PDESC: // already cleared?
		break;
		
		/* nothing */
	}

	mp->p_desc = NULL;
	return 0;
}


// Create msg based on p_desc data.
// After that call mops_update and the frame is complete.
int mops_ext_update (struct mops *mp)
{

	switch (mp->p_desc_type) {
	 case MOPS_ARP:
		mops_update_arp(mp);
		break;
	 case MOPS_BPDU:
		mops_update_bpdu(mp);
		break;
	 case MOPS_CDP:
		break;
	 case MOPS_DNS:
		break;
	 case MOPS_ICMP:
		break;
	 case MOPS_IGMP:
		mops_update_igmp(mp);
		break;
	 case MOPS_RTP:
		mops_update_rtp(mp);
		break;
	 case MOPS_LLDP:
		mops_update_lldp(mp);
		break;
	 case MOPS_SYSLOG:
		break;
	 case MOPS_NO_PDESC:
		return 0;  // OK!
		break;
	 default:
		return 1;  // Unknown value!?
	}
	
	return 0;
}


//////// General parameter update functions - modify a single parameter of p_desc structure
//
// 'Standardized' return values:
//
//   MOPS_PDESC_LOW          Value smaller than lower bound - but will set
//   MOPS_PDESC_HIGH         Value larger than upper bound  - but will set
//
//   MOPS_PDESC_OVERFLOW     Value exceeded possible range
//  
//   MOPS_PDESC_NO_MAC       Invalid MAC address
//   MOPS_PDESC_NO_IP        Invalid IP address
//
//   MOPS_PDESC_FAILURE      Unspecified problem
//   MOPS_PDESC_SUCCESS = 0  Value assigned properly
//
// 'Standardized' format:
// 
//  mops_pdesc_function ( *PDESC_VAR , USER_STRING , LIMITS )


   

// Assign one or more strings to a single string
// Practical example: Concatenate multiple tokens from the CLI
// Will never copy more than 'max' bytes to 'dst'
// 
// EXAMPLE:
// 
// mops_pdesc_mstrings (clipkt->description, argv, argc, 20);
// 
int mops_pdesc_mstrings (char *dst, char* argv[], int argc, int max)
{
   int i;
   char tmp[10000]; // should be sufficient for all purposes here
   
   dst[0]=0x00;
   tmp[0]=0x00;
   
   for (i=0; i<argc; i++)
     {  // check if next word would exceed tmp:
	if ((1+strlen(argv[i]))>(10000-strlen(tmp)))  // The '1+' counts for the additional space
	  return MOPS_PDESC_OVERFLOW;
	else
	  {
	     strncat(tmp, argv[i], 80); // Enforcing a maximum word length
	     strcat(tmp, " "); // We get only the tokens, not the spaces inbetween
	  }
     }
   
   strncpy(dst, tmp, max);
   if (strlen(tmp)>max) return MOPS_PDESC_OVERFLOW;
   
   return MOPS_PDESC_SUCCESS;
}
   




// Assign decimal or hexadecimal u_int8_t value, depending on spec
// spec can be 0=dec or 1=hex
int mops_pdesc_1byte (u_int8_t *dst, char* usr, int spec, int min, int max)
{
   u_int32_t i;
   int retval = MOPS_PDESC_SUCCESS;
   
   if ((max>255)||(min>255)) return MOPS_PDESC_FAILURE;
   
   if (spec==0)
     {
	i = (u_int32_t) str2int (usr);
     }
   else
     {
	i = (u_int32_t) xstr2int (usr);
     }
   
   if (i>255) return MOPS_PDESC_OVERFLOW;
   if (i<min) 
     retval = MOPS_PDESC_LOW;
   else if (i>max)
     retval = MOPS_PDESC_HIGH;

   *dst = (u_int8_t) i;
   
   return retval; 
}



// Assign decimal or hexadecimal u_int16_t value, depending on spec
// spec can be 0=dec or 1=hex
int mops_pdesc_2byte (u_int16_t *dst, char* usr, int spec, int min, int max)
{
   u_int32_t i;
   int retval = MOPS_PDESC_SUCCESS;
   
   if ((max>0xffff)||(min>0xffff)) return MOPS_PDESC_FAILURE;

   if (spec==0)
     {
	i = (u_int32_t) str2int (usr);
     }
   else
     {
	i = (u_int32_t) xstr2int (usr);
     }
   
   if (i>0xffff) return MOPS_PDESC_OVERFLOW;
   if (i<min) 
     retval = MOPS_PDESC_LOW;
   else if (i>max)
     retval = MOPS_PDESC_HIGH;

   *dst = (u_int16_t) i;
   
   return retval; 
}


// Assign decimal or hexadecimal u_int32_t value, depending on spec
// spec can be 0=dec or 1=hex
int mops_pdesc_4byte (u_int32_t *dst, char* usr, int spec, unsigned long int min, unsigned long int max)
{
   unsigned long int i;
   int retval = MOPS_PDESC_SUCCESS;
   
   if ((max>0xffffffff)||(min>0xffffffff)) return MOPS_PDESC_FAILURE;
   
   if (spec==0)
     {
	i = str2int (usr);
     }
   else
     {
	i = xstr2int (usr);
     }
   
   if (i>0xffffffff) return MOPS_PDESC_OVERFLOW;
   if (i<min) 
     retval = MOPS_PDESC_LOW;
   else if (i>max)
     retval = MOPS_PDESC_HIGH;

   *dst = (u_int32_t) i;
   
   return retval; 
}



// Maps MAC address given in 'usr' (e. g. 00:11:22:aa:bb:cc) into 'dst'
// which is an u_int8_t array.
// 
// Returns MOPS_PDESC_FAILURE (=1) upon invalid MAC address
// 
int mops_pdesc_mac (u_int8_t *dst, char* usr)
{
   u_int8_t tmp[6];
   
   // temporarily backup current value
   memcpy ((void*) tmp, (void*) dst, 6);
   
   if (str2hex_mac (usr, dst))
     {  
	// restore original value
	memcpy ((void*) dst, (void*) tmp, 6);
	return MOPS_PDESC_FAILURE;
     };
   
   return MOPS_PDESC_SUCCESS;
}


// Maps an IP address string into an byte-array u_int8_t ip[4] 
// Note: the destination is NOT an u_int32_t !!!
int mops_pdesc_ip (u_int8_t *dst, char* usr)
{
   u_int8_t tmp[4];
   int i, len, j=0;
   
   // Check if format is correct IPv4:
   len = strlen(usr);
   for (i=0; i<len; i++)
     {
	if (usr[i]=='.') 
	  j++;
	else if (!isdigit(usr[i]))
	  return MOPS_PDESC_FAILURE;
     }
   if (j!=3) return MOPS_PDESC_FAILURE;
   
   // temporarily backup current value
   memcpy ((void*) tmp, (void*) dst, 4);
   
   if (num2hex (usr, dst)!=4)
     {  
	// restore original value
	memcpy ((void*) dst, (void*) tmp, 4);
	return MOPS_PDESC_FAILURE;
     };
   
   return MOPS_PDESC_SUCCESS;
}






//////// Initialization functions for each protocol descriptor ///////////                    
//// Each function expects that an appropriate p_desc is already assigned
//// Also the p_desc_type should be set already.
	





int mops_init_pdesc_cdp(struct mops *mp)
{
   if (mp->p_desc == NULL) return 1;  // p_desc not properly assigned 

   
   return 0;
}


int mops_init_pdesc_dns(struct mops *mp)
{
   if (mp->p_desc == NULL) return 1;  // p_desc not properly assigned 

   
   return 0;
}


int mops_init_pdesc_icmp(struct mops *mp)
{
   if (mp->p_desc == NULL) return 1;  // p_desc not properly assigned 

   
   return 0;
}



int mops_init_pdesc_syslog(struct mops *mp)
{
   if (mp->p_desc == NULL) return 1;  // p_desc not properly assigned 
   
   return 0;
}







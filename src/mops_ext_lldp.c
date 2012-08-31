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
int mops_init_pdesc_lldp(struct mops *mp)
{
	struct mops_ext_lldp * pd;
	int i=0;
	
	if (mp->p_desc == NULL) return 1;  // p_desc not properly assigned 
	pd = mp->p_desc;

	mp->eth_type = 0x88cc;
	str2hex("01:80:c2:00:00:0e", mp->eth_dst, 6);
	mp->ndelay.tv_sec = 30;
	mp->ndelay.tv_nsec = 0;
	
	// get interface index for that packet
	i = mops_get_device_index(mp->device);
	
	pd->non_conform = 0;
	pd->chassis_id_subtype = 4; // MAC address
	if (pd->chassis_id==NULL) pd->chassis_id = malloc(255);
	if (pd->chassis_id==NULL) return 1;
	memcpy((void*) pd->chassis_id, (void*) device_list[i].mac_mops, 6);
	pd->chassis_id_len = 6;
	pd->port_id_subtype = 5; // interface name
	pd->port_id_len = strnlen(mp->device, 15);
	if (pd->port_id==NULL) pd->port_id = malloc(255);
	if (pd->port_id==NULL) return 1;
	memcpy((void*) pd->port_id, (void*) mp->device, pd->port_id_len);
	pd->TTL = 120;
	pd->optional_tlvs_s = 0;
	if (pd->optional_tlvs==NULL) pd->optional_tlvs = malloc(MAX_LLDP_OPT_TLVS);
	if (pd->optional_tlvs == NULL) return 1;
	return 0;
}



int mops_update_lldp (struct mops * mp)
{
	struct mops_ext_lldp * pd;
   
	pd = mp->p_desc; 
	if (pd==NULL) return 1;  // no valid pointer to a p_desc
	mp->msg_s = 0; // important! Otherwise the msg would get longer and longer after each call!
	
	switch (pd->non_conform) {
		
	 case 0: // Derive mandatory TLVs from struct entries and insert optional_tlvs
		mp->msg_s += mops_lldp_tlv_chassis(mp->msg, 
						   pd->chassis_id_subtype, 
						   pd->chassis_id_len, 
						   pd->chassis_id);
		mp->msg_s += mops_lldp_tlv_port(&mp->msg[mp->msg_s],
						pd->port_id_subtype,
						pd->port_id_len,
						pd->port_id);
		mp->msg_s += mops_lldp_tlv_TTL(&mp->msg[mp->msg_s],
					       pd->TTL);
		if (pd->optional_tlvs_s) {
			memcpy((void*) &mp->msg[mp->msg_s], 
			       (void*) pd->optional_tlvs, 
			       pd->optional_tlvs_s);
			mp->msg_s += pd->optional_tlvs_s;
		}
		mp->msg_s += mops_lldp_tlv_end(&mp->msg[mp->msg_s]); 
		break;
		
	 case 1: // User defined ALL TLVs (i. e. ignore struct entries)
		if (pd->optional_tlvs_s) {
			memcpy((void*) &mp->msg[mp->msg_s], 
			       (void*) pd->optional_tlvs, 
			       pd->optional_tlvs_s);
			mp->msg_s += pd->optional_tlvs_s;
		}
		mp->msg_s += mops_lldp_tlv_end(&mp->msg[mp->msg_s]); 
		break;
	 default:
		return 1;
	}
	return 0;
}


///////////////////////////////////////////////////////////////////////////////
//                                                                           //
// Below are utility functions to creade the LLDPU. From these, the          //
// following can be used for the optional part:                              //
//                                                                           // 
//                                                                           //
//                                                                           //
//                                                                           //
                                                                           
/* 

int  mops_lldp_opt_tlv          (struct mops *mp, int type, int len, u_int8_t *value)
int  mops_lldp_opt_tlv_chassis  (struct mops *mp, int subtype, int len, u_int8_t *cid)
int  mops_lldp_opt_tlv_port     (struct mops *mp, int subtype, int len, u_int8_t *pid)
int  mops_lldp_opt_tlv_TTL      (struct mops *mp, int ttl)
int  mops_lldp_opt_tlv_vlan     (struct mops *mp, int vlan)
int  mops_lldp_opt_tlv_end      (struct mops *mp) 
int  mops_lldp_opt_tlv_bad      (struct mops *mp, int type, int badlen, int len, u_int8_t *value)
int  mops_lldp_opt_tlv_org      (struct mops *mp, int oui, int subtype, int len, u_int8_t *inf)

*/


//                                                                           //
//                                                                           //
//                                                                           //
//                                                                           //
//                                                                           //
//                                                                           //
//                                                                           //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////





// Creates a LLDP TLV for a given type number and value string. The result will 
// be written into 'tlv'.
// 
// NOTE: len must be given and indicates the length of value.
// 
// RETURN VALUE: - Total number of bytes of this tlv
//               - 0 upon error
//               
int mops_lldp_tlv (u_int8_t *tlv, int type, int len, u_int8_t *value)
{
	u_int16_t tl=0, tln=0;
	
	if ((type>127) || (len>511)) return 0;
	
	tl = type << 9;
	tl |= len;
	
	tln = htons(tl);
	memcpy((void*) tlv, (void*) &tln, 2);
	memcpy((void*) &tlv[2], (void*) value, len);
	
	return len+2;
}


// Same as above but **adds the TLVs to the 'pd->optional_tlvs' string.**
// It also checks if MAX_LLDP_OPT_TLVS is exceeded.
//
// NOTE: first argument is a pointer to that mops!
//   
// RETURN VALUE: - 0 upon error (no more space)
//               - Total number of bytes written
// 
int mops_lldp_opt_tlv (struct mops * mp, int type, int len, u_int8_t *value)
{
	struct mops_ext_lldp * pd;
	u_int8_t tmp[MAX_LLDP_OPT_TLVS]; // this *must* be sufficient in length
	int l;
	
	if (mp->p_desc == NULL) return 1;  // p_desc not properly assigned 
	pd = mp->p_desc;
	
	l = mops_lldp_tlv (tmp, type, len, value);
	
	if ((MAX_LLDP_OPT_TLVS - pd->optional_tlvs_s)< (l+1)) return -1; // not enough space
	memcpy((void*) (pd->optional_tlvs + pd->optional_tlvs_s), (void*) tmp, l);
	pd->optional_tlvs_s += l;
	return l;
}


///////////////////////////////////////////////////////////////////////////////
//                                                                           //
//                                                                           //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////



// Creates a Chassis ID TLV -- the first mandatory TLV.
// The result will be written into 'tlv'.
// 
// RETURN VALUE: - Total number of bytes within tlv
//               - 0 upon error
//               
int mops_lldp_tlv_chassis (u_int8_t *tlv, int subtype, int len, u_int8_t *cid)
{
	u_int8_t tmp[256];
		
	if ((len>255) || (subtype>255)) return 0;
	
	tmp[0] = (u_int8_t) subtype;
	memcpy((void*) (tmp+1), (void*) cid, len);
	return mops_lldp_tlv(tlv, 1, len+1, tmp);
	
}

// Same but for optional tlv string
int mops_lldp_opt_tlv_chassis (struct mops *mp, int subtype, int len, u_int8_t *cid)
{
	u_int8_t tmp[256];
		
	if ((len>255) || (subtype>255)) return 0;
	tmp[0] = (u_int8_t) subtype;
	memcpy((void*) (tmp+1), (void*) cid, len);
	return mops_lldp_opt_tlv(mp, 1, len+1, tmp);
}



///////////////////////////////////////////////////////////////////////////////
//                                                                           //
//                                                                           //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////



// Creates a Port ID TLV -- the second mandatory TLV.
// The result will be written into 'tlv'.
// 
// RETURN VALUE: - Total number of bytes within tlv
//               - 0 upon error
//               
int mops_lldp_tlv_port (u_int8_t *tlv, int subtype, int len, u_int8_t *pid)
{
	u_int8_t tmp[256];
		
	if ((len>255) || (subtype>255)) return 0;
	
	tmp[0] = (u_int8_t) subtype;
	memcpy((void*) (tmp+1), (void*) pid, len);
	return mops_lldp_tlv(tlv, 2, len+1, tmp);
}

// Same but for optional tlv string
int mops_lldp_opt_tlv_port (struct mops *mp, int subtype, int len, u_int8_t *pid)
{
	u_int8_t tmp[256];
		
	if ((len>255) || (subtype>255)) return 0;
	tmp[0] = (u_int8_t) subtype;
	memcpy((void*) (tmp+1), (void*) pid, len);
	return mops_lldp_opt_tlv(mp, 2, len+1, tmp);
}


///////////////////////////////////////////////////////////////////////////////
//                                                                           //
//                                                                           //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////


// Creates a TTL TLV -- the third mandatory TLV.
// The result will be written into 'tlv'.
// 
// RETURN VALUE: - Total number of bytes within tlv
//               - 0 upon error
//               
int mops_lldp_tlv_TTL (u_int8_t *tlv, int ttl)
{
	u_int16_t ttlh=0, ttln=0;
	
	if (ttl>0xffff) return 0;
	
	ttlh = (u_int16_t) ttl;
	ttln = htons(ttlh);
	
	return mops_lldp_tlv(tlv, 3, 2, (u_int8_t*) &ttln);
}


// Same but for optional tlv string
int mops_lldp_opt_tlv_TTL (struct mops *mp, int ttl)
{
	u_int16_t ttlh=0, ttln=0;
	
	if (ttl>0xffff) return 0;
	
	ttlh = (u_int16_t) ttl;
	ttln = htons(ttlh);
	
	return mops_lldp_opt_tlv(mp, 3, 2, (u_int8_t*) &ttln);
}

///////////////////////////////////////////////////////////////////////////////
//                                                                           //
//                                                                           //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////


// Creates an End of LLDPDU TLV -- the last mandatory TLV.
// The result will be written into 'tlv'.
// 
// RETURN VALUE: - Total number of bytes within tlv
//               - 0 upon error
//               
int mops_lldp_tlv_end (u_int8_t *tlv)
{
	tlv[0] = 0x00;
	tlv[1] = 0x00;
	return 2;
}

// Same but for optional tlv string
int mops_lldp_opt_tlv_end (struct mops *mp)
{
	struct mops_ext_lldp * pd;

	if (mp->p_desc == NULL) return 1;  // p_desc not properly assigned 
	pd = mp->p_desc;

	if ((MAX_LLDP_OPT_TLVS - pd->optional_tlvs_s) > 2) {
		pd->optional_tlvs[pd->optional_tlvs_s++] = 0x00;
		pd->optional_tlvs[pd->optional_tlvs_s++] = 0x00;
		return 2;
	} else 
		return 0;
}


///////////////////////////////////////////////////////////////////////////////
//                                                                           //
//                                                                           //
//                                                                           //
///////////////////////////////////////////////////////////////////////////////


// Creates a 'bad' LLDP TLV for a given type number and value string. 
// The result will be appended into 'pd->optional_tlvs'
// 
// NOTE: 'len' must be given and indicates the TRUE length of value.
//       'badlen' can be any number and is used as official length within the TLV
//       
// RETURN VALUE: - Total number of bytes within tlv
//               - 0 upon error
//               
int mops_lldp_opt_tlv_bad (struct mops *mp,
		       int type, 
		       int badlen, 
		       int len, 
		       u_int8_t *value)
{
	u_int16_t tl=0, tln=0;
	u_int8_t tlv[512];
	struct mops_ext_lldp * pd = mp->p_desc;
	
	if ((type>127) || (len>511) || (badlen>511)) return 0;
	if ((MAX_LLDP_OPT_TLVS - pd->optional_tlvs_s) < (len+3)) return 0;
	
	tl = type << 9;
	tl |= badlen;
	
	tln = htons(tl);
	memcpy((void*) tlv, (void*) &tln, 2);
	memcpy((void*) &tlv[2], (void*) value, len);
	// this detour has historical reasons ;-)
	memcpy((void*) (pd->optional_tlvs + pd->optional_tlvs_s), (void*) tlv, len+2); 
	pd->optional_tlvs += len+2;

	return len+2;
}



// Creates a Organisational-specific TLV -- the second mandatory TLV.
// The result will be appended into 'pd->optional_tlvs'
// 
// RETURN VALUE: - Total number of bytes within tlv
//               - 0 upon error
//               
int mops_lldp_opt_tlv_org (struct mops *mp,
		       int oui,
		       int subtype, 
		       int len, 
		       u_int8_t *inf)
{
	u_int8_t tmp[512];
	u_int8_t *x;
	u_int32_t oui_n = (u_int32_t) oui;
	
	if ((len>507) || (subtype>255) || (oui_n>0xffffff)) return 0;

	x = (u_int8_t *) &oui_n;
	tmp[0] = *(x+2);
	tmp[1] = *(x+1);
	tmp[2] = *x;
	tmp[3] = (u_int8_t) subtype;
	memcpy((void*) (tmp+4), (void*) inf, len);
	return mops_lldp_opt_tlv(mp, 127, len+4, tmp);
}


int mops_lldp_opt_tlv_vlan (struct mops *mp,
			 int vlan)
{
	u_int16_t vid;
	if (vlan>0xffff) return 0; // yes, we also allow VLAN IDs > 4095
	vid = htons(vlan);
	return mops_lldp_opt_tlv_org (mp, 0x80c2, 1, 2, (u_int8_t*) &vid);
}


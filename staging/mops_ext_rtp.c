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
int mops_init_pdesc_rtp(struct mops *mp)
{
	struct mops_ext_rtp * pd;
	
	if (mp->p_desc == NULL) return 1;  // p_desc not properly assigned 
	pd = mp->p_desc;

	// set RTP defaults
	pd->v           = 2;
	pd->p           = 0;
	pd->x           = 0;
	pd->cc          = 0;
	pd->m           = 0;
	
	pd->pt            = 8; // 0=PCMU, 8=PCMA
	pd->sqnr          = 0;
	pd->tst           = 0;
	pd->tst_inc       = 160;
	pd->ssrc          = mz_rand32(); // Default Mausezahn stream would be 0xCAFEBABE
	pd->source        = 0; // don't use /dev/dsp  (but user may configure source = DSP_SOURCE)
	pd->cc_real       = 0;
	
	pd->x_type = 0; // no extension by default

	// General packet parameters
	mp->dp = 30000;
	mp->sp = 30002;
	mp->ndelay.tv_sec = 0;
	mp->ndelay.tv_nsec = 20000000;
	
	memset(&pd->payload, 0x00, MOPS_RTP_MAX_PAYLOAD_SIZE);
	
	return 0;
}


/*
 *  Standard RTP header according RFC 3550 
 * 
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |V=2|P|X|  CC   |M|     PT      |       sequence number         |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                           timestamp                           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |           synchronization source (SSRC) identifier            |
 *    +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
 *    |            contributing source (CSRC) identifiers             |
 *    |                             ....                              |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 
 *  !!! NOTE !!! -- This function should be used only to prepare the RTP
 *  header once. It does not update dynamic fields. To update dynamic fields
 *  each time a subsequent RTP packet is sent, use the function
 *  mops_update_rtp_dynamics().
 * 
 */
int mops_update_rtp (struct mops * mp)
{
	struct mops_ext_rtp * pd;
	int i,j;
	
	pd = mp->p_desc; 
	if (pd==NULL) return 1;  // no valid pointer to a p_desc
	mp->msg_s = 0;           // !! IMPORTANT !! Otherwise the msg would get longer and longer after each call!
	
	// 1st byte
	mops_msg_add_byte (mp, pd->cc);
	mops_msg_add_field (mp, pd->v, 6);
	mops_msg_add_field (mp, pd->p, 5);
	mops_msg_add_field (mp, pd->x, 4);

	// 2nd byte
	mops_msg_add_byte (mp, pd->pt);
	mops_msg_add_field (mp, pd->m, 7);
	
	// remaining
        mops_msg_add_2bytes (mp, pd->sqnr);
	mops_msg_add_4bytes (mp, pd->tst);
	mops_msg_add_4bytes (mp, pd->ssrc);

	// Add CSRC list?
	if ((j=pd->cc_real)) {
		if (j>16) { j=16; pd->cc_real=16; } // silent self healing if desired :-)
		for (i=0; i<j; i++) 
			mops_msg_add_4bytes (mp, pd->csrc[i]);
	}
	pd->rtp_header_len = 12 + j*4;
	
	/*
	 *  Add Extension header?
	 *  
	 *     0                   1                   2                   3
	 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *    |      defined by profile       |           length              |
	 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *    |                        header extension                       |
	 *    |                             ....                              |
	 */ 

	switch (pd->x_type) {
	 case 0: // none
		break;
	 case 1: // set aero, 8 bytes in total -- TODO -- 
		break;
	 case 42: // Mausezahn extension header: 
		  //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		  //    |      MOPS_RTP_EXT_MZID        |           length=4            |
	          //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	          //    |                      TX-timestamp sec                         |
		  //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	          //    |                      TX-timestamp nsec                        |
		  //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	          //    |                 Estimated Peer TX-timestamp sec               |
		  //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	          //    |                 Estimated Peer TX-timestamp nsec              |
		  //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		mops_msg_add_2bytes (mp, MOPS_RTP_EXT_MZID);
		mops_msg_add_2bytes (mp, 2);
		mops_msg_add_4bytes (mp, 0); // only placeholders, must be updated each packet
		mops_msg_add_4bytes (mp, 0); // only placeholders, must be updated each packet
		mops_msg_add_4bytes (mp, 0); // only placeholders, must be updated each packet
		mops_msg_add_4bytes (mp, 0); // only placeholders, must be updated each packet

		pd->rtp_header_len += 20;
		break;
	 default:
		return 1;
		break; // paranoid?
	}

	// Now add the payload
	switch (pd->pt) {
	 case 0:
	 case 8:
		mp->msg_s = 160 + pd->rtp_header_len; // simply set total RTP PDU length (the RTP payload is still undefined)
		mp->ndelay.tv_sec = 0;
		mp->ndelay.tv_nsec = 20000000;
		break;
	 default:
		break;
	}
	
	return 0;
}



// This function directly updates the dynamic RTP fields
// within the mops frame (=be quick here).
// 
// This function is typically called from within the transmission loops,
// see e. g. mops_tx_thread_native()
// 
// This includes:
// 
//   - RTP SQNR
//   - RTP Timestamp
//   - Mausezahn extension header if any
//   - The RTP payload
//   
int mops_update_rtp_dynamics (struct mops * mp)
{
	struct mops_ext_rtp * pd;
	struct timespec ct;
	int j, i = mp->begin_MSG;
	
	pd = mp->p_desc;  if (pd==NULL) return 1;  


	// The following variables must be incremented AFTER assignment to frame, 
	// so the initial values are also used!
	// 
	mops_hton2 (&pd->sqnr, &mp->frame[i+2]);
	pd->sqnr++;

	mops_hton4 (&pd->tst, &mp->frame[i+4]);
	pd->tst += pd->tst_inc; 

	
	// Extension header:
	// Timestamp must be updated BEFORE assignment to frame
	// 
	switch (pd->x_type) {
	 case 42: // Mausezahn extension header: Update timestamps
		j = i + pd->rtp_header_len; // points to first byte of timestamp of MZ extension header
		clock_gettime(CLOCK_MONOTONIC, &ct);
		mops_hton4 ((u_int32_t*) &ct.tv_sec,  &mp->frame[j-16]);
		mops_hton4 ((u_int32_t*) &ct.tv_nsec, &mp->frame[j-12]);
//[TODO] **** estimated peer timestamp **** PSEUDOCODE FOLLOWING:
//              if (peer_exists) {
//                 get_peer_timestamp_estimation(&est);
//		   mops_hton4 ((u_int32_t*) &est.sec,  &mp->frame[j-8]);
//		   mops_hton4 ((u_int32_t*) &est.nsec, &mp->frame[j-4]);
//		}
		break;
	 default:
		return 0;
		break;
	}

	// The pd->payload contains either zeroes or realtime voice data
	//   The pd->payload is initialized with zeroes and IFF a reading thread 
	//   exists, it may copy voice segments (e. g. from /dev/dsp) to 
	//   pd->payload. 
	// NOTE that there is NO NEED to protect pd->payload with mutexes, because
	// only if the reading thread is finished it (itself!) will call THIS function.
	if (pd->source == DSP_SOURCE) {
		memcpy((void*) &mp->frame[j], (void*) pd->payload, pd->payload_s);
	}
	
	return 0;
}


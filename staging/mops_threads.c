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
#include "llist.h"



void mops_set_active (struct mops *mp)
{
	pthread_mutex_lock (& (mp->mops_mutex) );
	mp->state = MOPS_STATE_ACTIVE;
	pthread_mutex_unlock (& (mp->mops_mutex) );
}

void mops_set_seqact (struct mops *mp)
{
	pthread_mutex_lock (& (mp->mops_mutex) );
	mp->state = MOPS_STATE_SEQACT;
	pthread_mutex_unlock (& (mp->mops_mutex) );
}


void mops_set_conf (struct mops *mp)
{
   pthread_mutex_lock (& (mp->mops_mutex) );
   mp->state = MOPS_STATE_CONFIG;
   pthread_mutex_unlock (& (mp->mops_mutex) );
}


int mops_is_active (struct mops *mp)
{
   int i=0;
   pthread_mutex_lock (& (mp->mops_mutex) );
   if (mp->state == MOPS_STATE_ACTIVE) i=1;
   pthread_mutex_unlock (& (mp->mops_mutex) );
   return i;
}

// Returns 1 if the packet is in any running state
// such as MOPS_STATE_ACTIVE or MOPS_STATE_SEQACT
int mops_is_any_active (struct mops *mp)
{
   int i=0;
   pthread_mutex_lock (& (mp->mops_mutex) );
   if (mp->state > MOPS_STATE_CONFIG) i=1;
   pthread_mutex_unlock (& (mp->mops_mutex) );
   return i;
}


int mops_is_seqact (struct mops *mp)
{
   int i=0;
   pthread_mutex_lock (& (mp->mops_mutex) );
   if (mp->state == MOPS_STATE_SEQACT) i=1;
   pthread_mutex_unlock (& (mp->mops_mutex) );
   return i;
}



// return mops state (0=MOPS_STATE_NULL, 1=MOPS_STATE_INIT, 2=MOPS_STATE_CONFIG, 3=MOPS_STATE_ACTIVE, 4=MOPS_STATE_SEQACT)
int mops_state (struct mops *mp)
{
   int i=0;
   pthread_mutex_lock (& (mp->mops_mutex) );
   i = mp->state;
   pthread_mutex_unlock (& (mp->mops_mutex) );
   return i;
}


int mops_tx_simple (struct mops *mp)
{

	if (mops_is_active(mp)) {
		return 3;  
	}

	if (mp->interval_used) {
		if ( pthread_create( &(mp->interval_thread), NULL, mops_interval_thread, mp) )  {
			mp->interval_used=1; // 1 means interval only configured
			return 1; // Error creating thread
		}
	} else // normal packet train
		if ( pthread_create( &(mp->mops_thread), NULL, mops_tx_thread_native, mp) )  {
		return 1; // Error creating thread
	}
   
	return 0;
}


// Starts a packet sequence.
// 
// RETURN VALUES: 0 upon success
//                1 failure: packet not in CONFIG state
//                2 failure: packet has infinite count
int mops_tx_sequence (struct mz_ll *seq)
{
	struct pseq *cur;
	int i;

	// verify 1) that all packets are in config state 
	//        2) and have finite count:
	cur = (struct pseq*) seq->data;
	for (i=0; i<cur->count; i++) {
		if (cur->packet[i]->state!=MOPS_STATE_CONFIG) return 1;
		if (cur->packet[i]->count==0) return 2;
	}

	// Set all packets in this sequence into state SEQACT:
	for (i=0; i<cur->count; i++)
		mops_set_seqact (cur->packet[i]);
	
	if ( pthread_create( &(seq->sequence_thread), NULL, mops_sequence_thread, seq) )  {
		return 3; // Error creating thread
	}
	seq->state=1;
	return 0;
}
	

// This is the sequence sending thread
void *mops_sequence_thread (void *arg)
{
	struct mz_ll *seq = (struct mz_ll*) arg;
	struct pseq *cur;
	int i;
	
	cur = (struct pseq*) seq->data;
	
	// Send one packet after each other, possibly with gaps inbetween:
	for (i=0; i<cur->count; i++) {
		mops_tx_thread_native (cur->packet[i]);
		// if gap exists...
		if ((cur->gap[i].tv_sec) || (cur->gap[i].tv_nsec)) { 
			nanosleep(&cur->gap[i], NULL); //...apply it.
		}
	}
	
	// Finally:
	// 1) reset all packets into config state
	for (i=0; i<cur->count; i++)
		cur->packet[i]->state=MOPS_STATE_CONFIG;
	// 2) join to main
	pthread_exit(NULL);
	// 3) set sequence state to inactive (=0)
	seq->state=0;
	
	return NULL;
}

// This is the interval management thread which starts
// packet transmission threads by itself. 
// 
// Note how this works: After the while statement below we have actually 
// two threads, mops_tx_thread_native (sending the packet) and mops_interval_thread which
// starts mops_tx_thread_native every mp->interval. If mp->interval is smaller than
// mp->delay (and mp->count > 1) then multiple transmission threads will be active at the 
// same time which is usually not what the user wants. We do not catch this case here
// but the user interface should do that (it is done in 'cmd_packet_interval').
// 
void *mops_interval_thread (void *arg)
{
	struct mops *mp = (struct mops*) arg;

	mp->interval_used=2; // 2 means active interval
	while (1) {
		if ( pthread_create( &(mp->mops_thread), NULL, mops_tx_thread_native, mp) )  {
			mp->interval_used=1; 
			pthread_exit(NULL); 
		}
		nanosleep(&mp->interval, NULL);
	}
	
	pthread_exit(NULL); // hmm...does this make sense?
	return NULL;
}


// General MOPS sending thread using packet sockets.
// 
void *mops_tx_thread_native (void *arg)
{
	struct mops *mp = (struct mops*) arg;
	struct mops_ext_rtp * pd;
	int ps, i, n=0;
	u_int8_t DA[4];
	// Local vars are faster  --------------------------
	struct timespec tv;
	register int infinity, devind;
	int ip_src_isrange = mp->use_IP & mp->ip_src_isrange;
	int ip_dst_isrange = mp->use_IP & mp->ip_dst_isrange;
	int sp_isrange = (mp->use_UDP | mp->use_TCP) & mp->sp_isrange;
	int dp_isrange = (mp->use_UDP | mp->use_TCP) & mp->dp_isrange;
	int ip_src_israndom = mp->use_IP & mp->ip_src_israndom;
	int sp_isrand = (mp->use_UDP | mp->use_TCP) & mp->sp_isrand;
	int dp_isrand = (mp->use_UDP | mp->use_TCP) & mp->dp_isrand;

	
	u_int32_t 
		ip_src_start = mp->ip_src_start,
		ip_src_stop = mp->ip_src_stop,
		ip_dst_start = mp->ip_dst_start,
		ip_dst_stop = mp->ip_dst_stop,
		tcp_seq_delta = mp->tcp_seq_delta,
		tcp_seq_range = 0,
	        tcp_ack_delta = mp->tcp_ack_delta,
		tcp_ack_range = 0,
		tcp_ack_count = 0,
		tcp_seq_count = 0;
	
	int
	        sp_start = mp->sp_start,
	        dp_start = mp->dp_start,
	        sp_stop = mp->sp_stop,
	        dp_stop = mp->dp_stop;

	int     
		rtp_mode = 0; // RTP not used
	
	int
		fragsize = 0,
		frag_overlap = 0,
		fragptr = 0,
		offset = 0,
		offset_delta = 0,
		begin_ip_payload = 0,
		ip_payload_s = 0,
		original_msg_s = 0,
		whats_used = 0; // store use_UDP or use_TCP here to clean up packet parameters finally
	char
		original_msg[MAX_MOPS_MSG_SIZE+1], // temporary buffer when fragmentation is needed
		ip_payload[MAX_MOPS_MSG_SIZE+1];   // temporary buffer when fragmentation is needed
		
	        
	// -------------------------------------------------
	
	
	/////////////////////////////
	// NOTE: If packet is part of a sequence, then this function is already part of a sequence thread
	//       and all packets are already in state SEQACT. Otherwise we set the packet in state ACTIVE.
	if (!mops_is_seqact(mp)) 
		mops_set_active (mp);
	/////////////////////////////


	// infinite or not? Count up or down?
	if (mp->count == 0) {
		infinity = 1; 
		mp->cntx = 0;
	}
	else {
		infinity = 0; 
		mp->cntx = mp->count; // count down
	}

	// Which delay?
	tv.tv_sec  = mp->ndelay.tv_sec;
	tv.tv_nsec = mp->ndelay.tv_nsec;

	// Which interface?
	for (i=0; i<device_list_entries; i++) {
		if (strncmp(device_list[i].dev, mp->device, 15)==0) break;
	}
	devind=i;
	
	// Packet socket already existing and valid?
	ps = device_list[devind].ps; // the packet socket
	if (ps<0) goto FIN;

	// Automatic direct or indirect delivery for IP packets?
	if ((mp->use_IP) && (mp->auto_delivery_off == 0)) {
		if (mp->ip_dst_isrange)
			mops_hton4(&mp->ip_dst_start, DA);
		else
			mops_hton4(&mp->ip_dst, DA);
		
		mops_ip_get_dst_mac(&device_list[devind], DA, mp->eth_dst);
	}


	// Impossible settings
	if (((ip_src_isrange) && (ip_src_israndom)) ||
            ((sp_isrand) && (sp_isrange)) ||
	    ((dp_isrand) && (dp_isrange))) {
		fprintf(stderr, "[ERROR] (mops_tx_thread_native) -- conflicting requirements: both range and random!\n");
		goto FIN;
	}
	
	// Initialize start values when ranges have been defined
	if (ip_src_isrange)      mp->ip_src  = mp->ip_src_start;
	if (ip_dst_isrange)      mp->ip_dst  = mp->ip_dst_start;
	if (sp_isrange)          mp->sp      = mp->sp_start;
	if (dp_isrange)          mp->dp      = mp->dp_start;
	if (tcp_seq_delta) {
		tcp_seq_range = mops_tcp_complexity_sqnr(mp);
		mp->tcp_seq = mp->tcp_seq_start;  
		tcp_seq_count = tcp_seq_range; 
	}
	if (tcp_ack_delta) {
		tcp_ack_range = mops_tcp_complexity_acknr(mp);
		mp->tcp_ack = mp->tcp_ack_start;  
		tcp_ack_count = tcp_ack_range; 
	}

	// RTP special message treatment
	if (mp->p_desc_type == MOPS_RTP) {
		pd = mp->p_desc; 
		if (pd==NULL) return NULL;
		if (pd->source == DSP_SOURCE) 
			rtp_mode = 2; // dsp payload
			else
			rtp_mode = 1; // zero payload
		
		mops_update_rtp (mp); // initialize RTP packet here 
	}
	
 	                             // TODO: VLAN, MPLS - ranges
	
	//
	// ---------------------- The holy transmission loop ---------------- // 
	//

	// Update whole packet (once before loop!)
	mops_ext_update (mp);
	mops_update(mp);

	
	// Check if IP fragmentation is desired.
	// If yes, set local 'fragsize' and 'begin_ip_payload' pointer.
	if (mp->ip_fragsize) {
		if (mp->use_IP) {
			fragsize = mp->ip_fragsize;
			frag_overlap = mp->ip_frag_overlap;
			offset = mp->ip_frag_offset;
			offset_delta = (fragsize-frag_overlap)/8;
			if (mp->use_UDP) {
				begin_ip_payload = mp->begin_UDP;
				whats_used = 1;
			} else if (mp->use_TCP) {
				begin_ip_payload = mp->begin_TCP;
				whats_used = 2;
			} else {
				begin_ip_payload = mp->begin_MSG;
				whats_used = 0;
			}
			ip_payload_s = mp->frame_s - begin_ip_payload;
			memcpy((void*) original_msg, (void*) mp->msg, mp->msg_s);
			original_msg_s = mp->msg_s;
			memcpy((void*) ip_payload, (void*) &mp->frame[begin_ip_payload], ip_payload_s);
		}
	}	
	
	
	goto START; // looks like a dirty hack but reduces a few cpu cycles each loop
	
	do {
		INLOOP:
		nanosleep(&tv, NULL); // don't apply this before first and after last packet.
		START:
		
		// +++++++++++++++++++++++++++++++++++

		
		// ------ IP fragmentation required? ------------------------------------------------------
		// 
		// Basic idea: At this point we assume that all updates have been already applied
		// so mp->frame contains a valid packet. But now we do the following:
		// 
		// 1. Determine first byte after end of IP header (IP options may be used) [done above]
		// 2. Store the 'IP payload' in the temporary buffer 'ip_payload' [done above]
		// 3. Create a new IP payload but take only the first fragsize bytes out of 'ip_payload'
		// 4. This new IP payload is copied into mp->msg
		// 5. Set the IP parameters: MF=1, offset=0
		// 6. Call mops_update() and send the packet
		// 7. offset = offset + fragsize/8 
		// 8. Increment the IP identification number
		// 9. Repeat this until the last fragment is reached. For the last fragment
		//   set the flag MF=0.
		// 10. Restore the original IP parameters (use_UDP or use_TCP)
		if (fragsize) { 
			mp->use_UDP=0;
			mp->use_TCP=0;
			fragptr=0; // NOTE: by intention we do not set mp->ip_frag_offset to 0 here !!! The user knows what she does!
			mp->ip_flags_MF=1;			
			mp->ip_id++; // automatically wraps around correctly (u_int16_t)
			// send all fragments except the last one:
			while(fragptr+fragsize < ip_payload_s) {
				memcpy((void*) mp->msg, (void*) ip_payload+fragptr, fragsize);
				mp->msg_s = fragsize;
				mops_update(mp);
				n = write(ps, mp->frame, mp->frame_s);
				if (n!=mp->frame_s) {
					fprintf(stderr, "ERROR: Could not send IP fragment through interface %s\n", mp->device);
					// LOG error msg
					goto FIN;
				}
				fragptr+=fragsize;
				mp->ip_frag_offset += offset_delta;
			}
			// send last fragment:
			mp->ip_flags_MF=0;			
			memcpy((void*) mp->msg, (void*) ip_payload+fragptr, ip_payload_s-fragptr);
			mp->msg_s = ip_payload_s-fragptr;
			mops_update(mp);
			n = write(ps, mp->frame, mp->frame_s);
			if (n!=mp->frame_s) {
				fprintf(stderr, "ERROR: Could not send IP fragment through interface %s\n", mp->device);
				// LOG error msg
				goto FIN;
			}
			
			// -- restore original mops parameters --
			switch (whats_used) {
			 case 1: mp->use_UDP = 1; break;
			 case 2: mp->use_TCP = 1; break;
			}
			memcpy((void*) mp->msg, (void*) original_msg, original_msg_s);
			mp->msg_s = original_msg_s;
			mp->ip_frag_offset=offset;
			goto NEXT;
		}
		
		// -- send unfragmented packets here: --
		n = write(ps, mp->frame, mp->frame_s);
		if (n!=mp->frame_s) {
			fprintf(stderr, "ERROR: Could not send packet through interface %s\n", mp->device);
			// LOG error msg
			goto FIN;
		}
		
		NEXT: 
		
		/* [ RTP TODO: ] Use another thread reading from /dev/dsp and signalling us to continue!
		 * It should work like this: (pseudocode below)
		 * 
		 * if (rtp_mode == DSP_SOURCE) {
		 *    pthread_cond_wait ( &mycond, &mymutex ); // wait until pthread condition is signaled
		 *    // now, frame should contain 160 bytes from /dev/dsp 
		 *    goto INLOOP;
		 * } 
		 *
		 * The reading thread will do something like this: (again fuzzy code only)
		 * 
		 * loop:
		 *   read(fd, pd->rtp_payload, 160); // this takes 20 msec anyway
		 *   mops_update_rtp_dynamics (mp); // also updates dynamic header fields
		 *   pthread_cond_broadcast (&mycond);  // wake up TX thread
		 * goto loop;  
		 * 
		 * See also 
		 * http://www.oreilly.de/catalog/multilinux/excerpt/ch14-05.htm
		 *
		 * NOTE that we must not reach nanosleep below because the 20 msec delay is
		 * done implicitely by reading 160 bytes from /dev/dsp
		 */
		
		switch (rtp_mode) {
		 case 1: // dummy payload => segmentation delay is controlled by nanosleep below!
			mops_update_rtp_dynamics (mp);
			break;
		 case 2: // await data from /dev/dsp => segmentation delay is controlled by a reading thread!
			/*    pthread_cond_wait ( &mycond, &mymutex ); // wait until pthread condition is signaled
		         *    // now, frame should contain 160 bytes from /dev/dsp 
		         *    goto INLOOP;
			 */
			break;
		 default:
			// no RTP, continue as usual
			break;
		}
		

		// +++++++++++++++++++++++++++++++++++
		// 
		// *** begin of modifiers -- order is important! *** *************** //
		// 
		if (tcp_seq_delta) {
			if (--tcp_seq_count) {
				mp->tcp_seq += tcp_seq_delta;
				mops_update(mp);
				goto INLOOP;
			} else {
				tcp_seq_count = tcp_seq_range;
				mp->tcp_seq = mp->tcp_seq_start;
				mops_update(mp);
			}
		}
		
		if (tcp_ack_delta) {
			if (--tcp_ack_count) {
				mp->tcp_ack += tcp_ack_delta;
				mops_update(mp);
				goto INLOOP;
			} else {
				tcp_ack_count = tcp_ack_range;
				mp->tcp_ack = mp->tcp_ack_start;
				mops_update(mp);
			}
		}
		
		if (ip_src_isrange) {
			if (++mp->ip_src > ip_src_stop) {
				mp->ip_src = ip_src_start;
				mops_update(mp);
			}
			else {
				mops_update(mp);
				goto INLOOP;
			}
		}

		if (ip_src_israndom) {
			mp->ip_src  = 0x01000001 +  (u_int32_t) ( ((float) rand()/RAND_MAX)*0xE0000000); //latter is 224.0.0.0
		}

		if (ip_dst_isrange) {
			if (++mp->ip_dst > ip_dst_stop) {
				mp->ip_dst = ip_dst_start;
				if (mp->auto_delivery_off == 0) {
					mops_hton4(&mp->ip_dst, DA);
					mp->eth_dst[0] = 0x01;
					mp->eth_dst[1] = 0x00;
					mp->eth_dst[2] = 0x5e;
					mp->eth_dst[3] = DA[1] & 127;
					mp->eth_dst[4] = DA[2];
					mp->eth_dst[5] = DA[3];	
				}
				mops_update(mp);
			}
			else {
				if (mp->auto_delivery_off == 0) {
					mops_hton4(&mp->ip_dst, DA);
					mp->eth_dst[0] = 0x01;
					mp->eth_dst[1] = 0x00;
					mp->eth_dst[2] = 0x5e;
					mp->eth_dst[3] = DA[1] & 127;
					mp->eth_dst[4] = DA[2];
					mp->eth_dst[5] = DA[3];	
				}
				mops_update(mp);
				goto INLOOP;
			}
		}
		
		if (dp_isrange) {
			if (++mp->dp > dp_stop) {
				mp->dp = dp_start;
				mops_update(mp);
			}
			else {
				mops_update(mp);
				goto INLOOP;
			}
		}

		if (dp_isrand) {
			mp->dp  = (u_int16_t) ( ((float) rand()/RAND_MAX)*0xffff); 
		}

		
		if (sp_isrange) {
			if (++mp->sp > sp_stop) {
				mp->sp = sp_start;
				mops_update(mp);
			}
			else {
				mops_update(mp);
				goto INLOOP;
			}
		}
		
		if (sp_isrand) {
			mp->sp  = (u_int16_t) ( ((float) rand()/RAND_MAX)*0xffff); 
		}
		
		
		// *** end of modifiers ******************************************** //
		if (infinity)  {
			mp->cntx++; // count up
			goto INLOOP;
		}
	} while (--mp->cntx);
	
	FIN:
	if (!mops_is_seqact(mp)) { 
		// only [change state and close thread] if packet is NOT part of a sequence.
		// If the packet is part of a sequence then THIS function is already part of 
		// a sequence thread and it will be closed in 'mops_sequence_thread'.
		mops_set_conf (mp);
		pthread_exit(NULL);
	}
	return NULL;
}
	




int mops_destroy_thread (struct mops *mp)
{
	int r=1;
	
	if (mp->interval_used==2) {
		pthread_cancel(mp->interval_thread);
		mp->interval_used=1;
		r=0;
	}
	
	if (mops_is_active(mp)) {
		pthread_cancel(mp->mops_thread);
		pthread_mutex_destroy(& mp->mops_mutex);
		mops_set_conf(mp);
		r=0;
	}
	
	return r;
}

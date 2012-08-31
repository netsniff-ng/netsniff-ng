/*
 * Mausezahn - A fast versatile traffic generator
 * Copyright (C) 2010 Herbert Haas
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
#include "cli.h"
#include "mops.h"
#include "llist.h"


///////////////////// TOC /////////////////////
//
// int              mops_delete_sequence             (char *name)
// struct mz_ll *   mops_create_sequence             (char *name)
// int              mops_dump_sequence               (char* str)
// int              mops_add_packet_to_sequence      (struct mz_ll *seq, struct mops *mp)
// int              mops_add_delay_to_sequence       (struct mz_ll *seq, struct timespec *t)
// int              mops_delete_packet_from_pseq     (struct mz_ll *seq, int index)
// int              stop_sequence                    (char *name)
// int              stop_all_sequences               ()        


// delete one sequence element (from the global packet_sequence list)
// which must be specified by its name
// 
int mops_delete_sequence (char *name)
{
	struct mz_ll *v;
	
	v = mz_ll_search_name (packet_sequences, name);
	if (v==NULL) return 1; // name not found 

	if (v->state) return 2; // sequence is currently active!
	
	if (mz_ll_delete_element (v)) 
		return -1; // cannot delete head element!
	return 0;
}



struct mz_ll * mops_create_sequence (char *name)
{
	struct mz_ll *cur;
	struct pseq *seq;
	int i;
	
	cur = mz_ll_create_new_element(packet_sequences);
	if (cur==NULL) return NULL;
	strncpy(cur->name, name, MZ_LL_NAME_LEN);
	// add data
	cur->data = (struct pseq*) malloc (sizeof(struct pseq));
	// initialize data
	seq = (struct pseq*) cur->data;
	seq->count = 0;
	for (i=0; i<MAX_PACKET_SEQUENCE_LEN; i++) {
		seq->packet[i] = NULL;  // pointer to the packets
		seq->gap[i].tv_sec = 0;
		seq->gap[i].tv_nsec = 0;
	}
	return cur; 
}
	


// PURPOSE: dumps all sequence objects line-by-line
// 
// ARGUMENTS: Caller must provide a pointer to a string of size MZ_LL_NAME_LEN+(MAX_PACKET_SEQUENCE_LEN*6)
//            (recommendation: 512 bytes !)
// 
// RETURN VALUE: 0 if list is finished, 1 otherwise
// 
// EXAMPLE:   char str[512];
//            while (mops_dump_sequence(str)
//               printf("%s\n", str);
//            
int mops_dump_sequence (char* str)
{
	static int init=0;
	static struct mz_ll *cur;
	struct pseq *seq;
	struct mops *pkt;
	
	char tmp[256], t[16];
	int i, c;
	
	tmp[0]='\0';

	if (init==-1) { // last turn said stop now!
		init=0;
		return 0;
	}
	
        if (init==0) {
		cur=packet_sequences->next;
		if (cur==NULL) {
			str[0]='\0';
			return 0;
		}
		init=1;
	}

	seq = (struct pseq*) cur->data;
	if (seq==NULL) {
		init=-1;
		sprintf(str, "(no sequences found)");
		return 1;
	}

	c = seq->count; // amount of currently stored packets in this sequence object

	// create string with all packet IDs:
	for (i=0; i<c; i++) {
		pkt = seq->packet[i];
		if (pkt == NULL) break;
		snprintf(t, 15, "%i", pkt->id);
		if (strnlen(tmp,256)>249) break;
		strncat(tmp, t, 6);
		if (i<c-1) strncat(tmp,", ", 2);
	}

	snprintf(str, 512, "%s {%s}", cur->name, tmp);

	cur=cur->next;
	if (cur==packet_sequences) init=-1; // stop next turn!
	return 1;
}


// finds next free slot in sequence seq and adds packet mp
// 
// RETURN VALUE: 0 upon success
//              -1 failure: array full
//              -2 failure: cannot add packets with infinite count
//              
int mops_add_packet_to_sequence (struct mz_ll *seq, struct mops *mp)
{
	struct pseq *cur;
	int i; 
	
	if (seq==NULL) return 1;

	// don't add packets with count=0
	if (mp->count==0) return -2;
	
	cur = (struct pseq*) seq->data;
	if (cur->count >= MAX_PACKET_SEQUENCE_LEN) return -1; // packet array full!
	for (i=0; i<MAX_PACKET_SEQUENCE_LEN; i++) { 
		if (cur->packet[i]==NULL) { // found empty slot
			cur->packet[i]=mp;
			cur->count++;
			return 0;
		}
	}
	return 1; // never reach here
}


// adds the given delay 't' to the last packet in the sequence's pseq
// 
// NOTE: return index number of pseq where delay had been added
//       or upon failure: -1 if there is no packet yet defined
//                        -2 if array is full
int mops_add_delay_to_sequence (struct mz_ll *seq, struct timespec *t)
{
	struct pseq *cur;
	int i;
	
	if (seq==NULL) return 1;
	
	cur = (struct pseq*) seq->data;
	i = cur->count;
	if (i>= MAX_PACKET_SEQUENCE_LEN) return -2; // packet array full!
	
	cur->gap[i-1].tv_sec = t->tv_sec;
	cur->gap[i-1].tv_nsec = t->tv_nsec;
	
	return i-1; // note: is -1 if there is no packet yet (count=0)
}


// Deletes packet and associated delay from a pseq for given index
// If index == -1 then the last packet/delay is removed
// 
// NOTE: index range is {1..count}
//
// RETURN VALUES: 0 upon success
//                1 upon failure
//                2 upon failure, index too big
//                
int mops_delete_packet_from_pseq (struct mz_ll *seq, int index)
{
	struct pseq *cur;
	int i;

	if (seq==NULL) return 1;
	cur = (struct pseq*) seq->data;
	if (cur->count==0) return 1; // list is empty, nothing to delete
	if (index>cur->count) return 2;
	if ((index==0) || (index<-1)) return 1; // total invalid index values
	if (index==-1) { // remove last element
		cur->packet[cur->count-1]=NULL;
		cur->gap[cur->count-1].tv_sec=0;
		cur->gap[cur->count-1].tv_nsec=0;
	} else {
		for (i=index-1; i<(cur->count-1); i++) {
		cur->packet[i] = cur->packet[i+1];
		cur->gap[i].tv_sec = cur->gap[i+1].tv_sec;
		cur->gap[i].tv_nsec=cur->gap[i+1].tv_nsec;
		}
	}
	cur->count--;	
	return 0;
}
	

int mops_delete_all_packets_from_pseq (struct mz_ll *seq)
{
	struct pseq *cur;
	int i;
	
	if (seq==NULL) return 1;
	cur = (struct pseq*) seq->data;
	if (cur->count==0) return 1; // list is empty, nothing to delete
	// DELETE ALL:
	cur->count = 0;
	for (i=0; i<MAX_PACKET_SEQUENCE_LEN; i++) {
		cur->packet[i] = NULL;  // pointer to the packets
		cur->gap[i].tv_sec = 0;
		cur->gap[i].tv_nsec = 0;
	}
	return 0;
}



// Stops an active sequence and sets all involved packets from state SEQACT to CONFIG.
// 
// RETURN VALUE: 0 upon success
//               1 if sequence does not exist
//               2 if sequence is not actice
int stop_sequence (char *name)
{
	struct mz_ll *v;
	struct pseq *cur;
	int i;
	
	v = mz_ll_search_name (packet_sequences, name);
	if (v==NULL) return 1; // name not found 
	if (!v->state) return 2; // sequence is not currently active!

	// now stop thread:
	pthread_cancel(v->sequence_thread);

	// reset packet states:
	cur = (struct pseq*) v->data;
	for (i=0; i<cur->count; i++)
		cur->packet[i]->state=MOPS_STATE_CONFIG;

	// reset sequence state:
	v->state = 0;
	return 0;
}


// runs through 'packet_sequences' and cancels all active sequences
// (i. e. stops threads and sets states appropriately)
// 
// Comment: It might seem a bit inefficient to call 'stop_sequence' for the
//          detailed work, but this is the more safer way and it is fast enough.
//          
// RETURN VALUE: Number of stopped sequences.
// 
int stop_all_sequences ()
{
	struct mz_ll *cur=packet_sequences->next;
	int i=0;
	
	while (cur!=packet_sequences) {
		if (cur!=packet_sequences) { // just for safety
			if (stop_sequence(cur->name)==0) i++;
		}
		cur=cur->next;
	} 
	
	return i;
}
		

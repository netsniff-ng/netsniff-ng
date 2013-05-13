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



#ifndef MZ_LINKED_LIST
#define MZ_LINKED_LIST

#define MAX_PACKET_SEQUENCE_LEN 20  // how many packets can be defined in a sequence at maximum

// A packet sequence -- this is the list data (each list element corresponds to one sequence)
struct pseq {
	struct mops *packet[MAX_PACKET_SEQUENCE_LEN];  // pointer to the packets
	struct timespec gap[MAX_PACKET_SEQUENCE_LEN];  // optional delay between different packets
	int count; // total number of current members (=packets)
};


// --------------- Mausezahn Multipurpose Linked List: -------------------

#define MZ_LL_NAME_LEN 64

// one list element 
struct mz_ll {
	struct mz_ll *prev;
	struct mz_ll *next;
	struct mz_ll *head; // always points to head element
	int refcount; // head element: total number of list items! (Otherwise can be used as refcount.)
	char name[MZ_LL_NAME_LEN];
	pthread_t  sequence_thread;
	int state; // 0 = inactive, 1 = active
	int index; // monotonically increasing;
	int index_last; //head always stores the last value!
	void *data; // points to your data
};

struct mz_ll *packet_sequences;
struct mz_ll *cli_seq; // currently edited packet sequence used by CLI

// prototypes
struct mz_ll * mz_ll_create_new_element(struct mz_ll *list);
int  mz_ll_delete_element (struct mz_ll *cur);
int mz_ll_delete_list(struct mz_ll *list);
struct mz_ll * mz_ll_search_name (struct mz_ll *list, char *str);
void _mz_ll_set_default (struct mz_ll *cur);
int mz_ll_dump_all(struct mz_ll *list);
int mops_tx_sequence (struct mz_ll *seq);

// convenience functions using the above in a more intelligent way
int mops_delete_sequence(char *name);
struct mz_ll * mops_create_sequence (char *name);
int mops_dump_sequence (char* str);
int mops_add_packet_to_sequence (struct mz_ll *seq, struct mops *mp);
int mops_add_delay_to_sequence (struct mz_ll *seq, struct timespec *t);
int mops_delete_packet_from_pseq (struct mz_ll *seq, int index);
int mops_delete_all_packets_from_pseq (struct mz_ll *seq);
int stop_sequence (char *name);
int stop_all_sequences ();
#endif


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




// -- TOC: --
// 
// struct mops *      mops_init               ()
// struct mops *      mops_alloc_packet       (struct mops *cur)
// struct mops *      mops_delete_packet      (struct mops *cur)
// int                mops_reset_packet       (struct mops *cur)
// 
// int                mops_dump_all           (struct mops* list)
// struct mops *      mops_search_name        (struct mops* list, char* key)
// struct mops *      mops_search_id          (struct mops* list, int key)
// void               mops_delete_all         (struct mops* list)
// void               mops_cleanup            (struct mops* list)
// 
// int                mops_set_defaults       (struct mops *mp)
// int                mops_print_frame        (struct mops *mp, char *str)
//
// int                mops_get_new_pkt_id     (struct mops *mp)
// int                mops_clear_layers       (struct mops *mp)

// int                mops_get_device_index   (char *devname)
// int                mops_use_device         (struct mops * mp, int i)

// int               mops_get_proto_info      (struct mops * mp, char *layers, char *proto)

#include "mz.h"
#include "mops.h"




// Creates first element, aka "head" element
// This element can also be used! See mops_alloc_packet!
// 
struct mops * mops_init()
{
	// these defaults can be changed by the user:
	min_frame_s = MIN_MOPS_FRAME_SIZE; // important global; depends on used packet tx subsystem such as libnet
	max_frame_s = MAX_MOPS_FRAME_SIZE-MOPS_SIZE_MARGIN; 
	
	// Create initial mops element:
	struct mops *new_mops = (struct mops*) malloc(sizeof(struct mops));
	new_mops->next = new_mops;
	new_mops->prev = new_mops;
	new_mops->state = MOPS_STATE_NULL;
	new_mops->id = 0; // importante!
	mops_set_defaults (new_mops);
	strncpy(new_mops->packet_name, "-------", 8);
	
   return new_mops;
}





// Returns pointer to new mops element:
//   1) either insert a new mops element in list
//   2) or returns same pointer again if current mops element is empty
// Note that new element N is always PREPENDED to cur:
//   ... = N-2 = N-1 = N = cur = 1 = 2 = ...
//   
// 
// RETURN VALUE:  + Pointer to new mops
//                - NULL upon failure  
struct mops * mops_alloc_packet(struct mops *cur)
{
	int j;
	struct mops *new_mops;
	int new_pkt_id, pkt_id_name;
	char pname[MAX_MOPS_PACKET_NAME_LEN];
   
	if (cur->state == MOPS_STATE_NULL) { // allows to use first packet in list
		new_mops = cur; // current mops was unused => no need to insert a new mops!
	}
	else { // create new mops element
		new_mops = (struct mops *) malloc(sizeof(struct mops));
		if (new_mops==NULL) {
			fprintf(stderr, "MZ alert: cannot create new mops entry - memory full?\n");
			return NULL; // memory full?
		}
	}

	new_mops->state = MOPS_STATE_INIT;

	// Assign unique packet id
	new_pkt_id = mops_get_new_pkt_id (cur);
	if (new_pkt_id==-1) return NULL;
	new_mops->id = new_pkt_id;   
	
	// Assign unique packet name
	pkt_id_name = new_pkt_id;
	do {
		sprintf(pname, "PKT%04d", pkt_id_name);
		pkt_id_name++;
	} while (mops_search_name (mp_head, pname)); // check if this name is really unique
   
	strncpy(new_mops->packet_name, pname, MAX_MOPS_PACKET_NAME_LEN);
     
	// append to doubly linked list 
	new_mops->prev = cur->prev;
	new_mops->next = cur;
	cur->prev = new_mops;
	new_mops->prev->next = new_mops;
	
	mops_set_defaults (new_mops);  // set header parametes (addresses etc)
   
	// Reset protocol descriptor
	new_mops->p_desc = NULL;
	new_mops->p_desc_type = MOPS_NO_PDESC; 
   
	// clear counter values
	new_mops->used_counters=0;
	for (j=0; j<MAX_MOPS_COUNTERS_PER_PACKET; j++) {
		new_mops->counter[j].use    = 0;
		new_mops->counter[j].offset = 0; 
		new_mops->counter[j].random = 0;
	}
	
	return new_mops;
}



// Delete particular packet (remove it from list).
// 
// If mp_head is deleted, makes previous element mp_head.
// Note that the global mp_head must exist but within MOPS this
// is always the case.
// 
// Returns pointer to previous element in the list
//         or NULL if packet is active
struct mops * mops_delete_packet(struct mops *cur)
{
	struct mops *last;

	if (mops_is_active(cur)) {
		mops_destroy_thread(cur);
	}
	
	mops_ext_del_pdesc (cur); // delete p_desc (if available)
	
	// remove automops data if available
	if (cur->amp != NULL) {
		free(cur->amp);
		cur->amp=NULL;
	}
	if (cur->amp_pdu != NULL) {
		free (cur->amp_pdu);
		cur->amp_pdu=NULL;
	}

	last = cur->prev;
	cur->next->prev = cur->prev;
	cur->prev->next = cur->next;
	if (cur==mp_head) {
		mp_head = last;
	}
	if (cur!=NULL) {
		free (cur);
		cur=NULL;
	}
   return last;
}



// Erase all data of a mops entry and even chooses a new standard name 
// DOES NOT delete the entry from the list
// 
int mops_reset_packet(struct mops *cur)
{
	int i=0;
	char pname[16];

	// stop thread if necessary
	if (mops_is_active(cur)) {
		mops_destroy_thread(cur);
	}
	
	// remove pdesc if available
	mops_ext_del_pdesc (cur);
	cur->state = MOPS_STATE_NULL;

	// remove automops data if available
	if (cur->amp != NULL) {
		free(cur->amp);
		cur->amp=NULL;
	}
	if (cur->amp_pdu != NULL) {
		free (cur->amp_pdu);
		cur->amp_pdu=NULL;
	}
	// find another name
	do {
		sprintf(pname, "PKT%04d", i);
		i++;
	} while (mops_search_name (mp_head, pname)); // check if this name is really unique
	strncpy(cur->packet_name, pname, MAX_MOPS_PACKET_NAME_LEN);
	
	// Place everything else in this function:
	mops_set_defaults (cur);

	return 0;
}




// Runs through all packets and dumps some statistics into 'str'
// Returns 1 if only the uninitialized head is available
// 
int mops_dump_all(struct mops* list, char *str)
{
	struct mops *head = list;
	struct mops *cur = list;
	
	char output[100];
	int anzmops=0, active=0, config=0, raw=0, ival=0;

	do {
		if (cur->state == MOPS_STATE_ACTIVE) {
			active++;
		} else if (cur->state == MOPS_STATE_CONFIG) { 
			config++;
		} else if (cur->interval_used==2) {
			ival++;
		}
		if (cur->use_ETHER == 0) raw++;

		anzmops++;		
		cur = cur->next;
	}  while (head != cur);
   
	snprintf(output, 99,  "%i Mopse(s)  (interval: %i, active: %i, config: %i, raw: %i)",
		anzmops, ival, active, config, raw);
   
	strncpy(str, output, 99);
	
	if ((!active) && (!config)) return 1;
	
	return 0;
}





// Search for key = name and return pointer to that mops
// Return NULL if not found
struct mops * mops_search_name (struct mops* list, char *key)
{
	struct mops *head = list;
	struct mops *cur = list;
	do   {
		if ( (strncasecmp(key, 
				  cur->packet_name, 
				  MAX_MOPS_PACKET_NAME_LEN) == 0))  {
			return cur; // FOUND!    
		}
		cur = cur->next;
	}
	while (head != cur);
	return NULL; // NOT FOUND!
}



// Search for key = id and return pointer to that mops
// Return NULL if not found
struct mops * mops_search_id (struct mops* list, u_int32_t key)
{
   struct mops *head = list;
   struct mops *cur = list;
   do {
	   if ( cur->id == key ) {
		   return cur; // FOUND!    
	   }
	   cur = cur->next;
   }
	while (head != cur);
	return NULL; // NOT FOUND!
}

   


// Deletes all elements except the specified element which us usually 
// the head element. Also ACTIVE elements will be removed and the 
// corresponding threads will be stopped.
// 
// Thus the list can grow again later via mops_alloc_packet
// 
void mops_delete_all(struct mops* list)
{
   struct mops *head = list;
   struct mops *cur = list->next; 
   struct mops *tmp;

   // Delete all but head element:
   while (head != cur)
     {
	     tmp = cur->next;
	     mops_ext_del_pdesc (cur); // delete p_desc (if available)
	     mops_destroy_thread(cur);
	     
	     // remove automops data if available
	     if (cur->amp != NULL) {
		     free(cur->amp);
		     cur->amp=NULL;
	     }
	     if (cur->amp_pdu != NULL) {
		     free (cur->amp_pdu);
		     cur->amp_pdu=NULL;
	     }
	     cur->amp_pdu_s=0;
	     
	     if (cur!=NULL) {
		     free(cur);
		     cur=NULL;
	     }
	     cur = tmp;
     }
	
   head->next = head;
   head->prev = head;
   
   head->state = MOPS_STATE_NULL;
}



// Same as mops_delete_all but also destroys the head element:
void mops_cleanup(struct mops* list)
{
	mops_delete_all(list);
	mops_ext_del_pdesc (list); // delete p_desc (if available)
	mops_destroy_thread(list);
	if (list!=NULL) {
		free(list);
		list=NULL;
	}
}




// Set default MOPS and protocol header parameters
// Currently most parameters are taken from the legacy tx-structure
// 
// NOTE: Does NOT and should NOT change the packet_name !!!
//       Because user might be confused if it is changed to something
//       unexpected such as 'PKT0341'.
// 
// TODO: find out MAC of default GW
int mops_set_defaults (struct mops *mp)
{
	// Initialize frame arrays with zero bytes
	memset(mp->frame, 0x00, MAX_MOPS_FRAME_SIZE);
	memset(mp->msg, 0x00, MAX_MOPS_MSG_SIZE);
	
	// Basics -- MOPS Management Parameters
	pthread_mutex_init (& mp->mops_mutex, NULL);
//	mp->mops_thread = 0;       // TODO
//	mp->interval_thread = 0;   // TODO
	mp->verbose = 1; // normal verbosity
	mp->use_ETHER = 0;
	mp->use_SNAP = 0;
	mp->use_dot1Q = 0;
	mp->use_MPLS = 0;
	mp->use_IP = 0;
	mp->use_UDP = 0;
	mp->use_TCP = 0;
	mp->frame_s = 0;
	mp->msg_s = 0;
	mp->description[0]='\0';
	mp->auto_delivery_off = 0; 
	mp->mz_system = 0;
	strncpy (mp->device, tx.device, 16);
	mp->count = 0;
	mp->cntx = 0;
	
	mp->ndelay.tv_sec = 0;
	mp->ndelay.tv_nsec = 100000000L; // 100 ms default delay

	mp->interval_used = 0;
	mp->interval.tv_sec = 0;
	mp->interval.tv_nsec = 0;
	
	mp->delay_sigma.tv_sec = 0;
	mp->delay_sigma.tv_nsec = 0;
	
	mp->MSG_use_RAW_FILE=0;
	mp->MSG_use_HEX_FILE=0;
	mp->MSG_use_ASC_FILE=0;
	mp->fp=NULL;
	mp->chunk_s = MAX_MOPS_MSG_CHUNK_SIZE;
	
	// TODO: check if amp and amp_header is free()'d in any case!!!
	mp->amp = NULL;
	mp->amp_pdu = NULL;
	mp->amp_pdu_s = 0;
	
	// Ethernet defaults:
	memcpy((void *) &mp->eth_dst, (void *) &tx.eth_dst, 6);
	memcpy((void *) &mp->eth_src, (void *) &tx.eth_src, 6);
	mp->eth_type = 0x800;
	mp->eth_src_israndom = 0;

	mp->dot1Q_isrange = 0;
	mp->mpls_isrange  = 0;
	
	// IP defaults:
	// abuse our hton: here we actually convert from net to host order:
	mops_hton4 ((u_int32_t*) &tx.ip_dst, (u_int8_t*) &mp->ip_dst);
	mops_hton4 ((u_int32_t*) &tx.ip_src, (u_int8_t*) &mp->ip_src); 
	// Note that the IP address of the "default interface" is assigned to that mops.
	// If the mops is bind to another interface then use the associated interface.
	// Implement this in cli_packet and function cmd_packet_bind
   	// 
	mp->ip_version = 4;
	mp->ip_IHL = 0;
	mp->ip_len = 20;
	mp->ip_tos = 0;
	mp->ip_flags_RS=0;             // 0|1 ... Reserved flag "must be zero"
	mp->ip_flags_DF=0;             // 0|1 ... Don't Fragment 
	mp->ip_flags_MF=0;             // 0|1 ... More Fragments
	mp->ip_frag_offset=0;
	mp->ip_fragsize=0;             // fragmentation OFF
	mp->ip_frag_overlap=0;         // no overlapping fragments
	mp->ip_ttl = 255;
	mp->ip_proto = 17;             // UDP
	mp->ip_src_israndom = 0;
	mp->ip_src_isrange  = 0;
	mp->ip_dst_isrange  = 0;
	mp->ip_option_used = 0;
	mp->ip_IHL_false = 0;
	mp->ip_len_false = 0;
	mp->ip_sum_false = 0;
	mp->ip_option_used = 0;
	mp->ip_option_s = 0;
	// L4 defaults (port numbers)
	mp->sp=0; 
	mp->sp_start=0; 
	mp->sp_stop=0;
	mp->sp_isrand=0;    
	mp->sp_isrange=0;
	
	mp->dp=0; 
	mp->dp_start=0; 
	mp->dp_stop=0;
	mp->dp_isrand=0;    
	mp->dp_isrange=0;
	
	// UDP defaults
	// 
	mp->udp_len_false = 0;
	mp->udp_sum_false = 0;
	mp->udp_sum = 0xffff;    // this default means "transmitter didn't compute checksum"
	
	// TCP defaults
   	// 
	mp->tcp_seq = 0xcafebabe;
	mp->tcp_seq_delta = 0; // no range
	mp->tcp_seq_start = 0;
	mp->tcp_seq_stop  = 0xffffffff;
	mp->tcp_ack = 0;
	mp->tcp_ack_delta = 0; // no range
	mp->tcp_ack_start = 0;
	mp->tcp_ack_stop  = 0xffffffff;
	mp->tcp_win = 100;
	mp->tcp_sum_false    = 0;
	mp->tcp_offset_false = 0;
	mp->tcp_offset = 0;
	mp->tcp_sum = 0xffff;    // this default means "transmitter didn't compute checksum"
	mp->tcp_option_used = 0;
	mp->tcp_option_s =0;
	mp->tcp_ctrl_CWR =0;
	mp->tcp_ctrl_ECE =0;        
	mp->tcp_ctrl_URG =0;            
	mp->tcp_ctrl_ACK =0;
	mp->tcp_ctrl_PSH =0;
	mp->tcp_ctrl_RST =0;            
	mp->tcp_ctrl_SYN =1; // assume that we begin with a TCP SYN
	mp->tcp_ctrl_FIN =0;
	mp->tcp_urg =0;
	mp->tcp_ack =0;
	mp->tcp_res =0;
	return 0;
}







int mops_print_frame (struct mops *mp, char *str)
{
   int i=0, fs;
   char octet[8], lnr[8], hex[MAX_MOPS_FRAME_SIZE*3];
   
   hex[0]=0x00;
   
   if (! (fs = mp->frame_s) ) return -1; // frame length zero (no frame?)
   
   if (fs>1)
     {
	sprintf(lnr,"%4i  ",i+1);
	strcat(hex, lnr);

	for (i=0; i<fs; i++)
	  { 
	     if ((i>0) && (!(i%8)))
	       {
		  strcat(hex, " "); // insert space after each 8 bytes
		  hex[strlen(hex)-2]=' ';
	       }
	     
	     if ((i>0) && (!(i%MAX_CLI_LINE_BYTES))) 
	       {
		  sprintf(lnr,"\n%4i  ",i+1);
		  strcat(hex, lnr);
	       }
	     
	     sprintf(octet, "%02x:", mp->frame[i]);
	     strcat(hex, octet);
	  }
     }

   hex[strlen(hex)-1]=' ';
   strcpy(str, hex);
   
   return 0;
}
   

   

   
   
   
   
// Find and returns a new unique packet id
// If none can be found, returns -1.
// 
int mops_get_new_pkt_id (struct mops *list)
{
	struct mops *head = list;
	struct mops *cur = list;
	int i, min=0xffffffff, max=0;
	
	do {
		if (cur->id < min) min = cur->id; // determine current min id
		if (cur->id > max) max = cur->id; // determine current max id
		cur = cur->next;
	}
	while (head != cur);
	
	if (min>0) 
		i= min-1;
	else
		i = max+1;
   
	// just for paranoia: check again if unique!
	do {
		if (cur->id == i) {
			return -1;  // 
		}
		cur = cur->next;
	}
	while (head != cur);
	
	return i;
}


// Simply sets specified  'layer switches' in mops struct 
// (use_ETHER, use_IP, ...) to zero.
// 
// RETURN VALUE: tells which layers had been configured before clearing.
// 
// The presence of the layers is indicated via binary coding:
// 
// MOPS_ALL       127    // clear all
// MOPS_ETH         1
// MOPS_SNAP        2    // either LLC, LLC+SNAP
// MOPS_dot1Q       4
// MOPS_MPLS        8
// MOPS_IP         16
// MOPS_UDP        32
// MOPS_TCP        64
//
int mops_clear_layers (struct mops *mp, int l)
{
	int ret=0;
   
	if (l & MOPS_ETH) {
		if (mp->use_ETHER) ret+=1;
		mp->use_ETHER = 0;
	}
	
	if (l & MOPS_SNAP) {
		if (mp->use_SNAP)  ret+=2;
		mp->use_SNAP  = 0;
	}
	
	if (l & MOPS_dot1Q) {
		if (mp->use_dot1Q) ret+=4;
		mp->use_dot1Q = 0;
	}
	
	if (l & MOPS_MPLS) {
		if (mp->use_MPLS)  ret+=8;
		mp->use_MPLS  = 0;
	}
	
	if (l & MOPS_IP) {
		if (mp->use_IP)    ret+=16;
		mp->use_IP    = 0;
	}
	
	if (l & MOPS_UDP) {
		if (mp->use_UDP)   ret+=32;
		mp->use_UDP   = 0;
	}
	
	if (l & MOPS_TCP) {
		if (mp->use_TCP)   ret+=64;
		mp->use_TCP   = 0;
	}

   return ret;
}


// Get global device index for a given device name.
// 
// RETURN VALUE:  
//   Either the desired device index or -1 if not found.
// 
// EXAMPLE:
//   i = mops_get_device_index("eth0")
//   
int mops_get_device_index(char *devname)
{
	int i;
	
	for (i=0; i<device_list_entries; i++) {
		if (strncmp(device_list[i].dev, devname, 16)==0) { 
			return i;
		}
	}
	
	return -1;
}



// Assign device-specific values (source IP and MAC addresses),
// drawn from global device table, to the specified MOPS entry 
// with index i.
// 
int mops_use_device(struct mops * mp, int i)
{
   // Assign source MAC address
   // Assign source IP address
   // TODO? Assign default gateway

   memcpy((void *) &mp->eth_src, (void *) &device_list[i].mac_mops[0], 6);
   memcpy((void *) &mp->ip_src, (void *) &device_list[i].ip_mops[0], 4);

   return 0;
}


// Creates two strings as used by the 'show packet' command, 
// 1) one identifying all used layers of a packet, 
// 2) the other which higher layer protocol is used
// 
// caller must define:
//   char layers[16], proto[16];
//   
// RETURNS 0 upon success, 1 upon failure.
// 
int  mops_get_proto_info(struct mops *mp, char *layers, char *proto)
{
	char ds[16], pr[16];

	if (mp==NULL) return 1;
	
	ds[0]='\0';
	pr[0]='\0';
	
	if (mp->use_ETHER) strcat(ds,"E"); else strcat(ds,"-");
	if (mp->use_SNAP) strcat(ds,"S"); else strcat(ds,"-");
	if (mp->use_dot1Q) strcat(ds,"Q"); else strcat(ds,"-");
	if (mp->use_MPLS) strcat(ds,"M"); else strcat(ds,"-");
	if (mp->use_IP) {
		if (mp->auto_delivery_off) 
			strcat(ds,"i"); 
		else
			strcat(ds,"I");
	} else strcat(ds,"-");
	
	if (mp->use_UDP) 
		strcat(ds,"U"); 
	else if 
		(mp->use_TCP) strcat(ds,"T"); 
	else strcat(ds,"-");
	
	switch (mp->p_desc_type) {
	 case MOPS_ARP:
		strncpy(pr, "ARP", 8);
		break;
	 case MOPS_BPDU:
		strncpy(pr, "BPDU", 8);
		break;
	 case MOPS_CDP:
		strncpy(pr, "CDP", 8);
		break;
	 case MOPS_DNS:
		strncpy(pr, "DNS", 8);
		break;
	 case MOPS_ICMP:
		strncpy(pr, "ICMP", 8);
		break;
	 case MOPS_IGMP:
		strncpy(pr, "IGMP", 8);
		break;
	 case MOPS_LLDP:
		strncpy(pr, "LLDP", 8);
		break;
	 case MOPS_RTP:
		strncpy(pr, "RTP", 8);
		break;
	 case MOPS_SYSLOG:
		strncpy(pr, "SYSLOG", 8);
		break;
	 default:
		break;
	}

	strncpy(layers, ds, 16);
	strncpy(proto, pr, 16);
	return 0;
}



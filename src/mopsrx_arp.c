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

// Starts an ARP RX thread for *every* device in the device_list.
// (Except for the loopback interface)
// 
// RETURN VALUE: 0 upon success,
//               1 upon error.
// 
int mops_rx_arp ()
{
	int i;
	
	for (i=0; i<device_list_entries; i++) {
		if (mz_strcmp(device_list[i].dev, "lo", 2)==0) continue; // omit loopback!
		if (pthread_create( &(device_list[i].arprx_thread), 
				    NULL, 
				    rx_arp, 
				    &device_list[i])) { // give thread a pointer to that device_list entry
			printf("xxxxxxxxxx\n");
			return 1; // Error creating thread
		} else {
			if (verbose) {
				fprintf(stderr, " Started ARP monitor on device %s.\n", 
					device_list[i].dev);
			}
		}
	}
	return 0;
}


// Thread function to receive ARP responses for a given device. 
// Runs forever - until Mausezahn stops (see clean_up())
// 
// Argument: pointer to device_struct!
// 
// 
// 
void *rx_arp (void *arg) 
{
	char errbuf[PCAP_ERRBUF_SIZE];
   	pcap_t  *p_arp;
	struct bpf_program filter;
	char filter_str[] = "arp";  // We want to analyze both requests and responses!
	struct device_struct *dev =  (struct device_struct*) arg;
	
	// FYI, possible filter string is also:
	// "eth.dst==00:05:4e:51:01:b5 and arp and arp.opcode==2";
	
	p_arp = pcap_open_live (dev->dev, 
			    100,         // max num of bytes to read
			    1,           // 1 if promiscuous mode
			    PCAP_READ_TIMEOUT_MSEC,  // read timeout 'until error' (-1 = indefinitely)
			    errbuf);

	if (p_arp == NULL) {
		fprintf(stderr," rx_arp: [ERROR] %s\n",errbuf);
		return NULL; // TODO: Should return pointer to error message or something similar
	}
   
	dev->p_arp = p_arp; // also assign pointer to a global which is needed for clean_up
   
	if ( pcap_compile(p_arp, 
			  &filter,        // the compiled version of the filter
			  filter_str,     // text version of filter
			  0,              // 1 = optimize
			  0)              // netmask
	     == -1) {
		fprintf(stderr," rx_arp: [ERROR] Error calling pcap_compile\n"); 
		return NULL;
	}

	if ( pcap_setfilter(p_arp, &filter) == -1)	{
		fprintf(stderr," rx_arp: [ERROR] Error setting pcap filter\n");
		pcap_perror(p_arp, " rx_arp: ");
		return NULL;
	}
   
	if (pcap_setdirection(p_arp, PCAP_D_IN) == -1) {
		pcap_perror(p_arp, " rx_arp: ");
		return NULL;
	}
   
	again:
	pcap_loop (p_arp, 
		   1,               // number of packets to wait
		   got_arp_packet,  // name of callback function
		   (u_char*) dev);           // optional additional arguments for callback function
	goto again;
	
	pthread_exit(NULL); // destroy thread
   return NULL;
}


void got_arp_packet (u_char                   *args, 
		     const struct pcap_pkthdr *header, // statistics about the packet (see 'struct pcap_pkthdr')
		     const u_char             *packet)             // the bytestring sniffed  
{
	const struct struct_ethernet *ethernet;
	const struct struct_arp      *arp;
	int                          size_ethernet = sizeof(struct struct_ethernet);
	struct device_struct         *dev          = (struct device_struct*) args;

	u_int8_t 
		da[6],   // eth da
		sa[6],   // eth sa
		smac[6],  // source hw address
		sip[4],  // source protocol address
		tmac[6],  // target hw address
		tip[4];  // target protocol address
	u_int16_t op;    // operation
	u_int32_t sec, nsec;
	u_int8_t *x;
	
	// These are the most important lines here:
	ethernet = (struct struct_ethernet*)(packet);
	arp      = (struct struct_arp*)(packet+size_ethernet);
	sec      = (u_int32_t) header->ts.tv_sec;
	nsec     = (u_int32_t) ((header->ts.tv_usec) * 1000);
	
	op = arp->arp_op; // note that we don't have network byte order anymore!
	                  // tmact is: 
                          //          100 instead of 00:01 (request)
	                  //          200 instead of 00:02 (response)

	memcpy((void*) da, (void*) ethernet->eth_da, 6);
	memcpy((void*) sa, (void*) ethernet->eth_sa, 6);
	memcpy((void*) smac, (void*) arp->arp_smac, 6);
	memcpy((void*) sip, (void*) arp->arp_sip, 4);
	memcpy((void*) tmac, (void*) arp->arp_tmac, 6);
	memcpy((void*) tip, (void*) arp->arp_tip, 4);
		
	// Only handle the packet if it is really an ARP response!
	////AND if it is not sent by THIS host! (not possible, we only scan inbound!)
	x = (u_int8_t*) & op;
	if  (*(x+1) == 0x02) { 
		// ARP RESPONSE: Update ARP table
		arptable_add(dev, sa, da, smac, sip, sec, nsec);
	} else if  (*(x+1) == 0x01) {
		// ARP REQUEST: Detect poisoning attacks
		arpwatch(dev, sa, da, smac, sip, tmac, tip, sec, nsec);
	}
	

	
	
	// ARP binding consists of: sip (IP) - smac (MAC)
	// 
	// User alert, 2 possibilities:
	// 
	//   1. Learned new binding: does smac belong to sip? 
	// 
	//   2. Alert: Mismatch of stored versus announced sip-to-smac binding
	// 
	// In both cases user action: [Learn] [Ignore] [Attack] [Amok Attack]
	// Countermeasures: Mausezahn him!
	//
	// ALSO correct ARP tables of other hosts, especially on the default gateway
	// that is, send arp replies with true binding
   	// 
	// Finally: Create logging message

}



// Add new entry in device-specific ARP table
// but first check if already existing or change.
// 
// RETURN VALUE: 0 upon success
//               1 upon error
// 
int arptable_add(struct device_struct *dev, 
		 u_int8_t *sa, 
		 u_int8_t *da, 
		 u_int8_t *smac, 
		 u_int8_t *sip, 
		 u_int32_t sec, 
		 u_int32_t nsec)
{
	struct arp_table_struct *prev=NULL, *cur = dev->arp_table; 
	int i=0, alert=0;

	// If SA and SMAC are different this might be a MITM !!!
	if (compare_mac(smac, sa)) alert=1;
	
	// Check if IP (sip) is already existing in arp table:
	while (cur!=NULL) {
		if (compare_ip(sip, cur->sip)==0) { // IP found!
			timestamp_hms(cur->when);
			if (da[0]==0xff) cur->bc_resp++; 
			else  cur->uni_resp++;
			if (compare_mac(smac, cur->smac)==0) { 
				// entry identical !
				cur->sec=sec;
				cur->nsec=nsec;
				return 0;
			} else {
				// entry with other MAC address found !
				if (cur->locked==0) {
					cur->changed++;
					memcpy((void*) cur->smac_prev, (void*) cur->smac, 6);
					memcpy((void*) cur->smac, (void*) smac, 6);
					cur->sec_prev=cur->sec;
					cur->nsec_prev=cur->nsec;
					cur->sec=sec; 
					cur->nsec=nsec;
					if (alert) cur->flags|=0x02;
				}
				return 0;
			}
		}
		prev = cur;
		cur = cur->next; 
		i++;
	}
	
	// If we get here, then there was no entry for that IP yet!
	// Create new arp_table entry:
	cur = (struct arp_table_struct *) malloc(sizeof(struct arp_table_struct));
	if (cur==NULL) return 1;

	// Append element:
	if (dev->arp_table==NULL) dev->arp_table = cur;
	else prev->next = cur;
	
	memcpy((void*) cur->sa, (void*) sa, 6);
	memcpy((void*) cur->smac, (void*) smac, 6);
	cur->smac_prev[0]=0x00;
	cur->smac_prev[1]=0x00;
	cur->smac_prev[2]=0x00;
	cur->smac_prev[3]=0x00;
	cur->smac_prev[4]=0x00;
	cur->smac_prev[5]=0x00;
	memcpy((void*) cur->sip, (void*) sip, 4);
	if (da[0]==0xff) { 
		cur->bc_resp=1;
		cur->uni_resp=0;
	} else {
		cur->bc_resp=0;
		cur->uni_resp=1;	
	}
	cur->changed=1;
	cur->locked=0;
	cur->dynamic=1;
	cur->flags=0;
	cur->sec=sec;
	cur->nsec=nsec; 
	cur->sec_prev=0;
	cur->nsec_prev=0;
	cur->index=i+1; // I assume users prefer to count from 1.
	timestamp_hms(cur->when);
	if (alert) cur->flags|=0x02;
	cur->next=NULL;
	return 0;
}
   


// Validate ARP requests
int arpwatch(struct device_struct *dev, 
	     u_int8_t *sa, 
	     u_int8_t *da, 
	     u_int8_t *smac, 
	     u_int8_t *sip, 
	     u_int8_t *tmac,
	     u_int8_t *tip,
	     u_int32_t sec,
	     u_int32_t nsec)
{
	// Unicast requests are considered as anomaly
	
	if ((da[0]&0x01)==0) { // broadcast bit NOT set?
		fprintf(stderr, "NOTE: Non-broadcast ARP request from %02x:%02x:%02x:%02x:%02x:%02x\n",
			sa[0], sa[1], sa[2], sa[3], sa[4], sa[5]);
	}
	
	return 0;
}


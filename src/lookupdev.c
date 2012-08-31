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

#include <netpacket/packet.h>
#include <netinet/ether.h>


// PURPOSE: Find usable network devices
// 
// NOTE: 
//   
//  1. Ignores devices without IP address 
//  2. Ignores loopback (etc)
// 
// RETURN VALUES:
// 
//  0 if usable device found (device_list[] and tx.device set)
//  1 if no usable device found
//  
int lookupdev()
{
   // char *tx.device is global, see as.h

   char 
     ipaddress[IPADDRSIZE+1],
     errbuf[PCAP_ERRBUF_SIZE];

   pcap_if_t 
     *alldevs,
     *index = NULL;

   pcap_addr_t *pcap_addr;

   int i=0;
   

   // FIRST get a list of all available devices
   //  
   if (pcap_findalldevs(&alldevs, errbuf) == -1)
     {
	fprintf(stderr," mz: %s\n",errbuf);
	return 1;
     }
   
   index = (pcap_if_t *) alldevs;
   
   while (index)
     {
	if (index->addresses)
	  {
	     pcap_addr = index->addresses;
	     while(pcap_addr)
	       {
		  if (pcap_addr->addr && (pcap_addr->addr->sa_family==AF_INET))
		    {
		       if (inet_ntop(pcap_addr->addr->sa_family,
				     (void *)&pcap_addr->addr->sa_data[2],
				     ipaddress,
				     IPADDRSIZE))
			 {
			    if (verbose)
			      {
				 fprintf(stderr," mz: device %s got assigned %s ",
					 index->name, ipaddress);
			      }
			    
			    if (strncmp(ipaddress, "127", 3)==0)
			      {
				 if (verbose) fprintf(stderr, "(loopback)\n");
				 strncpy(device_list[i].dev, index->name, 9);
				 strncpy(device_list[i].ip_str, ipaddress, IPADDRSIZE);
				 device_list[i].phy=0;
				 get_if_addr(index->name, device_list[i].ip, device_list[i].mac);
				 get_if_addr(index->name, device_list[i].ip_mops, device_list[i].mac_mops);
				 i++;
			      }
			    else if (strncmp(ipaddress, "169.254", 7)==0)
			      {
				 if (verbose) fprintf(stderr, "but IGNORED (cause: host-scope address)\n");
			      }
			    else // FOUND VALID INTERFACE
			      {
				 if (verbose) fprintf(stderr, "and is a possible candidate.\n");
				 strncpy(device_list[i].dev, index->name, 9);
				 strncpy(device_list[i].ip_str, ipaddress, IPADDRSIZE);
                                 device_list[i].phy=1;
				 get_if_addr(index->name, device_list[i].ip, device_list[i].mac);
				 get_if_addr(index->name, device_list[i].ip_mops, device_list[i].mac_mops);
				 i++;
			      }
			    
				 // Select only interfaces with IP addresses
				 // but avoid those that start with 127 or 169.254
				 // Put the remaining on a list. If this list has more than one entry
				 // ask the user which interface to listen to.
			 }
		       else
			 {
			    return 1;
			 }
		    }
		  pcap_addr = pcap_addr->next;
	       } // closes while(pcap_addr)
	  }
	index = index->next;
     } // closes while (index)
   
   device_list_entries = i;

   /*
   if (verbose)
     {
	for (i=0; i<device_list_entries; i++)
	  {
	     fprintf(stderr, " mz: Found device %s with IP %s\n", device_list[i].dev, device_list[i].ip_str);
	  }
     }
   */

   // No device found:
   if (device_list_entries==0) 	return 1;
   
   // Else device found:
   // initialize tx.device with first entry of the device_list
   strncpy (tx.device, device_list[0].dev, 16);
   
   return 0;
}








// Determines ip and mac address of specified interface 'ifname'
// Caller must provide an unsigned char ip[4], mac[6]
//
int get_if_addr (char *ifname, u_int8_t *ip, u_int8_t *mac)
{
   int fd, i;
   struct ifreq ifr;
   struct sockaddr_in saddr;
   u_int8_t *x;

   ifr.ifr_addr.sa_family = AF_INET;
   strncpy(ifr.ifr_name, ifname , IFNAMSIZ-1);

   // we must open a socket to get the addresses
   fd = socket(AF_INET, SOCK_DGRAM, 0);
   if (fd == -1) return 1;

   // get mac
   ioctl(fd, SIOCGIFHWADDR, &ifr);
   for (i=0; i<6; i++)  mac[i]= (u_int8_t) ifr.ifr_hwaddr.sa_data[i];

   // get IP
   ioctl(fd, SIOCGIFADDR, &ifr);
   saddr=*((struct sockaddr_in *)(&(ifr.ifr_addr)));
   x = (u_int8_t*)&saddr.sin_addr;
   ip[0]=*x; ip[1]=*(x+1); ip[2]=*(x+2); ip[3]=*(x+3);

   close(fd);


 return 0;
}




// For a given device name, find out the following parameters:
// 
//  - MTU
//  - Network
//  - Mask
//  - Default GW (IP)
//  - Default GW (MAC)
//  - Open packet socket (if not already done)
//  
int get_dev_params (char *name) 
{
	FILE *fd;
	
	char f[10][16], line[256];
	int  in=0, nw=1, gw=2, mk=7; // default columns in /proc/net/route for interface, network, gateway, and mask.
	unsigned int tmp[4], net[4]={0,0,0,0}, dgw[4], mask[4]={0,0,0,0};
	int i=0, flag=0, nw_found=0, gw_found=0, devind=0, dev_found=0;

	struct ifreq si;
	struct sockaddr_ll  psock;
	int ps, index, mtu;
	struct arp_table_struct *cur;
	// 1. Check if device is already present in our device_list

	for (i=0; i<device_list_entries; i++) {
		if (strncmp(device_list[i].dev, name, 16)==0) { 
			devind=i;
			dev_found=1;
			break;
		}
	}
	if (dev_found==0) return 1; // ERROR: device name not found !!!!


	
	// 2. find network, gateway, and mask
	
	fd = fopen("/proc/net/route", "r");	
	while (fgets(line, 255, fd)!=NULL) {
		sscanf(line, "  %s %s %s %s %s %s %s %s %s %s", f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8], f[9]);
		if (!flag) { // find columns (we do NOT assume that the order of columns is the same everywhere)
			for (i=0; i<10; i++) {
				if (strncasecmp(f[i],"iface", 16)==0) in=i;
				if (strncasecmp(f[i],"destination", 16)==0) nw=i;
				if (strncasecmp(f[i],"gateway", 16)==0) gw=i;
				if (strncasecmp(f[i],"mask", 16)==0) mk=i;
			}
			flag=1;
		}
		
		if (strncmp(f[in], name, 16)==0) { // interface found
			// Determine network
			if ((strncmp(f[nw],"00000000",8)!=0) && (strncmp(f[gw],"00000000",8)==0)) {
				// ignore 169.254 and 127 networks
				sscanf(f[nw],"%02x%02x%02x%02x",&tmp[3], &tmp[2], &tmp[1], &tmp[0]);
				if ((tmp[0]!=127) && (tmp[0]!=169)) {
					nw_found=1;
					net[0]=tmp[0];
					net[1]=tmp[1];
					net[2]=tmp[2];
					net[3]=tmp[3];
					// also get mask for that network
					sscanf(f[mk],"%02x%02x%02x%02x",&tmp[3], &tmp[2], &tmp[1], &tmp[0]);
					mask[0]=tmp[0];
					mask[1]=tmp[1];
					mask[2]=tmp[2];
					mask[3]=tmp[3];
				}
			}
			// Determine gateway
			if ((strncmp(f[nw],"00000000",8)==0) && (strncmp(f[gw],"00000000",8)!=0)) {
				sscanf(f[gw],"%02x%02x%02x%02x",&dgw[3], &dgw[2], &dgw[1], &dgw[0]);
				gw_found=1;
			}
		}
	}
	
	fclose(fd);

	
	// 3. Get device index, determine MTU, 
	// and bind socket to device for later TX and RX

	// if socket is already open, then close and re-open it!
	if (device_list[devind].ps>=0) { 
		close(device_list[devind].ps);
		device_list[devind].ps=-1;
	}
	
	if (device_list[devind].ps<0) {
		ps = socket (PF_PACKET, SOCK_RAW, htons(ETH_P_IP)); //ETH_P_ALL, ETH_P_802_3);
		if (ps<0) {
			fprintf(stderr, " Warning: [lookupdev.c get_dev_params()]  Cannot open socket!\n");
			return 1;
		}
		
		// Get device index
		strncpy(si.ifr_name, name, IFNAMSIZ);
		if (ioctl(ps, SIOCGIFINDEX, &si)==-1) {
			perror("ioctl");
			close(ps);
			return 1;
		}
		index=si.ifr_ifindex;

		// Get MTU
		if (ioctl(ps, SIOCGIFMTU, &si)==-1) {
			perror("ioctl");
			close(ps);
			return 1;
		}
		mtu = si.ifr_mtu;

		// ***** bind socket for later TX and RX ****
		psock.sll_family = AF_PACKET;     // evident
	//	psock.sll_protocol = 0;           // unsigned short - Physical layer protocol
		psock.sll_ifindex  = index;       // int - Interface number      
		psock.sll_hatype   = 0;           // unsigned short - Header type //ARPHRD_ETHER
		psock.sll_pkttype  = 0;           // unsigned char - Packet type 
		psock.sll_halen    = 6;           // unsigned char - Length of address
		bind(ps, (const struct sockaddr *) &psock, sizeof(psock)); // <= !!!
		device_list[devind].ps = ps; // Note that close(ps) must be done upon termination
	}
	
	// Get MAC of default gateway
	service_arp(name, device_list[devind].ip_gw, device_list[devind].mac_gw);

	usleep(200); // this is a VERY short delay but it usually works in today's LANs
	cur=device_list[devind].arp_table;
	while(cur!=NULL) {
		if ((cur->sip[0]==dgw[0]) &&
		    (cur->sip[1]==dgw[1]) &&
		    (cur->sip[2]==dgw[2]) &&
		    (cur->sip[3]==dgw[3])) { // entry found!
			for (i=0; i<6; i++) {
				device_list[devind].mac_gw[i] = cur->smac[i];
			}
		}
		cur=cur->next;
	}
	
	// FINALLY: Copy findings in device_list
	
	if (device_list[devind].phy) {
		for (i=0; i<4; i++) {
			device_list[devind].net[i]   = net[i];
			device_list[devind].mask[i]  = mask[i];
			device_list[devind].ip_gw[i] = dgw[i];
		}
	}
	else {
		for (i=0; i<4; i++) {
			device_list[devind].net[i]   = 0;
			device_list[devind].mask[i]  = 0;
			device_list[devind].ip_gw[i] = 0;
		}
	}
	
	device_list[devind].index = index;
	device_list[devind].mtu = mtu;

	return 0;
}


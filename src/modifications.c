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




// ***************************************************************************
// 
//    This sections contains functions to manipulate headers of 
//    Eth, MPLS, 802.1Q, IP, UDP, and TCP:
//    
//      int update_Eth_SA       (libnet_t *l, libnet_ptag_t t)
//      int update_IP_SA        (libnet_t *l, libnet_ptag_t t)
//      int update_IP_DA        (libnet_t *l, libnet_ptag_t t)
//      int update_DPORT        (libnet_t *l, libnet_ptag_t t)
//      int update_SPORT        (libnet_t *l, libnet_ptag_t t)
//      int update_TCP_SQNR     (libnet_t *l, libnet_ptag_t t)
//    
//    and finally:
//    
//      int print_frame_details()
//
// ***************************************************************************

#include "mz.h"
#include "mops.h"

///////////////////////////////////////////////////////////////////////////
// Applies another random Ethernet source address to a given Ethernet-PTAG.
// (The calling function should check 'tx.eth_src_rand' whether the SA 
// should be randomized.)
// 
int update_Eth_SA(libnet_t *l, libnet_ptag_t t)
{
   tx.eth_src[0] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256) & 0xFE; // keeps bcast-bit zero
   tx.eth_src[1] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
   tx.eth_src[2] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
   tx.eth_src[3] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
   tx.eth_src[4] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
   tx.eth_src[5] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
 
   t = libnet_build_ethernet (tx.eth_dst, 
			      tx.eth_src, 
			      tx.eth_type, 
			      NULL,              // the payload
			      0, 
			      l, 
			      t);

   if (t == -1)
     {
	fprintf(stderr, " mz/update_Eth_SA: Can't build Ethernet header: %s\n",
		libnet_geterror(l));
	exit(EXIT_FAILURE);
     }
   
   return 0;
}


// Update official timestamp, own timestamp and sequence number in the RTP header. 
// The actual RTP message is stored in tx.udp_payload.
int update_RTP(libnet_t *l, libnet_ptag_t t)
{
	u_int8_t *ptr;
	struct mz_timestamp ts;
	
	tx.rtp_sqnr++;
	tx.rtp_stmp+=160; // TODO: different values for different codecs
	
	// update SQNR
	ptr = (u_int8_t*) &tx.rtp_sqnr;
	tx.udp_payload[2] = *(ptr+1);
	tx.udp_payload[3] = *ptr;

	// update official timestamp
	ptr = (u_int8_t*) &tx.rtp_stmp;
	tx.udp_payload[4] = *(ptr+3);
	tx.udp_payload[5] = *(ptr+2);
	tx.udp_payload[6] = *(ptr+1);
	tx.udp_payload[7] = *ptr;

   
	// update own timestamp
	getcurtime(&ts); // Now add TX timestamp:
	mops_hton4 ((u_int32_t*) &ts.sec,  &tx.udp_payload[16]);
	mops_hton4 ((u_int32_t*) &ts.nsec, &tx.udp_payload[20]);
   
	t = libnet_build_udp(tx.sp, 
			     tx.dp, 
			     tx.udp_len, 
			     tx.udp_sum,
			     tx.udp_payload,
			     tx.udp_payload_s,
			     l, 
			     t);

	if (t == -1) {
		fprintf(stderr," mz/send_frame: RTP header update failed!\n");
		exit (1);
	}
	return 0;
}


///////////////////////////////////////////////////////////////////////////
// Applies another SOURCE IP address, 
//  - either a random one (tx.ip_src_rand==1)
//  - or from a specified range (tx.ip_src_isrange==1) 
// to a given IP-PTAG.
// 
// Note: tx.ip_src MUST be already initialized with tx.ip_src_start.
//       This is done by 'get_ip_range_src()' in tools.c.
// 
// 
// RETURNS '1' if tx.ip_src restarts
// 
int update_IP_SA (libnet_t *l, libnet_ptag_t t)
{
   u_int8_t *x, *y;  
   int i=0;
   
   if (tx.ip_src_rand)
     {
	tx.ip_src_h  = (u_int32_t) ( ((float) rand()/RAND_MAX)*0xE0000000); //this is 224.0.0.0
	i=1;
     }
   else if (tx.ip_src_isrange)
     {
	tx.ip_src_h++;
	if (tx.ip_src_h > tx.ip_src_stop) // reached the end of the range => restart!
	  {
	     tx.ip_src_h = tx.ip_src_start;
	     i=1;
	  }
     }
   
   // Now convert "tx.ip_src_h" into "tx.ip_src" which is in 'Network Byte Order':
   x = (unsigned char*) &tx.ip_src_h;
   y = (unsigned char*) &tx.ip_src;
   
   *y = *(x+3);
   y++;
   *y = *(x+2);
   y++;
   *y = *(x+1);
   y++;
   *y = *x;
   
   // TODO: Omit certain IP addresses:
   //       E.g. if (rand_ip == tx.ip_src) goto rand_again;  // never use true interface IP
   // TODO: Check other address exceptions ...

   t = libnet_build_ipv4 (tx.ip_len, 
			  tx.ip_tos, 
			  tx.ip_id, 
			  tx.ip_frag,
			  tx.ip_ttl, 
			  tx.ip_proto,
			  tx.ip_sum, 
			  tx.ip_src,             // possibly now random
			  tx.ip_dst,
			  (mode==IP) ? (tx.ip_payload_s) ? tx.ip_payload : NULL : NULL,  // if e.g. mode=UDP ignore payload argument
			  (mode==IP) ? tx.ip_payload_s : 0,
			  l, 
			  t);

   if (t == -1)
     {
	fprintf(stderr," mz/update_IP_SA: IP address manipulation failed!\n");
	exit (1);
     }

   return i;
}




/////////////////////////////////////////////////////////////////////////////////////////
// Applies another DESTINATION IP address from a specified range (tx.ip_dst_isrange==1) 
// to a given IP-PTAG.
// 
// Note: tx.ip_dst MUST be already initialized with tx.ip_dst_start.
//       tx.ip_dst_h 'mirrors' tx.ip_dst 
//       (i. e. tx.ip_dst_h is NOT in network byte order => easy to count)
//       This is done by 'get_ip_range_dst()' in tools.c.
// 
// RETURN VALUE: '1' if tx.ip_dst restarts
// 
int update_IP_DA(libnet_t *l, libnet_ptag_t t)
{
   u_int8_t *x, *y;  
   int i=0;


   if (tx.ip_dst_isrange)
     {
	tx.ip_dst_h++;
	if (tx.ip_dst_h > tx.ip_dst_stop) // we reached the end of the range => restart!
	  {
	     tx.ip_dst_h = tx.ip_dst_start;
	     i=1;
	  }
     }

   
   // Now convert "tx.ip_dst_h" into "tx.ip_dst" which is in 'Network Byte Order':

   x = (unsigned char*) &tx.ip_dst_h;
   y = (unsigned char*) &tx.ip_dst;
   
   *y = *(x+3);
   y++;
   *y = *(x+2);
   y++;
   *y = *(x+1);
   y++;
   *y = *x;

   
   // TODO: Omit certain IP addresses:
   //       E.g. if (rand_ip == tx.ip_src) goto rand_again;  // never use true interface IP
   // TODO: Check other address exceptions ...
   
   t = libnet_build_ipv4 (tx.ip_len, 
			  tx.ip_tos, 
			  tx.ip_id, 
			  tx.ip_frag,
			  tx.ip_ttl, 
			  tx.ip_proto,
			  tx.ip_sum, 
			  tx.ip_src, 
			  tx.ip_dst,
			  (mode==IP) ? (tx.ip_payload_s) ? tx.ip_payload : NULL : NULL,  // if e.g. mode=UDP ignore payload argument
			  (mode==IP) ? tx.ip_payload_s : 0,
			  l, 
			  t);

   if (t == -1)
     {
	fprintf(stderr," mz/update_IP_DA: IP address manipulation failed!\n");
	exit (1);
     }

   return i;
}




///////////////////////////////////////////////////////////////////////////////////////
//
// Applies another DESTINATION PORT from a specified range to a given UDP- or TCP-PTAG.
// 
// Note: tx.dp MUST be already initialized with tx.dp_start
//       This is done by 'get_port_range()' in tools.c.
//
// RETURN VALUE: '1' if tx.dp restarts
//      
int update_DPORT(libnet_t *l, libnet_ptag_t t)
{
  // u_int32_t DP;
   int i=0;
   
  // DP = (u_int32_t) tx.dp;
  // DP++;
   tx.dp++;

   
   // Exceeded range => restart:
   if ((tx.dp > tx.dp_stop) ||  // we exceeded the end of the range 
       (tx.dp == 65535) )       // or exceeded the 16-bit range
     {
	tx.dp = tx.dp_start;
	i=1;
     }
   
   
   if (mode==UDP)
     {
	t = libnet_build_udp(tx.sp, 
			     tx.dp, 
			     tx.udp_len, 
			     tx.udp_sum,
			     (tx.udp_payload_s) ? tx.udp_payload : NULL,
			     tx.udp_payload_s, 
			     l, 
			     t);

	if (t == -1)
	  {
	     fprintf(stderr," mz/send_frame: UDP header manipulation failed!\n");
	     exit (1);
	  }
     }
   else // TCP
     {
	t = libnet_build_tcp (tx.sp,
			      tx.dp,
			      tx.tcp_seq, 
			      tx.tcp_ack,
			      tx.tcp_control,
			      tx.tcp_win, 
			      tx.tcp_sum, 
			      tx.tcp_urg, 
			      tx.tcp_len,
			      (tx.tcp_payload_s) ? tx.tcp_payload : NULL,
			      tx.tcp_payload_s, 
			      l, 
			      t);
		  
	if (t == -1)
	  {
	     fprintf(stderr, " mz/update_DPORT: Can't build TCP header: %s\n", libnet_geterror(l));
	     exit (0);
	  }  
     }
   
   return i;
}

   
///////////////////////////////////////////////////////////////////////////////////
//
// Applies another SOURCE PORT from a specified range to a given UDP- or TCP-PTAG.
// 
// Note: tx.sp MUST be already initialized with tx.sp_start
//       This is done by 'get_port_range()' in tools.c.
//       
// RETURN VALUE: '1' if tx.sp restarts
//       
int update_SPORT(libnet_t *l, libnet_ptag_t t)
{
   
//   u_int32_t SP;
   int i=0;
   
//   SP = (u_int32_t) tx.sp;
//   SP++;
   tx.sp++;

   
   // Exceeded range => restart:
   if ((tx.sp > tx.sp_stop) ||  // we exceeded the end of the range 
       (tx.sp == 65535) )       // or exceeded the 16-bit range
     {
	tx.sp = tx.sp_start;
	i=1;
     }
     
   if (mode==UDP)
     {
	t = libnet_build_udp(tx.sp,
			     tx.dp, 
			     tx.udp_len, 
			     tx.udp_sum,
			     (tx.udp_payload_s) ? tx.udp_payload : NULL,
			     tx.udp_payload_s, 
			     l, 
			     t);

	if (t == -1)
	  {
	     fprintf(stderr," mz/send_frame: UDP header manipulation failed!\n");
	     exit (1);
	  }
     }
   else // TCP
     {
	t = libnet_build_tcp (tx.sp,
			      tx.dp, 
			      tx.tcp_seq, 
			      tx.tcp_ack,
			      tx.tcp_control,
			      tx.tcp_win, 
			      tx.tcp_sum, 
			      tx.tcp_urg, 
			      tx.tcp_len,
			      (tx.tcp_payload_s) ? tx.tcp_payload : NULL,
			      tx.tcp_payload_s, 
			      l, 
			      t);
		  
	if (t == -1)
	  {
	     fprintf(stderr, " mz/update_DPORT: Can't build TCP header: %s\n", libnet_geterror(l));
	     exit (0);
	  }  
     }
   
   return i;   
}

#define LIBNET_CKSUM_CARRY(x) \
    (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))

int update_USUM(libnet_t *l, libnet_ptag_t t)
{
     int sum = 0;
     unsigned int tmp;

     if (tx.udp_sum != 0)
	return 0;

     sum += libnet_in_cksum((u_int16_t *) &tx.ip6_src, 16);
     if (tx.ip_option_s && tx.ip6_segs)
       sum += libnet_in_cksum((u_int16_t *) &tx.ip_option[tx.ip_option_s - 16], 16); // Use last IP address
     else
       sum += libnet_in_cksum((u_int16_t *) &tx.ip6_dst, 16);

     tmp = htonl(tx.udp_len);
     sum += libnet_in_cksum((u_int16_t *) &tmp, 4);
     tmp = htonl(IPPROTO_UDP);
     sum += libnet_in_cksum((u_int16_t *) &tmp, 4);

     tmp = ((htons(tx.sp) << 16) + htons(tx.dp));
     sum += libnet_in_cksum((u_int16_t *) &tmp, 4);

     tmp = htons(tx.udp_len) << 16;
     sum += libnet_in_cksum((u_int16_t *) &tmp, 4);

     if (tx.udp_payload_s)
       sum += libnet_in_cksum((u_int16_t *) tx.udp_payload, tx.udp_payload_s);

     tx.udp_sum = ntohs(LIBNET_CKSUM_CARRY(sum));

     t = libnet_build_udp(tx.sp,
			  tx.dp,
			  tx.udp_len,
			  tx.udp_sum,
			  tx.udp_payload_s ? tx.udp_payload : NULL,
			  tx.udp_payload_s,
			  l,
			  t);
     return t;
}

int update_TSUM(libnet_t *l, libnet_ptag_t t)
{
     int sum = 0;
     unsigned int tmp;

     if (tx.tcp_sum != 0)
	return 0;

     sum += libnet_in_cksum((u_int16_t *) &tx.ip6_src, 16);
     if (tx.ip_option_s && tx.ip6_segs)
       sum += libnet_in_cksum((u_int16_t *) &tx.ip_option[tx.ip_option_s - 16], 16); // Use last IP address
     else
       sum += libnet_in_cksum((u_int16_t *) &tx.ip6_dst, 16);

     tmp = htonl(tx.tcp_len);
     sum += libnet_in_cksum((u_int16_t *) &tmp, 4);
     tmp = htonl(IPPROTO_TCP);
     sum += libnet_in_cksum((u_int16_t *) &tmp, 4);

     tmp = ((htons(tx.sp) << 16) + htons(tx.dp));
     sum += libnet_in_cksum((u_int16_t *) &tmp, 4);

     tmp = htonl(tx.tcp_seq);
     sum += libnet_in_cksum((u_int16_t *) &tmp, 4);
     tmp = htonl(tx.tcp_ack);
     sum += libnet_in_cksum((u_int16_t *) &tmp, 4);

     tmp = ((ntohs(((tx.tcp_offset) << 12) + tx.tcp_control) << 16) + htons(tx.tcp_win));
     sum += libnet_in_cksum((u_int16_t *) &tmp, 4);

     tmp = htonl(tx.tcp_urg);
     sum += libnet_in_cksum((u_int16_t *) &tmp, 4);

     sum += tx.tcp_sum_part;

     if (tx.tcp_payload_s)
       sum += libnet_in_cksum((u_int16_t *) tx.tcp_payload, tx.tcp_payload_s);

     tx.tcp_sum = ntohs(LIBNET_CKSUM_CARRY(sum));

     t = libnet_build_tcp (tx.sp,
	                   tx.dp,
	                   tx.tcp_seq,
	                   tx.tcp_ack,
	                   tx.tcp_control,
	                   tx.tcp_win,
	                   tx.tcp_sum,
	                   tx.tcp_urg,
	                   tx.tcp_len,
	                   tx.tcp_payload_s ? tx.tcp_payload : NULL,
	                   tx.tcp_payload_s,
	                   l,
	                   t);

   return t;
}

int update_ISUM(libnet_t *l, libnet_ptag_t t)
{
     int sum = 0;
     unsigned int tmp;

     if (tx.icmp_chksum != 0)
	return 0;

     sum += libnet_in_cksum((u_int16_t *) &tx.ip6_src, 16);
     if (tx.ip_option_s && tx.ip6_segs)
       sum += libnet_in_cksum((u_int16_t *) &tx.ip_option[tx.ip_option_s - 16], 16); // Use last IP address
     else
       sum += libnet_in_cksum((u_int16_t *) &tx.ip6_dst, 16);

     tmp = htonl(LIBNET_ICMPV6_H + tx.icmp_payload_s);
     sum += libnet_in_cksum((u_int16_t *) &tmp, 4);
     tmp = htonl(IPPROTO_ICMP6);
     sum += libnet_in_cksum((u_int16_t *) &tmp, 4);

     tmp = htonl(((tx.icmp_type << 8) + tx.icmp_code));
     sum += libnet_in_cksum((u_int16_t *) &tmp, 4);

     if (tx.icmp_payload_s)
       sum += libnet_in_cksum((u_int16_t *) tx.icmp_payload, tx.icmp_payload_s);

     tx.icmp_chksum = ntohs(LIBNET_CKSUM_CARRY(sum));

     t = libnet_build_icmpv4_echo (tx.icmp_type,
				   tx.icmp_code,
				   tx.icmp_chksum,
				   tx.icmp_ident,
				   tx.icmp_sqnr,
				   tx.icmp_payload_s ? tx.icmp_payload : NULL,
				   tx.icmp_payload_s,
				   l,
				   t);

   return t;
}

///////////////////////////////////////////////////////////////////////
//
// Applies another TCP SQNR from a specified range to a given TCP-PTAG
// 
// RETURN VALUE: '1' if tx.txp_seq restarts
// 
int update_TCP_SQNR(libnet_t *l, libnet_ptag_t t)
{

   u_int32_t diff;
   int i=0;
   
   tx.tcp_seq += tx.tcp_seq_delta;
   diff = tx.tcp_seq_stop - tx.tcp_seq_start;

   if (diff < tx.tcp_seq_stop) // start < stop
     {
	if (tx.tcp_seq > tx.tcp_seq_stop)
	  {
	     tx.tcp_seq = tx.tcp_seq_start;
	     i=1;
	  }
     }
   else // stop < start
     {
	if ( (tx.tcp_seq<tx.tcp_seq_start) && 
	     (tx.tcp_seq>tx.tcp_seq_stop) )
	  {
	     tx.tcp_seq = tx.tcp_seq_start;
	     i=1;
	  }
	
     }
   
   t = libnet_build_tcp (tx.sp,
			 tx.dp, 
			 tx.tcp_seq, 
			 tx.tcp_ack,
			 tx.tcp_control,
			 tx.tcp_win, 
			 tx.tcp_sum, 
			 tx.tcp_urg, 
			 tx.tcp_len,
			 (tx.tcp_payload_s) ? tx.tcp_payload : NULL,
			 tx.tcp_payload_s, 
			 l, 
			 t);
   
   if (t == -1)
     {
	fprintf(stderr, " mz/update_TCP_SQNR: Can't build TCP header: %s\n", libnet_geterror(l));
	exit (0);
     }  
   
   return i;
}


////////////////////////////////////////////////////////////////////////
//
//

int print_frame_details()
{
   unsigned char *dum1, *dum2;
   char pld[65535];
   char sa[32], da[32];
   
   if (!tx.packet_mode)
     {
	bs2str(tx.eth_dst, da, 6);
	bs2str(tx.eth_src, sa, 6);
	fprintf(stderr, " Eth: DA = %s, SA = %s\n",da,sa);
     }
   
   
   if (tx.dot1Q)
     {
	fprintf(stderr, " 802.1Q VLAN-TAG = %s\n", tx.dot1Q_txt);
     }

   if (tx.mpls)
     {
	fprintf(stderr," MPLS labels (label:exp:bos:ttl): %s\n",tx.mpls_verbose_string);
	
     }

   
   dum1 =  (unsigned char*) &tx.ip_src_h;
   dum2 = (unsigned char*) &tx.ip_dst_h;
   (mode==IP) ? (void) bs2str(tx.ip_payload, pld, tx.ip_payload_s) : strcpy(pld, "[see next layer]");

   if (ipv6_mode) {
     char src6[64]; char dst6[64];
     libnet_addr2name6_r(tx.ip6_src, LIBNET_DONT_RESOLVE, src6, 64);
     libnet_addr2name6_r(tx.ip6_dst, LIBNET_DONT_RESOLVE, dst6, 64);

     fprintf(stderr," IP:  ver=6, dscp=%u, flow=%u, len=%u, next=%u, hop=%u "
             "SA=%s, DA=%s\n      payload=%s\n", tx.ip_tos, tx.ip_flow,
	     tx.ip_len, tx.ip_proto, tx.ip_ttl, src6, dst6, pld);
   }
   else {
     fprintf(stderr," IP:  ver=4, len=%u, tos=%u, id=%u, frag=%u, ttl=%u, proto=%u, sum=%u, "
	     "SA=%u.%u.%u.%u, DA=%u.%u.%u.%u,\n"
	     "      payload=%s\n", tx.ip_len, tx.ip_tos,
	     tx.ip_id, tx.ip_frag, tx.ip_ttl, tx.ip_proto, tx.ip_sum,
	     *(dum1+3),*(dum1+2),*(dum1+1),*(dum1), *(dum2+3),*(dum2+2),*(dum2+1),*(dum2+0), pld);
   }
   
   if ((mode==UDP)||(mode==DNS)||(mode==RTP))
     {
	bs2str(tx.udp_payload, pld, tx.udp_payload_s);
	fprintf(stderr, " UDP: sp=%u, dp=%u, len=%u, sum=%u, \n"
		"      payload=%s\n", tx.sp, tx.dp, tx.udp_len, tx.udp_sum, pld);
     }
   if (mode==TCP) // TODO: Improve message details (flags, ...)
     {
	bs2str(tx.tcp_payload, pld, tx.tcp_payload_s);
	fprintf(stderr, " TCP: sp=%u, dp=%u, S=%u, A=%u, flags=%x, win=%u, len=%u, sum=%u, \n"
		"      payload=%s\n", 
		tx.sp, tx.dp, tx.tcp_seq, tx.tcp_ack, tx.tcp_control, tx.tcp_win, tx.tcp_len, tx.tcp_sum, pld);
     }
   
   // send_icmp must prepare the verbose string because there are many
   // different types of ICMP packets...
   if (mode==ICMP) 
     {
	fprintf(stderr, " %s\n", tx.icmp_verbose_txt);
     }

   if (mode==ICMP6)
     {
	fprintf(stderr, " %s\n", tx.icmp_verbose_txt);
     }
   
   // libnet_diag_dump_pblock(l);
   fprintf(stderr,"\n");

   if (simulate)
     {
	fprintf(stderr, "*** NOTE: Simulation only! Nothing has been sent! ***\n");
	exit(0);
     }
   
   
   return 0;
}


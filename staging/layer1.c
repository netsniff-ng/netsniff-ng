/*
 * Mausezahn - A fast versatile traffic generator
 * Copyright (C) 2008 Herbert Haas
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



// ****************************************************************************
// 
//     This section contains functions to send an arbitrary byte stream out of 
//     the network card. Currently it works perfect for Ethernet cards.
//     
//     TODO: Access to the 802.11 header 
// 
// ****************************************************************************

#include "mz.h"
#include "cli.h"

int send_eth()
{
   // Tasks:
   // 1. Check 'eth_src_txt' and 'eth_dst_txt' which contain either a MAC address or a keyword
   //    'eth_dst' can be set without having 'eth_src_txt' specified (the next 6 bytes of the
   //    'arg_string' will be used). But if 'eth_src_txt' is given then also 'eth_dst_txt' 
   //    should have been specified, otherwise a default (ff-ff-ff-ff-ff-ff) will be used.
   // 2. Check whether 'arg_string' contains a hex-string. If YES then convert it into an
   //    'eth_payload' and extract eth_type.
   // 3. Apply 'padding' if specified
   // 4. Check if frame has at least minimum length (14 Bytes).
   // 5. Send frame 'count' times and
   // 6. Apply 'delay' (make precautions for better delay functions)
   
   int 
     src,                 // flag telling whether user has specified a source address
     dst,                 // flag telling whether user has specified a destination address
     src_random=0, 
     dst_random=0, 
     byte_ptr=1,
     bytestring_s=0,
     min_size=15,
     pad=0,
     repeat, loop, update,
     i=0,
     j=0;
   char 
     err_buf[LIBNET_ERRBUF_SIZE],
     message[MAX_PAYLOAD_SIZE*3];
     
   u_int8_t       bytestring[MAX_PAYLOAD_SIZE];
   libnet_ptag_t  t;
   libnet_t       *l;

   
	
   if (tx.dot1Q)
     {
	fprintf(stderr," Note: raw layer 2 mode does not support 802.1Q builder.\n"
		       " If you want to create VLAN tags then you must do it by hand.\n");
	exit(1);
     }
   
   if (tx.mpls)
     {
	fprintf(stderr," Note: raw layer 2 mode does not support MPLS builder.\n"
		       " If you want to create MPLS labels then you must do it by hand.\n");
	exit(1);
     }
   
	

   
   // So other functions can use this function for sending Ethernet frames
   // These other functions must set dst, src, type and payload!
   if (tx.eth_params_already_set) goto ALL_SPECIFIED;
   
   
   if ((tx.padding) && (tx.padding<15)) // Note: ignored if padding==0
     { 
	     tx.padding=15;
	     if (mz_port)    {
		     cli_print(gcli, "Note: Set padding to 15 bytes (total length)\n");
	     } else
		     fprintf(stderr, " mz/send_eth: [Note] adjusted minimum frame size to 15 bytes.\n");
     }
   
   // Create a temporal, local bytestring:
   //
   for (i=0; i<MAX_PAYLOAD_SIZE; i++) bytestring[i]=0x00;
   bytestring_s = str2hex (tx.arg_string, bytestring, MAX_PAYLOAD_SIZE);
   
   // Set the flags to shorten subsequent decisions:
   src = strlen(tx.eth_src_txt);
   dst = strlen(tx.eth_dst_txt);
   
   
   // IN ANY CASE if src has been specified:
   // 
   if (src) 
     {
	// Evaluate Ethernet CLI options (-a and -b)
	if (check_eth_mac_txt(ETH_SRC))  // if true then problem!
	  {
	     // use own (already set in init.c)
	  }
	src_random = tx.eth_src_rand; // local vars are faster
     }

   // IN ANY CASE if dst has been specified:
   // 
   if (dst) 
     {
	// Evaluate Ethernet CLI options (-a and -b)
	if (check_eth_mac_txt(ETH_DST))  // if true then problem!
	  {
	     str2hex("ff:ff:ff:ff:ff:ff",tx.eth_dst, 6); // the default 
	  }
	dst_random = tx.eth_dst_rand; // local vars are faster
     }

   
   // Catch errors with too short bytestrings:
   // 
   if (src)
     {
	// bytestring only needs to contain eth_type
	min_size-=12; 
     }
   else if (dst)
     {
	// bytstring must contain src and type
	min_size-=6;
     }
   if (bytestring_s < min_size)
     {
	     j = min_size - bytestring_s; // this is what's missing
	     bytestring_s += j; // note that bytestring has been filled up with 0x00, so we can do that
     }

	
   // ADDENDUM: If src specified, dst missing:
   // 
   if ( (!dst) && (src) ) 
     {
	str2hex_mac ("ff:ff:ff:ff:ff:ff", tx.eth_dst);
     }
   
   
   
   // ADDENDUM: If dst specified, src missing:
   // 
   if ((dst) && (!src))
     {
	// Get eth_src from bytestring:
	if (bytestring_s>=6) {
		(void) getbytes (bytestring, tx.eth_src, byte_ptr, byte_ptr+5);
		byte_ptr=7; // now points to eth_type within bytestring
	}
     }
   
   // FINALLY: If both dst and src have NOT been specified:
   // 
   if ((!dst) && (!src))
     {
	     if (bytestring_s>=6) {
		     (void) getbytes (bytestring, tx.eth_dst, byte_ptr, byte_ptr+5);
		     byte_ptr=7;
	     }

	     if (bytestring_s>=12) {
		     (void) getbytes (bytestring, tx.eth_src, byte_ptr, byte_ptr+5);
		     byte_ptr=13; // points to eth_type
	     }
     }
   
   // Set eth_type:
   // 
   if (bytestring_s>=2) {
	   tx.eth_type = 256 * bytestring[byte_ptr-1] + bytestring[byte_ptr]; // don't forget: byte_ptr counts from 1 not 0
	   byte_ptr+=2; // points to first payload byte (if available)
   }


   // Get remaining payload:
   // 
   if ( (tx.eth_payload_s = bytestring_s - byte_ptr +1) > 0 ) // if there are any remaining bytes
     {
	(void) getbytes (bytestring, tx.eth_payload, byte_ptr, bytestring_s);
     }
   

	
   // Add padding if desired. 
   // Note: padding means 'extend to given length' (not 'add these number of bytes')
   if (tx.padding) 
     {
	pad = tx.padding - (14 + tx.eth_payload_s); // number of additonal pad bytes required
	for (i=0; i<pad; i++)
	  {  
	    // tx.eth_payload[i+tx.eth_payload_s] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
	    tx.eth_payload[i+tx.eth_payload_s] = 0x00;
	  }
	tx.eth_payload_s += pad;
     }
   
   
	
   ALL_SPECIFIED:
   // *** All Ethernet parameters have been determined !
   // *** Now let's send the frame!
   
   l = libnet_init (LIBNET_LINK_ADV, tx.device, err_buf ); 
   
   if (l == NULL)
     {
	fprintf(stderr, " mz/send_eth: libnet_init() failed (%s)", err_buf);
	return -1;
     }
   
   repeat=1;
   
   if (tx.count == 0) 
     {
	loop = 1000000;
	if (!quiet) 
	  fprintf(stderr, " mz: !!! Infinite mode! Will send frames until you stop Mausezahn!!!\n");
     }
   else
     loop = tx.count;

   if ( (!quiet) && (!tx.delay) && (tx.count==0) )
	fprintf(stderr, " mz: !!! Will send at maximum frame rate without feedback!!!\n");
   
   t=0;
   update=1;

   // this is for the statistics:
   mz_start = clock();
   total_d = tx.count;
   
   while (repeat)
     {
	if (tx.count!=0) repeat=0; // count=0 means repeat ad inifinitum 
	
	for (i=0; i<loop; i++)
	  {
	     if (src_random)
	       {
		  tx.eth_src[0] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256) & 0xFE;
		  tx.eth_src[1] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
		  tx.eth_src[2] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
		  tx.eth_src[3] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
		  tx.eth_src[4] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
		  tx.eth_src[5] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
		  update=1;
	       }
	     
	     if (dst_random)
	       {
		  tx.eth_dst[0] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
		  tx.eth_dst[1] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
		  tx.eth_dst[2] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
		  tx.eth_dst[3] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
		  tx.eth_dst[4] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
		  tx.eth_dst[5] = (u_int8_t) ( ((float) rand()/RAND_MAX)*256);
		  update=1;
	       }
	     
	     if (update) // new frame parameters
	       {
		  t = libnet_build_ethernet (tx.eth_dst,
					     tx.eth_src,
					     tx.eth_type,
					     tx.eth_payload,
					     tx.eth_payload_s,
					     l,
					     t); 
	     
		  if (t == -1)
		    {
		       fprintf(stderr, " mz/send_eth: %s", libnet_geterror(l));
		       return -1;
		    }
		  
		  if (verbose) 
		    {
		       bs2str (tx.eth_dst, message, 6);                     // DA
		       fprintf(stderr, " mz: send %s",message);
		       
		       bs2str (tx.eth_src, message, 6);                     // SA
		       fprintf(stderr, " %s",message);
		       
		       type2str(tx.eth_type, message);
		       fprintf(stderr, " %s",message);                      // Type
		       
		       bs2str (tx.eth_payload, message, tx.eth_payload_s);   // Payload
		       fprintf(stderr, " %s\n",message);
		    }
		  update=0;
		  if (verbose==2) 
		    {
		        fprintf(stderr, "\n");
		       	fprintf(stderr, "*** NOTE: Simulation only! Nothing has been sent! ***\n");
		       libnet_destroy(l);
		       return 0;
		    }
		  
		    
	       }
	     
	     libnet_write(l);

	     if (tx.delay) 
	       {
		  SLEEP (tx.delay);
		  if ( (verbose) && (!src_random) && (!dst_random)  ) 
		    {
		       fprintf(stderr, ".");
		    }
	       }
	     
	  } // end for
	
     } // end while
   
   if (verbose)
     {
	if ((tx.delay) || (tx.count==0))
	  {
	     fprintf(stderr,"\n");
	  }
	
	fprintf(stderr, " mz: sent %u frames.\n",loop);
     }
   
   
   
   libnet_destroy(l);

   
   return 0;
}



// ==========================================================================================
 
   /*
   if (verbose)
     {
	fprintf(stderr," mz/send_bytes: \n");
	bs2str(da,dast,6);
	fprintf(stderr,"   DA = %s", dast);
	bs2str(sa,sast,6);
	fprintf(stderr," SA = %s", sast);
	fprintf(stderr," type = %x",et);
	bs2str(payload,pl,payload_s);
	fprintf(stderr,"  data = %s\n",pl);
     }
   */

   









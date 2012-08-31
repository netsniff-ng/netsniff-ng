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





// ***************************************************************************
// 
//    This sections contains:
//     
//     -  complexity() ... calculates and reports how many frames will 
//                         be generated.
//     -  send_frame() ... the general and mighty SENDING FUNCTION.
//
// ***************************************************************************

#include "mz.h"
#include "cli.h"


// Calculates the number of frames to be sent.
// Should be used as standard output except the
// 'quiet' option (-q) has been specified.
int complexity()
{
   unsigned long int 
     nr_sqnr = 1, 
     nr_dp   = 1, 
     nr_sp   = 1,
     nr_da   = 1,
     nr_sa   = 1;
   
   u_int32_t 
     sn1, 
     sn2, 
     delta;

   long double ref;
   
   if (tx.count==0) goto infinity;
   
   total_d = 1.0;
   
   // How many sequence numbers?
   if (tx.tcp_seq_delta)
     {
	sn1 = tx.tcp_seq_start;
	sn2 = tx.tcp_seq_stop;
	delta = tx.tcp_seq_delta;
	
	if (sn1<sn2) // the easier case
	  {
	     nr_sqnr = (sn2-sn1)/delta;
	  }
	else
	  {
	     nr_sqnr = (sn2 + (0xffffffff - sn1)) / delta;
	  }
	//fprintf(stderr,"SQNR Range = %lu\n",nr_sqnr);
	nr_sqnr +=1;
     }
   
   if (tx.dp_isrange)
     {
	nr_dp = tx.dp_stop - tx.dp_start + 1;
	//fprintf(stderr,"DP Range = %lu\n",nr_dp);
     }

   if (tx.sp_isrange)
     {
	nr_sp = tx.sp_stop - tx.sp_start + 1;
	//fprintf(stderr,"SP Range = %lu\n",nr_sp);
     }
   
   if (tx.ip_dst_isrange)
     {
	nr_da = tx.ip_dst_stop - tx.ip_dst_start + 1;
	//fprintf(stderr,"DA Range = %lu\n",nr_da);
     }
   
   if (tx.ip_src_isrange)
     {
	nr_sa = tx.ip_src_stop - tx.ip_src_start + 1;
	//fprintf(stderr,"SA Range = %lu\n",nr_sa);
     }
   
   total_d *= tx.count;
   total_d *= nr_sqnr;
   total_d *= nr_dp;
   total_d *= nr_sp;
   total_d *= nr_da;
   total_d *= nr_sa;  
   



   ref=0xffffffff;

   ref*=ref;
   
   if (total_d>ref)
     {
	fprintf(stderr, "You must be crazy...\n");
     }
   else if (total_d>0xffffffff)
     {
	fprintf(stderr, "Do you REALLY know what you do?\n");
     }
   else if (total_d>0xffffff)
     {
	fprintf(stderr, "Do you know what you do?\n");
     }

   if (mz_port)
     {
	cli_print(gcli, "Mausezahn will send %.Lf frames...\r", total_d);
     }
   else
     {
	fprintf(stderr, "Mausezahn will send %.Lf frames... ", total_d);
	fflush(stderr);
	if (verbose) fprintf(stderr,"\n");
     }
   
   
   
   mz_start = clock();
   
   infinity:
   
   
    if (tx.count==0)
     {
	if (mz_port)
	  {
	     cli_print(gcli, "Mausezahn will send frames infinitly...\n");
	  }
	else
	  {
	     fprintf(stderr, "Mausezahn will send frames infinitly...\n");
	  }
     }
   
   
   return 0;
}



///////////////////////////////////////////////////////////////////////
//
// Send complete frame (layers 2, 3, 4) multiple times if required
// 
// 
int send_frame (libnet_t *l, libnet_ptag_t  t3, libnet_ptag_t  t4)
{
   int i=0, count;

   int // local vars are faster ;-)
     tcp_seq_delta,
     dp_isrange,
     sp_isrange,
     ip_dst_isrange,
     ip_src_isrange,
     rtp_mode=0;

   
   count = tx.count;
   tcp_seq_delta = tx.tcp_seq_delta;
   dp_isrange = tx.dp_isrange;
   sp_isrange = tx.sp_isrange;
   ip_dst_isrange = tx.ip_dst_isrange;
   ip_src_isrange = tx.ip_src_isrange | tx.ip_src_rand;
   if (mode == RTP) rtp_mode = 1;
   
   if (count==0) goto AGAIN;

   for (i=0; i<count; i++)
     {

	AGAIN:

	if (verbose) (void) print_frame_details();
	libnet_write(l);
	if (mz_rand) tx.delay=(unsigned int) tx.delay*rand()/RAND_MAX;
	if (tx.delay) SLEEP (tx.delay);
	
	//   No layer-2 modifications done here 
	//   (see create_eth_frame which does L2 modifications additionally)

	
	if (tcp_seq_delta)
	  {
	     if (update_TCP_SQNR(l, t4)==0) // end of range not yet reached
	       {
		  goto AGAIN;
	       }
	  }
	
	if (dp_isrange)
	  {
	     if (update_DPORT(l, t4)==0) // end of range not yet reached
	       {
		  goto AGAIN;
	       }
	  }
	
	if (sp_isrange)
	  {
	     if (update_SPORT(l, t4)==0) // end of range not yet reached
	       {
		  goto AGAIN;
	       }
	  }
	

	if (ip_dst_isrange)
	  {
	     if (update_IP_DA(l, t3)==0) // end of range not yet reached
	       {
		  goto AGAIN;
	       }
	  }
	
	if (ip_src_isrange) // also catches random SA (see above)
	  {
	     if (update_IP_SA(l, t3)==0) // end of range not yet reached
	       {
		  goto AGAIN;
	       }
	  }

	if (rtp_mode) // update SQNR and Timestamps in RTP header and payload
	  {
	     update_RTP(l, t4);
	  }
	
	
	if (!count) goto AGAIN;
     }
   

   
   libnet_destroy(l);
   
   return 0;
}


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


///////////////////////////////////////////////////
// 
// Table of contents:
// 
// rcv_rtp_init()
// rcv_rtp()
// compare4B()
// got_rtp_packet() 
// print_jitterbar()
// 

///////////////////////////////////////////////////
// 
// Documentation about RTP traffic analysis
// 
// See http://wiki.wireshark.org/RTP_statistics
//
// 

#include "mz.h"
#include "mops.h"

// Initialize the rcv_rtp process: Read user parameters and initialize globals
int rcv_rtp_init()
{
	char argval[MAX_PAYLOAD_SIZE];
	char dummy[512];
	int len;
	u_int32_t port = 30000;  // 4-byte variable to catch errors, see below

	int ssrc_s = 0;
   
	// Help text

	if (getarg(tx.arg_string,"help", NULL)==1) {
		fprintf(stderr,"\n"
			MAUSEZAHN_VERSION
		"\n"
		"| RTP reception for jitter measurements.\n"
		"|\n"
		"| Parameters:\n"
		"|\n"
		"|   bar             ...... Display modes: By default 'bar' is used and shows the RFC 3550 jitter as\n"
		"|                          ASCII-based waterfall diagram.\n"
		"|   txt             ...... The 'txt' mode prints all measurement values numerically upon each\n"
		"|                          measurement interval.\n"
//		"|   curse           ...... Shows all values and a diagram within an resizesable ncurses window.\n"
		"|\n"
		"|   ssrc            ....... Listen to the stream with the specified SSRC. You must specify this\n"
		"|                           when there are concurrent streams, e. g. one in each direction.\n"
		"|\n"
		"|   log             ....... Write moving average also in a datafile (not only on terminal).\n"
		"|   logg            ....... Like log but additionally write detailed real-time statistics in a data file\n"
		"|   path = <path>    ....... Path to directory where datafiles can be stored (default: local directory).\n"
		"|   num = <10-%d> ...... number of packets to be received for averaging (default: %d).\n"
		"|   port = <0-65535> ....... Change if RTP packets are sent to a different port than 30000 (default).\n"
		"|\n"
		"| Note:\n"
		"|\n"
		"|  Mausezahn can log actual realtime measurement data in data files (in the specified path or\n"
		"|  current directory) but always prints the moving average on the command line (this can be disabled\n"
		"|  using the 'quiet' option (-q)).\n" 
		"|\n"
		"|  The realtime data file(s) consist of two columns:\n"
		"|\n"
		"|  1. relative timestamp in usec\n"
		"|  2. 'true' jitter in usec\n"
		"|\n"
		"|  where the 'true' jitter is calculated using the (relative) timestamps inside the received\n"
		"|  packets t(i) and the (relative) timestamps T(i) observed locally when packets are received using\n"
		"|  the formula:\n"
		"|\n"
		"|    jitter(i) = [T(i) - T(i-1)] - [t(i) - t(i-1)] + jitter(i-1)  .\n"
		"|\n"
		"|  This method has two advantages: (i) we do not need to synchronize the clocks of sender and\n"
		"|  receiver, and (ii) the TX-side jitter (mainly caused by the kernel-scheduler) is subtracted\n"
		"|  so that we primarily measure the jitter caused by the network.\n"
		"|  \n"
		"|  The data files consist of seven columns:\n"
		"|  \n"
		"|  1. relative timestamp in seconds\n" 
		"|  2. minimum jitter\n"
		"|  3. average jitter\n"
		"|  4. minimum jitter\n"
		"|  5. estimated jitter variance according RFC-3550\n"
		"|  6. packet drop count (total)\n"
		"|  7. packet disorder count (total)\n"
		"|  \n"
		"|  All measurement values are done in usec and refer to the current set of samples (see parameter 'num').\n"
	        "|  Note that an RFC-conform jitter (smoothed mean deviation) is calculated and collected in column five.\n"
		"|  The drop value refers to the current measurement window, while the total drop and disorder values are\n"
		"|  calculated using some weird estimation functions; the goal was to provide a 'time-less' estimation\n"
		"|  while being able to automatically resynchronize to a re-started RTP measurement stream.\n"
		"|  \n"
		"| EXAMPLE USAGE:\n"
		"|\n"		
		"|  At the TX-station enter:\n"
		"|\n"
		"|    # mz eth0 -t rtp -B 10.3.3.42    (optionally change rate via -d option, payload size via pld command)\n"
		"|\n"
		"|  At the RX-station (10.3.3.42) enter:\n"
		"|\n"
		"|    # mz eth0 -T rtp \"log, path=/tmp/mz/\"\n"
		"|\n"
		"\n", TIME_COUNT_MAX, TIME_COUNT);
	exit(0);
	}
   
   
	// check argstring for arguments
   
	if (getarg(tx.arg_string,"bar", NULL)==1) {
		rtp_dm = BAR;
	}
	
	if (getarg(tx.arg_string,"txt", NULL)==1) {
		rtp_dm = TEXT;
	}
	
	if (getarg(tx.arg_string,"curses", NULL)==1) {
		rtp_dm = BAR; //NCURSES;
		fprintf(stderr, " XXX This Mausezahn version does not support ncurses windows.\n");
	}
	
	if (getarg(tx.arg_string,"width", argval)==1) { 
		if (rtp_dm != BAR) {
			fprintf(stderr, " mz/rcv_rtp: The 'width' parameter requires the display mode 'bar'\n");
			return -1;
		}
		bwidth = (int) str2int(argval); // [TODO] bwidth is currently not used
		if (bwidth>RCV_RTP_MAX_BAR_WIDTH) {
			fprintf(stderr, "The width must not exceed %i\n", 
				RCV_RTP_MAX_BAR_WIDTH);
			return -1;
		}
	} else bwidth=80;

	if (getarg(tx.arg_string,"ssrc", argval)==1) {
		ssrc_s = str2hex(argval, mz_ssrc, 4);
		if (ssrc_s<0) {
			fprintf(stderr, " mz/rtp_rcv: invalid ssrc!\n");
			return -1;
		}
	}
	
	if (getarg(tx.arg_string,"log", NULL)==1) {
		rtp_log = 1;
	}

	if (getarg(tx.arg_string,"logg", NULL)==1) {
		rtp_log = 2;
	}

   
	if (getarg(tx.arg_string,"path", argval)==1) {
		len = strlen(argval);
		if (len>128) {     
			fprintf(stderr, " mz/Error: path must not exceed 128 characters!\n");
			exit (-1);
		}
		if (argval[len-1]!='/') {
			strncat(argval, "/",1); // ensure that all paths end with "/"
		}
		strncpy(path, argval, 128);
	}


	if (getarg(tx.arg_string,"num", argval)==1) {
		gind_max = (u_int32_t) str2int(argval);
		if (gind_max > TIME_COUNT_MAX) {
			gind_max = TIME_COUNT_MAX;
			fprintf(stderr, " mz/Warning: num range is 10..%d. Will reset to %d.\n", 
				TIME_COUNT_MAX, TIME_COUNT_MAX);
		}
		else if (gind_max < 10) {
			gind_max = 10;
			fprintf(stderr, " mz/Warning: num range is 10..%d. Will reset to 10.\n",
				TIME_COUNT_MAX);
		}
	}
   

	// initialize global filter string 
	strncpy (rtp_filter_str, "udp dst port 30000", 64);
	
	if (getarg(tx.arg_string,"port", argval)==1) {
		port = (u_int32_t) str2int(argval);
		if (port>65535) {
			port = 30000;
			fprintf(stderr, " mz: Too large port number! Reset to default port (30000).\n");
		}
	
		sprintf(rtp_filter_str, "udp dst port %u", (unsigned int) port);
	}
   
	// 
	if (ssrc_s==0) str2hex("ca:fe:fe:ed", mz_ssrc, 4);

	// open file
   	// 
	if (rtp_log) {
		// get a new filename
		timestamp_human(filename, "rtp_avg_");
		strncpy(dummy, path, 128);
		strncat(dummy, filename, 64);
		if (verbose) fprintf(stderr, " mz: Will open %s\n", dummy);
		
		fp = fopen (dummy, "w+");
		
		if (fp == NULL) {
			perror("fopen");
			exit (-1);
		}
		
		gtotal=0; // counts written data blocks
		fprintf(fp, "# Average jitter measurements made by Mausezahn " MAUSEZAHN_VERSION_SHORT ".\n");
		fprintf(fp, "# Timestamp is in seconds, all other values in microseconds.\n");
		fprintf(fp, "# Column values (from left to right):\n");
		fprintf(fp, "#  1. Timestamp\n"
			"#  2. min_jitter\n"
			"#  3. avg_jitter\n"
			"#  4. max_jitter\n"
			"#  5. estimated jitter according RFC-3550\n"
			"#  6. packet drop count (total)\n"
			"#  7. packet disorder count (total)\n");
		
	
		///////////// also detailed log required /////////////
		if (rtp_log==2) {
			// get a new filename
			timestamp_human(filename, "rtp_rt_");
			strncpy(dummy, path, 128);
			strncat(dummy, filename, 64);
			if (verbose) fprintf(stderr, " mz: Will open %s\n", dummy);
	     
			fp2 = fopen (dummy, "w+");
	     
			if (fp2 == NULL) {
				perror("fopen");
				exit (-1);
			}
	     
			fprintf(fp2, "# Jitter measurements by Mausezahn " MAUSEZAHN_VERSION_SHORT ".\n");
			fprintf(fp2, "# Timestamp (usec) , true jitter (nsec)\n");
		}
		
	}
	
	drop=0;
	dis=0;
	jitter_rfc=0;

	return 0;
}
   

   
   
   
   
   
////////////////////////////////////////////////////////////////////////////////////////////
//
// Defines the pcap handler and the callback function
int rcv_rtp()
{
   char   errbuf[PCAP_ERRBUF_SIZE];
   
   pcap_t     *p;
   
   struct bpf_program filter;

   
   
   p = pcap_open_live (tx.device,
		       MAXBYTES_TO_READ,   // max num of bytes to read
		       0,                  // 1 if promiscuous mode
		       PCAP_READ_TIMEOUT_MSEC,     // read timeout in msec
		       errbuf);
   
   if (p == NULL)
     {
	fprintf(stderr," mz/rcv_rtp: %s\n",errbuf);
	exit(1);
     }
   

   if ( pcap_compile(p,
		     &filter,         // the compiled version of the filter
		     rtp_filter_str,  // text version of filter
		     0,               // 1 = optimize
		     0)               // netmask
	== -1)
     {
	fprintf(stderr," mz/rcv_rtp: Error calling pcap_compile\n");
	exit(1);
     }
   
   
   
   if ( pcap_setfilter(p, &filter) == -1)
     {
	fprintf(stderr," mz/rcv_rtp: Error setting filter\n");
	pcap_geterr(p);
	exit(1);
     }

   again:


   pcap_loop (p,
	      1,                // number of packets to wait
	      got_rtp_packet,   // name of callback function
	      NULL);            // optional additional arguments for callback function
   
   
   goto again;
   
   
   // TODO: Currently we never reach this point!
   fprintf(stderr, " mz: receiving of RTP finished.\n");
   pcap_close(p);
   
   return 0;
}




// Compares two 4-byte variables byte by byte
// returns 0 if identical, 1 if different
inline int compare4B (u_int8_t *ip1, u_int8_t *ip2)
{
   if (*ip1 != *ip2) return 1;
   if (*(ip1+1) != *(ip2+1)) return 1;
   if (*(ip1+2) != *(ip2+2)) return 1;
   if (*(ip1+3) != *(ip2+3)) return 1;
   
   return 0;
}
                




// Handler function to do something when RTP messages are received
void got_rtp_packet(u_char *args,
		    const struct pcap_pkthdr *header, // statistics about the packet (see 'struct pcap_pkthdr')
		    const u_char *packet)             // the bytestring sniffed
{
	const struct struct_ethernet *ethernet;
	const struct struct_ip       *ip;
	const struct struct_udp      *udp;
	const struct struct_rtp      *rtp;
	
	int size_ethernet = sizeof(struct struct_ethernet);
	int size_ip = sizeof(struct struct_ip);
	int size_udp = sizeof(struct struct_udp);
	// int size_rtp = sizeof(struct struct_rtp);
   	// 
	ethernet = (struct struct_ethernet*)(packet);
	ip       = (struct struct_ip*)(packet+size_ethernet);
	udp      = (struct struct_udp*)(packet+size_ethernet+size_ip);
	rtp      = (struct struct_rtp*)(packet+size_ethernet+size_ip+size_udp);
	
	struct mz_timestamp 
		deltaTX,
		deltaRX;
	
	u_int32_t 
		i,
		jitter_abs,
		jitter_avg,
		jitter_max,
		jitter_min,
		curtime=0;

	int32_t ltemp;
	
	u_int8_t *x,*y;
	
	char dummy[256];
	char ts_hms[10];
	unsigned char *dum;
	static u_int32_t drop_last=0, drop_prev=0;
	int s1, s2;
	
	// check if the RTP packet is really from a Mausezahn instance:
	if (compare4B((u_int8_t*) &rtp->ssrc, mz_ssrc)==0) {
		// we got a valid RTP packet from a Mausezahn instance
		// Get current SQNR and store it in 'sqnr_cur' in host byte order
		x  = (u_int8_t*) &rtp->sqnr;
		y  = (u_int8_t*) &sqnr_cur;
		
		*y = *(x+1);
		y++;
		*y = *x;

		/////////////////////////////////////////////////////////////////////
		// Packet drop and disorder detection:
		if (sqnr0_flag) {
			if (sqnr_next==sqnr_cur) {  // correct SQNR received
				sqnr_next++;
				sqnr_last++;
			} else if (sqnr_last>sqnr_cur) { // disordered sequence
				dis++;
				if (drop) drop--; // don't get below 0
				else { // drop reached zero: resync (restarted RTP stream?)
					sqnr_last = sqnr_cur; 
					sqnr_next = (++sqnr_last);
					dis=0;
				}
			} else {  // packet drop
				drop += (sqnr_cur-sqnr_next);
				sqnr_last = sqnr_cur;
				sqnr_next = (++sqnr_last);
			}
		} else { 
			// initial synchronization with observed SQNR:
			sqnr_last = sqnr_cur;
			sqnr_next = (++sqnr_last);
			sqnr0_flag++;
		}
		//
		/////////////////////////////////////////////////////////////////////

		
		// Get RX timestamp from pcap header
		timeRX[gind].sec  = header->ts.tv_sec;
		timeRX[gind].nsec = header->ts.tv_usec *1000;

		// Get TX timestamp from the packet 
		mops_hton4((u_int32_t*) &rtp->time_sec,  (u_int8_t*) &timeTX[gind].sec);
		mops_hton4((u_int32_t*) &rtp->time_nsec, (u_int8_t*) &timeTX[gind].nsec);

//		printf("%li %li\n", (long int) timeTX[gind].sec, (long int) timeTX[gind].nsec);
		
		gind++;
	
		////////////////////////////////////////////////////////////////
		if (gind == gind_max) { // array full, now calculate statistics
			gind=0;
			gtotal++;
			
			jitter_avg = 0;
			jitter_min = 0xffffffff;
			jitter_max = 0;
			
			
			///////////////////////////////////////////////////////
			// calculate deltas and jitters
			for (i=2; i<gind_max; i++) { // omit the first 2 data 
				                     // entries because of 
				                     // artificial high TX-delta!
						     // 
				///////////////////////////////////////////////
				// calculate deltaTX and deltaRX
				//
				s1=timestamp_subtract (&timeTX[i], &timeTX[i-1], &deltaTX);
				s2=timestamp_subtract (&timeRX[i], &timeRX[i-1], &deltaRX);
				if (s1) fprintf(stderr, " ***  ***\n");
				
				// Then calculate the precise jitter by considering 
				// also TX-jitter: (pseudo)jitter = deltaRX - deltaTX, 
				// hence we have positive and negative jitter (delay 
				// deviations) jitter entries are in +/- nanoseconds
				jitter[i] = (deltaRX.sec*1000000000L + deltaRX.nsec)
					  - (deltaTX.sec*1000000000L + deltaTX.nsec);
				// Calculate RFC 3550 jitter estimation. According to 
				// that RFC the jitter should be measured in timestamp 
				// units; however currently Mausezahn uses nanoseconds.
				// (If we want to solve this: G.711 timestamp units are 
				// 125 usec, so jitter/=125 would be sufficient, AFAIK)
				ltemp = labs(jitter[i]) - jitter_rfc;
				jitter_rfc += (ltemp>>4);  
				// Add previous pseudojitter to get the true jitter 
				// (See Documentation!)
				jitter[i] += jitter[i-1];
				//
				////////////////////////////////////////////////
		  


		  
				////////////////////////////////////////////////
				// Determine avg, min, and max jitter within this time frame:
				jitter_abs = labs(jitter[i]);
				jitter_avg += jitter_abs;
				if (jitter_abs < jitter_min) jitter_min = jitter_abs;
				if (jitter_abs > jitter_max) jitter_max = jitter_abs;
				//
				////////////////////////////////
		  
				/// PRINT IN FILE_2: Detailed jitter data ///
				if (rtp_log==2) {
					// Calculate relative timestamp for column 1 of the datafile 
					curtime = timeRX[i].sec*1000000+timeRX[i].nsec/1000;
					if (time0_flag) {
						curtime = curtime - time0;
					} else { // this is only done once during the Mausezahn process
						time0 = curtime;
						time0_flag=1;
						curtime = curtime - time0;
					}
					fprintf(fp2, "%lu, %li\n", 
						(long unsigned int) curtime, 
						(long int) jitter[i]);
					fflush(fp2); // save everything immediately 
					             // (CHECK if fsync() is additionally needed)
				}
			} // end for (i=2; i<gind_max; i++)
			//
			////////////////////////////////////////////////////////
	     
	     
			jitter_avg = jitter_avg / (gind_max-2);    // average true jitter, always positive

			if (drop>=drop_prev) { // because the total drop count may decrease(!) if disordered packets appear lately
				drop_last = drop - drop_prev;
				drop_prev=drop;
			} else drop_last=0; 
			
			// PRINT ON CLI: statistics data
			switch (rtp_dm) {
			 case TEXT:
				dum =  (unsigned char*) &ip->src;
				fprintf(stdout, 
					"Got %u packets from host %u.%u.%u.%u: %lu lost (%lu absolute lost, %lu out of order)\n"
					"  Jitter_RFC (low pass filtered) = %li usec\n"
					"  Samples jitter (min/avg/max)   = %lu/%lu/%lu usec\n",
					gind_max,
					*(dum),*(dum+1),*(dum+2),*(dum+3),
					(long unsigned int) drop_last, 
					(long unsigned int) drop, 
					(long unsigned int) dis,
					(long int) jitter_rfc/1000,
					(long unsigned int) jitter_min/1000,
					(long unsigned int) jitter_avg/1000,
					(long unsigned int) jitter_max/1000);
				break;
				
			 case BAR:
				print_jitterbar(jitter_rfc/1000, drop_last);
				break;
				
			 case NCURSES: // would be nice...?
				break;
				
			 default:
				break;
			}

			// Determine whether some packets got lost:
			// 
			// 
			// 
			// 
	     
	     
	     
			/// PRINT IN FILE_1: statistics only ///
			if (rtp_log) {
				ts_hms[0]=0x00;
				timestamp_hms (ts_hms);
				fprintf(fp, 
					"%s, %lu, %lu, %lu, %li, %u, %u\n",
					ts_hms,
					(long unsigned int) jitter_min/1000,
					(long unsigned int) jitter_avg/1000,
					(long unsigned int) jitter_max/1000,
					(long int) jitter_rfc/1000,
					drop,
					dis);
				fflush(fp);
			}
	     
	     
	     
			// Open another file if current file reaches a limit
			// 
			if ((rtp_log==2) && (gtotal>MAX_DATA_BLOCKS)) { // file big enough, 
				gtotal=0;
				if (fclose(fp2) == EOF) {
					perror("fclose");
					exit(1);
				}
		  
				if (verbose) 
					fprintf(stderr, " mz: %s written.\n",filename);
		  
				timestamp_human(filename, "rtp_");  // get a new filename
				strncpy(dummy, path, 128);
				strncat(dummy, filename, 64);
		  
				if (verbose) fprintf(stderr, " mz: Will open %s\n", dummy);
		  
				if  ( (fp2 = fopen (dummy, "w+")) == NULL) {
					if (errno != EAGAIN) {
						perror("fopen");
						exit (-1);
					}
				}
				fprintf(fp2, "# Jitter measurements by Mausezahn " 
					MAUSEZAHN_VERSION_SHORT ".\n");
				fprintf(fp2, "# Timestamp (usec) , true jitter (nsec)\n");
			}
		} // statistics end *********************************************************************
	}
}




void print_jitterbar (long int j, u_int32_t d)
{
	// Determine actual data window by considering two events:
	// 
	//  1) window move     (j exceeds lower or upper limit)
	//  2) window rescale  (window moves happen too often or the variance 
	//                      of successive data points is too small)
	// 
	// The most critical value is the chosen resolution (window range), 
	// especially the _initial_ resolution. 
       
	static long int range=0, min=0, max=0, minvar=0, j0=0, dj=0;
	static int moved=0, varcount=0, barcount=0;
	char str[128], bar[150], 
		str1[8], str2[8], str3[8], str4[8];
	int event=0, anz;
	long int tmp;
	
	// Initialize vars (start with an opened window)
	// Note that 'range' is actually half of the window
	if (!range) {
		range=j;
		if (range<500) range=500;
		max = j+range;
		min = 0;
		minvar=range/40;
		event++;
	} else {
		dj = labs(j-j0);  // no initialization: calculate jitter delta
	}
	
	// Move window when borders crossed:
	if ((j<min) || (j>max)) {
	        max = j + range;
		min = max-2*range;
		if (min<0) {
			min=0;
			range=(max-min)/2;
			fprintf(stdout, "\nNOTE: +- Rescaled window to %4.2f msec\n", (double) range/500);
		}
		moved++;
		event++;
		fprintf(stdout,"\n");
//		printf("move event: min=%li max=%li\n", min, max);
	} else {
		if (moved) moved--;
//		printf("normal event: min=%li max=%li\n", min, max);
	}
	
	
	// Increase range when window moved 5 times in a row
	if (moved>2) { 
		range*=3;
		if (range>10000000L) range=10000000L;
		minvar=range/40;
		if (minvar<1000) minvar=1000;
		max=j+range;
		min=j-range;
		if (min<0) {
			min=0;
			range=(max-min)/2;
		}
		moved=0;
		event++;
//		printf("scale up event: min=%li max=%li\n", min, max);
		fprintf(stdout, "\nNOTE: ++ Rescaled window to %4.2f msec\n", (double) range/500);
	}


	// Decrease range when jitter deltas are smaller than minvar
	// 5 times in a row
	if (dj<minvar) 
		varcount++;
	else 
		varcount=0;
	
	if (varcount>5) {
		range*=0.75;
		if (range>j) range=j;
		if (range<500)	{
			range=500;
		}
		minvar=range/40;
		if (minvar<1000) minvar=1000;
		max=j+range;
		min=j-range;
		if (min<0) {
			min=0;
			range=(max-min)/2;
		}
		fprintf(stdout, "\nNOTE: -- Rescaled window to %4.2f msec\n", (double) range/500);
		varcount=0;
		event++;
//		printf("scale down event: min=%li max=%li\n", min, max);
	}
	
	j0=j;

	barcount++;
	if (barcount==24) {
		event=1;
		barcount=0;
	}
	
	if (event) {
		tmp=range*0.667;
		sprintf(str1,"%4.2f", (double) min/1000);
		sprintf(str2,"%4.2f", (double) (min+tmp)/1000);
		sprintf(str3,"%4.2f", (double) (max-tmp)/1000);
		sprintf(str4,"%4.2f", (double) max/1000);

		fprintf(stdout,
			"%-6s                   %-6s                    %-6s                    %-6s\n"
			"|-------------------------|-------------------------|-------------------------|\n",
			str1, str2, str3, str4);
		barcount=0;
	}

	anz = 80*(j-min)/(2*range);
	if (anz) {
		memset((void*) str, '#', anz);
		memset((void*) str+anz, ' ', 80-anz);
		str[80]='\0';
	}
	else {
		memset((void*) str, ' ', 80);
		str[0]='#';
		str[80]='\0';
	}
	if (d) 
		sprintf(bar, "%s%4.2f msec !%lu dropped!", str, (double) j/1000, (unsigned long int) d);
	else
		sprintf(bar, "%s%4.2f msec", str, (double) j/1000);
	
	fprintf(stdout,"%s\n", bar);
}


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



#include "mz.h"
#include "cli.h"
#include "mops.h"

#define MZ_RTP_HELP \
   		"| RTP type: Send Real Time Protocol packets.\n" \
		"|\n" \
		"| This mode is solely intended to conduct delay, drop, and jitter measurements in\n" \
		"| Voice (Video) over IP networks. You will typically initiate another Mausezahn\n" \
		"| instance on the destination host, which will perform the measurements or even\n" \
		"| 'bounce back' the packets for Round Trip Time (RTT) measurements.\n" \
		"|\n" \
		"| When the delay parameter is not specified, the default (inter-packet) delay is\n" \
		"| set to 20 msec. You must specify the destination host using the -B option.\n" \
		"| The default destination port is (UDP) 30000 but can be overridden (dp parameter).\n" \
		"| You do not need to specify the count option (-c), because 'infinite' (0) is assumed.\n" \
		"|\n" \
		"| You can specify these additional GENERAL options:\n" \
		"|\n" \
		"|  -c <count>     ..... use this packet count value instead of infinity.\n" \
		"|  -d <delay>     ..... use this delay value instead of the defaul. Per default\n" \
		"|                       the units are microseconds but you can also use msec or sec\n" \
		"|\n" \
		"| You can specify these additional UDP/RTP-specific arguments:\n" \
		"|\n" \
		"|   dp    = <1-65535> ..... use this UDP destination port instead of 30,000.\n" \
		"|   sp    = <1-65535> ..... use this UDP source port instead of random.\n" \
		"|   ssrc  = XX:XX:XX:XX ... use this hex sequence as stream identifier\n" \
		"|                           (=SSRC, required for multiple concurrent measurements)\n" \
                "|   codec             ..... simulate G.711 codec (other will follow).\n" \
		"|   pld = <1..1000> ....... create specified payload size (default=160 bytes, which results\n" \
		"|                           in a total datagram length of 180 bytes, considering the UDP and\n" \
		"|                           RTP header lengths (8 and 12 bytes, respectively).\n" \
		"|\n" \
                "| Additional help: enter 'mz -T rtp help'\n" \
		"|\n"



int create_rtp_packet()
{
	u_int8_t byte1,	byte2;
	u_int16_t seqnr;
	u_int8_t ssrc[4] = {0,0,0,0} ;
	int ssrc_s = 0;
	u_int8_t *ptr;
	char argval[MAX_PAYLOAD_SIZE];
	unsigned int rtp_payload_size=160;
	struct mz_timestamp ts;
	
	if ( (getarg(tx.arg_string,"help", NULL)==1) && (mode==RTP) ) {
		if (mz_port)
		{
			cli_print(gcli, "%s", MZ_RTP_HELP);
			return -1;
		}
		else
		{
			
			fprintf(stderr,"\n" 
				MAUSEZAHN_VERSION
				"\n%s", MZ_RTP_HELP);
			exit(0);
		}
	}
	
	
	if (getarg(tx.arg_string,"pld", argval)==1) {
		rtp_payload_size = (unsigned int) str2int(argval);
	}
	
	if (getarg(tx.arg_string,"codec", argval)==1) {
		tx.delay = 20000;
	}

	if (getarg(tx.arg_string,"ssrc", argval)==1) {
		ssrc_s = str2hex(argval, ssrc, 4);
		if (ssrc_s<0) {
			fprintf(stderr, " mz/rtp: invalid ssrc!\n");
			return -1;
		}
	}

   // TODO: Optional arguments for RTP
   
   
   // Create header: //

   // Byte 1    
   // 
   // +--+--+--+--+--+--+--+--+
   // | ver | P| X| CSRC Count|
   // +--+--+--+--+--+--+--+--+
   // 
   // Default: ver=2, Padding=0, Extension_Header=1, CSRC_Count=0 => 10 0 1 0000 = 0x90

	byte1 = 0x90;
   
   // Byte 2
   // 
   // +--+--+--+--+--+--+--+--+
   // | M|    Payload Type    |
   // +--+--+--+--+--+--+--+--+
   // 
   // Marker=0, Payload Type=0 (or 8 alternatively)

	byte2 = 0x00;
   
   // Bytes 3,4
   // 
   // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   // |               Sequence Number                 |
   // +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

	seqnr = 0x0000;
   
   // Bytes 5,6,7,8
   // 
   //	Timestamp  /* done below */
   //
   
   
   // Bytes 9,10,11,12
   //
   //   Synchronization Source Identifier
   // 
   
	if (ssrc_s==0) str2hex("ca:fe:fe:ed", ssrc, 4);
	
   // Bytes 13,14,15,16
   // 
   //     CSRC - Contributing Source Identifiers (optional, only used by mixers)
   //
   //   csrc = 0x00000000; 
   
   // Bytes 17,18,19,20
   // 
   //   Header Extension (optional) NOT USED HERE!
   // 

   // !!! Thus payload begins with index 16 in a C array !!!

   // ------------ Now combine all fields: ----------------
   tx.udp_payload[0] = byte1;
   tx.udp_payload[1] = byte2;
   
   ptr = (u_int8_t*) &seqnr;
   tx.udp_payload[2] = *(ptr+1);
   tx.udp_payload[3] = *ptr;
   
   // TIMESTAMP: will be linearly increased, e.g. using 20msec G.711: 0, 160, 320, ...
   tx.udp_payload[4] = 0x00;
   tx.udp_payload[5] = 0x00;
   tx.udp_payload[6] = 0x00;
   tx.udp_payload[7] = 0x00;

   tx.udp_payload[8] = ssrc[0];
   tx.udp_payload[9] = ssrc[1];
   tx.udp_payload[10] = ssrc[2];
   tx.udp_payload[11] = ssrc[3];
   
   /*
   ptr = (u_int8_t*) &csrc;
   tx.udp_payload[12] = *(ptr+3);
   tx.udp_payload[13] = *(ptr+2);
   tx.udp_payload[14] = *(ptr+1);
   tx.udp_payload[15] = *ptr;
   */
   
   // Add the NEW Mausezahn extension header (see mops_ext_rtp.c)
   tx.udp_payload[12] = 0xca;  // identifier
   tx.udp_payload[13] = 0xca;
   tx.udp_payload[14] = 0x00;
   tx.udp_payload[15] = 0x04;  // length
   getcurtime(&ts); // Now add TX timestamp:
   mops_hton4 ((u_int32_t*) &ts.sec,  &tx.udp_payload[16]);
   mops_hton4 ((u_int32_t*) &ts.nsec, &tx.udp_payload[20]);
   // NOTE: The remaining 8 bytes of this extension header are set to zero
   // via the following code.
   
   memset(&tx.udp_payload[24], 0x00, (rtp_payload_size-12)); // payload (considering our 8 byte timestamp)
   tx.udp_payload_s = 12 + rtp_payload_size; // the latter ist the payload size
   
   // ---------- now hand over to UDP -----------------

   tx.dp = 30000;
   tx.sp = 30000;
     
   tx.udp_len = 8 + tx.udp_payload_s;
   
   return 0;
}






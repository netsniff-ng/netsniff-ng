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



////////////////////////////////////////////////////////////////////
//
// Layer 4 packet types
// 
// 1. UDP
// 2. ICMP
// 3. TCP
// 
////////////////////////////////////////////////////////////////////

#include "mz.h"
#include "cli.h"


#define MZ_UDP_HELP \
   		"| UDP type: Send raw UDP packets.\n"  \
		"|\n" \
		"| Parameters: \n" \
		"|\n" \
		"|  sp          0-65535\n" \
		"|  dp          0-65535\n" \
		"|  len         0-65535\n" \
		"|  udp_sum     0-65535\n" \
		"|  payload|p   <hex payload>\n" \
		"|\n" \
		"| Optionally the port numbers can be specified as ranges, e. g. \"dp=1023-33700\",\n" \
		"| in which case one packet per port number is sent.\n" \
		"|\n" \
		"| Note that the UDP length must include the header length. If you do NOT specify the len\n" \
		"| parameter (or specify len=0) then Mausezahn will compute the correct length.\n" \
		"|\n" \
		"| Note that all IP parameters can be modified (see IP help, i. e. '-t ip \"help\")\n" \
		"| except that (to avoid confusion) the IP length is 'iplen' and the IP checksum is 'ipsum'.\n" \
		"| Of course all Ethernet fields can also be accessed.\n" \
		"|\n" \
		"\n"


#define MZ_ICMP_HELP \
		"| ICMP type: Send raw ICMP packets.\n" \
		"|\n" \
		"| ARGUMENT SYNTAX: [type] <optional parameters> \n" \
		"| \n" \
		"| Per default an echo reply is sent (type=0, code=0)\n" \
		"|\n" \
		"| TYPE         OPTIONAL PARAMETERS\n" \
		"| ===========  ====================================================================\n" \
		"| Ping:       \"ping\" or \"echoreq\" \n" \
		"|              'id' (0-65535) is the optional identification number\n" \
		"|              'seq' (0-65535) is the optional packet sequence number\n" \
		"|\n" \
		"| Redirect:   \"redir, code=0, gw=192.168.1.10, p=aa:bb:cc\"\n" \
		"|              'gw' (or 'gateway') is the announced gateway, by default your own\n" \
		"|              IP address.\n" \
		"|              'code' can be:\n" \
		"|                  0 ... redirect datagram for the network\n" \
		"|                  1 ... redirect datagram for the host\n" \
		"|                  2 ... redirect datagram for ToS and network\n" \
		"|                  3 ... redirect datagram for ToS and host\n" \
		"|              'p' (or 'payload') is the payload of the ICMP packet, tpyically an IP\n" \
		"|              header. Note that - at the moment - you must prepare this payload by\n"  \
		"|              yourself.\n" \
		"|\n" \
		"| Unreachable \"unreach, code=2\"\n" \
		"|              'code' can be:\n" \
		"|                  0 ... network unreachable\n" \
		"|                  1 ... host unreachable\n" \
		"|                  2 ... protocol unreachable\n" \
		"|                  3 ... port unreachable\n" \
		"|                  4 ... fragmentation needed but DF-bit is set\n" \
		"|                  5 ... source route failed\n" \
		"|\n" \
		"|\n" \
		"| (other ICMP types will follow)\n" \
		"|\n" \
		"\n"

#define MZ_ICMP6_HELP \
		"| ICMPv6 type: Send raw ICMPv6 packets.\n" \
		"|\n" \
		"| Parameters  Values                               Explanation \n"  \
		"| ----------  ------------------------------------ -------------------\n" \
		"|  type       0-255                                ICMPv6 Type\n" \
		"|  code       0-255                                ICMPv6 Code\n" \
		"|  id         0-65535                              optional identification number\n" \
		"|  seq        0-65535                              optional packet sequence number\n" \
		"|  icmpv6_sum 0-65535                              optional checksum\n" \
		"\n"

#define MZ_TCP_HELP \
   		"| TCP type: Send raw TCP packets.\n" \
		"|\n" \
		"| Parameters  Values                               Explanation \n"  \
		"| ----------  ------------------------------------ -------------------\n" \
		"|  sp         0-65535                              Source Port\n" \
		"|  dp         0-65535                              Destination Port\n" \
		"|  flags      fin|syn|rst|psh|ack|urg|ecn|cwr\n" \
		"|  s          0-4294967295                         Sequence Nr.\n" \
		"|  a          0-4294967295                         Acknowledgement Nr.\n" \
		"|  win        0-65535                              Window Size\n" \
		"|  urg        0-65535                              Urgent Pointer\n" \
		"|  tcp_sum    0-65535                              Checksum\n" \
		"|\n" \
		"| The port numbers can be specified as ranges, e. g. \"dp=1023-33700\".\n" \
		"| Multiple flags can be specified such as \"flags=syn|ack|urg\".\n" \
		"|\n" \
		"| Also the sequence number can be specified as a range, for example:\n" \
		"|\n" \
		"|   s=10000-50000 ... send 40000 packets with SQNRs in that range. If the second\n" \
		"|                     value is lower than the first then it is assumed that the\n" \
		"|                     SQNRs should 'wrap around'.\n" \
		"|   ds=30000 ........ use this increment within a SQNR-range.\n" \
		"|\n" \
		"| Note that all IP parameters can be modified (see IP help, i. e. '-t ip \"help\")\n" \
		"| except that (to avoid confusion) the IP length is 'iplen' and the IP checksum is 'ipsum'.\n" \
		"| Of course all Ethernet fields can also be accessed.\n"\
		"|\n"



// Note: If another function specified tx.udp_payload then it must also
// set tx.udp_payload_s AND tx.udp_len = tx.udp_payload_s + 8
libnet_ptag_t  create_udp_packet (libnet_t *l)
{
   libnet_ptag_t  t;
   char argval[MAX_PAYLOAD_SIZE];
   int T; // only an abbreviation for tx.packet_mode 
   int i;
   
   /////////////////////////////
   // Default UDP header fields
   // Already reset in init.c
   /////////////////////////////
   
   T = tx.packet_mode; // >0 means automatic L2 creation
   
   if ( (getarg(tx.arg_string,"help", NULL)==1) && (mode==UDP) )
     {
	if (mz_port)
	  {
	     cli_print(gcli, "%s", MZ_UDP_HELP);
	     return -1;
	  }
	else
	  {
	     
	     fprintf(stderr,"\n" 
		     MAUSEZAHN_VERSION
		     "\n%s", MZ_UDP_HELP);

	     exit(0);
	  }
	
     }

   
   // Evaluate CLI parameters:

   if (getarg(tx.arg_string,"dp", argval)==1)
     {
	if (get_port_range (DST_PORT, argval)) // problem
	  {
	     tx.dp = 0;
	  }
     }
   
   if (getarg(tx.arg_string,"sp", argval)==1)
     {
	if (get_port_range (SRC_PORT, argval)) // problem
	  {
	     tx.sp = 0;
	  }
     }
   

   // Check if hex_payload already specified (externally)
   if (tx.hex_payload_s)
     {
	memcpy( (void*) tx.udp_payload, (void*) tx.hex_payload, tx.hex_payload_s);
	tx.udp_payload_s = tx.hex_payload_s;
     }
   
   if ( (getarg(tx.arg_string,"payload", argval)==1) || (getarg(tx.arg_string,"p", argval)==1))
     {
	tx.udp_payload_s = str2hex (argval, tx.udp_payload, MAX_PAYLOAD_SIZE);
     }
   
   

   if (getarg(tx.arg_string,"sum", argval)==1)
     {
	if (T) fprintf(stderr, " IP_Warning: 'sum' cannot be set in this mode.\n");
	tx.ip_sum = (u_int16_t) str2int(argval);
     }

   if (getarg(tx.arg_string,"udp_sum", argval)==1)
     {
        tx.udp_sum = (u_int16_t) str2int(argval);
     }

   
   if (tx.ascii) // ASCII PAYLOAD overrides hex payload
     {
	strncpy((char *)tx.udp_payload, (char *)tx.ascii_payload, MAX_PAYLOAD_SIZE);
	tx.udp_payload_s = strlen((char *)tx.ascii_payload);
	printf("[%s]\n", tx.ascii_payload);
     }


   /////////
   // Want some padding? The specified number of padding bytes are ADDED to the 
   // payload.
   // (Note the difference in send_eth() where you specified the total number
   // of bytes in the frame)
   // 
   if (tx.padding)
     {
	for (i=0; i<tx.padding; i++)
	  {
	     tx.udp_payload[tx.udp_payload_s+i] = 0x42; // pad with THE ANSWER (why random?)
	  }
	tx.udp_payload_s += tx.padding;
     }

   
   
   ////////
   // The following is VERY IMPORTANT because the ip_payload_s is also set!
   if (getarg(tx.arg_string,"len", argval)==1)
     { 
	tx.udp_len = (u_int16_t) str2int(argval);
	tx.ip_payload_s = tx.udp_len;
     }
   else // len NOT specified by user
     {
	if (tx.udp_len == 0) // len also not specified by another function (e. g. create_dns_packet...)
	  {
	     tx.udp_len = 8 + tx.udp_payload_s;
	     tx.ip_payload_s = tx.udp_len;
	  }
	else // len (and payload and payload_s) has been specified by another function
	  {
	     tx.ip_payload_s = tx.udp_len;
	  }
	
     }
   

   
   t = libnet_build_udp(tx.sp, 
			tx.dp, 
			tx.udp_len, 
		        tx.udp_sum,
			(tx.udp_payload_s) ? tx.udp_payload : NULL,
			tx.udp_payload_s, 
			l, 
			0);
   
   // Checksum overwrite? Libnet IPv6 checksum calculation can't deal with extension headers, we have to do it ourself...
   libnet_toggle_checksum(l, t, (tx.udp_sum || ipv6_mode) ? LIBNET_OFF : LIBNET_ON);
   
   if (t == -1)
     {
	fprintf(stderr, " mz/create_udp_packet: Can't build UDP header: %s\n", libnet_geterror(l));
	exit (0);
     }


   
   return t;
   
}








///////////////////////////////////////////////////
///////////////////////////////////////////////////
///////////////////////////////////////////////////
///////////////////////////////////////////////////
///////////////////////////////////////////////////



libnet_ptag_t  create_icmp_packet (libnet_t *l)
{
   
   libnet_ptag_t  t;
   char argval[MAX_PAYLOAD_SIZE];
   unsigned char *x;

   int i;
   
   enum 
     {
	NONE,
	ECHO_REQUEST,
	REDIRECT,
	UNREACHABLE
     } 
   icmp;           // which ICMP Type? 

   
   if ( (getarg(tx.arg_string,"help", NULL)==1) && (mode==ICMP) )
     {
	if (mz_port)  
	  {
	     cli_print(gcli, "%s", MZ_ICMP_HELP);
	     return -1;
	  }
	else 
	  {
	     
	     fprintf(stderr,"\n" 
		     MAUSEZAHN_VERSION
		     "\n%s", MZ_ICMP_HELP);
	     exit(0);
	  }
     }

 
   /////////////////////////////////////////
   //
   // Which ICMP Type has been specified?
   // 
   // Note: to allow invalid type values we need the enum 'icmp' tp specify the sending function
   //       and the 'type' variable seperately.
   
   if ( (getarg(tx.arg_string,"redirect", NULL)==1) || (getarg(tx.arg_string,"redir", NULL)==1) )
     {
	icmp = REDIRECT;
	tx.icmp_type = ICMP_REDIRECT;
	tx.icmp_code=ICMP_REDIRECT_HOST;
     }
   

   if ( (getarg(tx.arg_string,"ping", NULL)==1) || (getarg(tx.arg_string,"echoreq", NULL)==1) )
     {
	icmp = ECHO_REQUEST;
	tx.icmp_type = ICMP_ECHO;
	tx.icmp_code = 0;
     }

   
   if (getarg(tx.arg_string,"unreach", NULL)==1)
     {
	icmp = UNREACHABLE;
	tx.icmp_type = ICMP_UNREACH;
	tx.icmp_code = 0; // network unreachable
     }


   /////////////////////////////////////////
   //
   // Which parameters have been specified?
   

   if (getarg(tx.arg_string,"type", argval)==1)
     {
	tx.icmp_type = (u_int8_t) str2int(argval);
     }
   
   if (getarg(tx.arg_string,"code", argval)==1)
     {
	tx.icmp_code = (u_int8_t) str2int(argval);
     }
   else
     {
	// Use appropriate defaults depending on ICMP type
     }
   
   
   if (getarg(tx.arg_string,"icmp_sum", argval)==1)
     {
	tx.icmp_chksum = (u_int16_t) str2int(argval);
     }
   
   if ( (getarg(tx.arg_string,"gateway", argval)==1) || (getarg(tx.arg_string,"gw", argval)==1) )
     {
	tx.icmp_gateway = str2ip32 (argval);
     }
   else
     {
	tx.icmp_gateway = tx.ip_src;  // prefer own address
     }


   if (getarg(tx.arg_string,"id", argval)==1)
     {
	tx.icmp_ident = (u_int16_t) str2int(argval);
     }
   
   if (getarg(tx.arg_string,"seq", argval)==1)
     {
	tx.icmp_sqnr = (u_int16_t) str2int(argval);
     }
   
   
   // Check if hex_payload already specified (externally)
   if (tx.hex_payload_s)
     {
	memcpy( (void*) tx.icmp_payload, (void*) tx.hex_payload, tx.hex_payload_s);
	tx.icmp_payload_s = tx.hex_payload_s;
     }
   
   
   if ( (getarg(tx.arg_string,"payload", argval)==1) || (getarg(tx.arg_string,"p", argval)==1))
     {
	tx.icmp_payload_s = str2hex (argval, tx.icmp_payload, MAX_PAYLOAD_SIZE);
     }
   else
     {
	tx.icmp_payload_s = 0;
     }
   
   
   if (tx.ascii) // ASCII PAYLOAD overrides hex payload
     {
	strncpy((char *)tx.icmp_payload, (char *)tx.ascii_payload, MAX_PAYLOAD_SIZE);
	tx.icmp_payload_s = strlen((char *)tx.ascii_payload);
     }


   /////////
   // Want some padding? The specified number of padding bytes are ADDED to the 
   // payload.
   // (Note the difference in send_eth() where you specified the total number
   // of bytes in the frame)
   // 
   if (tx.padding)
     {
	for (i=0; i<tx.padding; i++)
	  {
	     tx.icmp_payload[tx.icmp_payload_s+i] = 0x42; // pad with THE ANSWER (why random?)
	  }
	tx.icmp_payload_s += tx.padding;
     }

   
   ////////////////////////////////////////////////////////////////////////////////////////////
   //
   // Now determine which type of ICMP packet to send.
   // 
   // NOTE: Every section (icmp-type) must provide
   //    
   //        1. a build function
   //        2. tx.ip_payload_s which indicates the whole ICMP packet size
   //        3. tx.icmp_verbose_string containing details about the ICMP packet (verbose mode)
   // 
   ////////////////////////////////////////////////////////////////////////////////////////////
   
   switch (icmp)
     {
      case REDIRECT: // +++++++++++++++
	t = libnet_build_icmpv4_redirect (tx.icmp_type, 
					  tx.icmp_code, 
					  tx.icmp_chksum,
					  tx.icmp_gateway, 
					  (tx.icmp_payload_s) ? tx.icmp_payload : NULL,
					  tx.icmp_payload_s,
					  l,
					  0);
	tx.ip_payload_s = LIBNET_ICMPV4_REDIRECT_H + tx.icmp_payload_s;  // for send_ip
	if (verbose)
	  {
	     x = (unsigned char*) &tx.icmp_gateway;
	     sprintf(tx.icmp_verbose_txt,"ICMP Redirect, GW=%u.%u.%u.%u",
		     *(x),*(x+1),*(x+2),*(x+3));
	  }
	break; // ++++++++++++++++++++++
      case NONE:
      case ECHO_REQUEST:
	t = libnet_build_icmpv4_echo(tx.icmp_type, 
				     tx.icmp_code, 
				     tx.icmp_chksum,
				     tx.icmp_ident,
				     tx.icmp_sqnr, 
				     (tx.icmp_payload_s) ? tx.icmp_payload : NULL,
				     tx.icmp_payload_s,
				     l, 
				     0);
	tx.ip_payload_s = LIBNET_ICMPV4_REDIRECT_H + tx.icmp_payload_s;  // for send_ip
	if (verbose)
	  {
	     if (icmp == NONE)
		sprintf(tx.icmp_verbose_txt,"ICMP Type %u Code %u\n",tx.icmp_type,tx.icmp_code);
	     else
		sprintf(tx.icmp_verbose_txt,"ICMP Echo Request (id=%u seq=%u)\n",tx.icmp_ident,tx.icmp_sqnr);
	  }
	break; // ++++++++++++++++++++++
      case UNREACHABLE:
	t = libnet_build_icmpv4_unreach(tx.icmp_type,
					tx.icmp_code, 
					tx.icmp_chksum,
					(tx.icmp_payload_s) ? tx.icmp_payload : NULL,
					tx.icmp_payload_s,
					l, 
					0);
	if (verbose)
	  {
	     sprintf(tx.icmp_verbose_txt,"ICMP unreachable (code=%u)\n",tx.icmp_code);
	  }
	break; // ++++++++++++++++++++++
      default:
	(void) fprintf(stderr," mz/icmp: unknown mode! Stop.\n");
	return (1);
     }

   libnet_toggle_checksum(l, t, tx.icmp_chksum ? LIBNET_OFF : LIBNET_ON);

   if (t == -1)
     {
	fprintf(stderr, " mz/create_icmp_packet: Can't build ICMP header: %s\n", libnet_geterror(l));
	exit (0);
     }

   
   return t;
}

libnet_ptag_t  create_icmp6_packet (libnet_t *l)
{
   libnet_ptag_t  t;
   char argval[MAX_PAYLOAD_SIZE];

   int i;
   tx.icmp_ident = 0;
   tx.icmp_sqnr = 0;

   if ( (getarg(tx.arg_string,"help", NULL)==1) && (mode==ICMP) )
     {
	if (mz_port)
	  {
	     cli_print(gcli, "%s", MZ_ICMP6_HELP);
	     return -1;
	  }
	else
	  {
	     fprintf(stderr,"\n"
		     MAUSEZAHN_VERSION
		     "\n%s", MZ_ICMP6_HELP);
	     exit(0);
	  }
     }


   /////////////////////////////////////////
   //
   // Which parameters have been specified?


   if (getarg(tx.arg_string,"type", argval)==1)
     {
	tx.icmp_type = (u_int8_t) str2int(argval);
     }

   if (getarg(tx.arg_string,"code", argval)==1)
     {
	tx.icmp_code = (u_int8_t) str2int(argval);
     }

   if (getarg(tx.arg_string,"id", argval)==1)
     {
	tx.icmp_ident = (u_int16_t) str2int(argval);
     }

   if (getarg(tx.arg_string,"seq", argval)==1)
     {
	tx.icmp_sqnr = (u_int16_t) str2int(argval);
     }

   if (getarg(tx.arg_string,"icmpv6_sum", argval)==1)
     {
	tx.icmp_chksum = (u_int16_t) str2int(argval);
     }

   // Check if hex_payload already specified (externally)
   if (tx.hex_payload_s)
     {
	memcpy( (void*) tx.icmp_payload, (void*) tx.hex_payload, tx.hex_payload_s);
	tx.icmp_payload_s = tx.hex_payload_s;
     }

   if ( (getarg(tx.arg_string,"payload", argval)==1) || (getarg(tx.arg_string,"p", argval)==1))
     {
	tx.icmp_payload_s = str2hex (argval, tx.icmp_payload, MAX_PAYLOAD_SIZE);
     }
   else
     {
	tx.icmp_payload_s = 0;
     }

   if (tx.ascii) // ASCII PAYLOAD overrides hex payload
     {
	strncpy((char *)tx.icmp_payload, (char *)tx.ascii_payload, MAX_PAYLOAD_SIZE);
	tx.icmp_payload_s = strlen((char *)tx.ascii_payload);
     }

   /////////
   // Want some padding? The specified number of padding bytes are ADDED to the
   // payload.
   // (Note the difference in send_eth() where you specified the total number
   // of bytes in the frame)
   //
   if (tx.padding)
     {
	for (i=0; i<tx.padding; i++)
	  {
	     tx.icmp_payload[tx.icmp_payload_s+i] = 0x42; // pad with THE ANSWER (why random?)
	  }
	tx.icmp_payload_s += tx.padding;
     }

   sprintf(tx.icmp_verbose_txt,"ICMPv6 Type %u Code %u\n",tx.icmp_type,tx.icmp_code);

   t = libnet_build_icmpv4_echo (tx.icmp_type,
				    tx.icmp_code,
				    tx.icmp_chksum,
				    tx.icmp_ident,
				    tx.icmp_sqnr,
				    tx.icmp_payload_s ? tx.icmp_payload : NULL,
				    tx.icmp_payload_s,
				    l,
				    0);
   tx.ip_payload_s = LIBNET_ICMPV6_H + tx.icmp_payload_s;  // for send_ip

   // Libnet IPv6 checksum calculation can't deal with extension headers, we have to do it ourself...
   libnet_toggle_checksum(l, t, (tx.icmp_chksum || ipv6_mode) ? LIBNET_OFF : LIBNET_ON);

   if (t == -1)
     {
	fprintf(stderr, " mz/create_icmp_packet: Can't build ICMPv6 header: %s\n", libnet_geterror(l));
	exit (0);
     }

   return t;
}



///////////////////////////////////////////////////
///////////////////////////////////////////////////
///////////////////////////////////////////////////
///////////////////////////////////////////////////
///////////////////////////////////////////////////


// Note: If another function specified tx.tcp_payload then it must also
// set tx.tcp_payload_s AND tx.tcp_len = tx.tcp_payload_s + 20
libnet_ptag_t  create_tcp_packet (libnet_t *l)
{
   libnet_ptag_t  t, t2;
   char argval[MAX_PAYLOAD_SIZE], *dummy1, *dummy2;
   int T; // only an abbreviation for tx.packet_mode 
   int i;
   
   u_int8_t tcp_default_options[] = 
     {
	  0x02, 0x04, 0x05, 0xac,                                     // MSS
	  0x04, 0x02,                                                 // SACK permitted
	  0x08, 0x0a, 0x19, 0x35, 0x90, 0xc3, 0x00, 0x00, 0x00, 0x00, // Timestamps
	  0x01,                                                       // NOP
	  0x03, 0x03, 0x05                                            // Window Scale 5
     };
   
	  
   
   /////////////////////////////
   // Default TCP header fields
   // Already reset in init.c
   /////////////////////////////
   
   T = tx.packet_mode; // >0 means automatic L2 creation
   
   if ( (getarg(tx.arg_string,"help", NULL)==1) && (mode==TCP) )
     {
	if (mz_port)
	  {
	     cli_print(gcli, "%s", MZ_TCP_HELP);
	     return -1;
	  }
	else
	  {
	     fprintf(stderr,"\n" 
		     MAUSEZAHN_VERSION
		     "\n%s", MZ_TCP_HELP);
	     exit(0);
	  }
     }

 
   // Evaluate CLI parameters:

   if (getarg(tx.arg_string,"dp", argval)==1)
     {
	if (get_port_range (DST_PORT, argval)) // problem
	  {
	     tx.dp = 0;
	  }
     }

   
   if (getarg(tx.arg_string,"sp", argval)==1)
     {
	if (get_port_range (SRC_PORT, argval)) // problem
	  {
	     tx.sp = 0;
	  }
     }
   
   
   if (getarg(tx.arg_string,"s", argval)==1)
     {
	//check whether a range has been specified:
	dummy1 = strtok(argval, "-");
	tx.tcp_seq = (u_int32_t) str2int (dummy1);
	if (  (dummy2 = strtok(NULL, "-")) == NULL ) // no additional value
	  {
	     tx.tcp_seq_stop = tx.tcp_seq;
	  }
	else // range
	  {
	     tx.tcp_seq_stop = (u_int32_t) str2int (dummy2);
	     tx.tcp_seq_start = tx.tcp_seq;          // initially tcp_seq = tcp_seq_start
	     tx.tcp_seq_delta = 1;                   // an initialization only in case 'ds' not specified
	  }
     }
   
   if (getarg(tx.arg_string,"ds", argval)==1)
     {
	tx.tcp_seq_delta = (u_int32_t) str2int (argval);
     }
   
   if (getarg(tx.arg_string,"a", argval)==1)
     {
	tx.tcp_ack = (u_int32_t) str2int (argval);
     }
   
   if (getarg(tx.arg_string,"win", argval)==1)
     {
	tx.tcp_win = (u_int16_t) str2int (argval);
     }
   
   if (getarg(tx.arg_string,"urg", argval)==1)
     {
	tx.tcp_urg = (u_int16_t) str2int (argval);
     }
   

   if ( (getarg(tx.arg_string,"flags", argval)==1) ||
	(getarg(tx.arg_string,"flag", argval)==1) ) // because everybody confuses this
     {
	if (get_tcp_flags(argval)) // problem
	  {
	     tx.tcp_control=2; // Assume SYN as default
	  }
     }

   if (getarg(tx.arg_string,"tcp_sum", argval)==1)
     {
        tx.tcp_sum = (u_int16_t) str2int(argval);
     }

   // Check if hex_payload already specified (externally)
   if (tx.hex_payload_s)
     {
	memcpy( (void*) tx.tcp_payload, (void*) tx.hex_payload, tx.hex_payload_s);
	tx.tcp_payload_s = tx.hex_payload_s;
     }
   
   
   if ( (getarg(tx.arg_string,"payload", argval)==1) || (getarg(tx.arg_string,"p", argval)==1))
     {
	tx.tcp_payload_s = str2hex (argval, tx.tcp_payload, MAX_PAYLOAD_SIZE);
     }
   

   if (tx.ascii) // ASCII PAYLOAD overrides hex payload
     {
	strncpy((char *)tx.tcp_payload, (char *)tx.ascii_payload, MAX_PAYLOAD_SIZE);
	tx.tcp_payload_s = strlen((char *)tx.ascii_payload);
	tx.tcp_len = 20 + tx.tcp_payload_s;   // only needed by libnet to calculate checksum
	tx.ip_payload_s = tx.tcp_len;         // for create_ip_packet
     }
   
   
   
   /////////
   // Want some padding? The specified number of padding bytes are ADDED to the 
   // payload.
   // (Note the difference in send_eth() where you specified the total number
   // of bytes in the frame)
   // 
   if (tx.padding)
     {
	for (i=0; i<tx.padding; i++)
	  {
	     tx.tcp_payload[tx.tcp_payload_s+i] = 0x42; // pad with THE ANSWER (why random?)
	  }
	tx.tcp_payload_s += tx.padding;

     }


   
   tx.tcp_len = 20 + tx.tcp_payload_s;       // only needed by libnet to calculate checksum
   tx.ip_payload_s = tx.tcp_len;         // for create_ip_packet

   if (tx.tcp_control & 0x02) // packets with syn require an MSS option 
     {
	t2 = libnet_build_tcp_options(tcp_default_options,
				     20, 
				     l, 
				     0);
	
	if (t2 == -1)
	  {
	     fprintf(stderr, " mz/create_tcp_packet: Can't build TCP options: %s\n", libnet_geterror(l));
	     exit (0);
	  }

	tx.tcp_len += 20;
	tx.tcp_offset = 10;
	tx.ip_payload_s = tx.tcp_len;	// for create_ip_packet
	tx.tcp_sum_part = libnet_in_cksum((u_int16_t *) tcp_default_options, 20);
     }
   else
     {
       tx.tcp_offset = 5;
       tx.tcp_sum_part = 0;
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
			 0);

   
   
   // Libnet IPv6 checksum calculation can't deal with extension headers, we have to do it ourself...
   libnet_toggle_checksum(l, t, (tx.tcp_sum || ipv6_mode) ? LIBNET_OFF : LIBNET_ON);
   
   if (t == -1)
     {
	fprintf(stderr, " mz/create_tcp_packet: Can't build TCP header: %s\n", libnet_geterror(l));
	exit (0);
     }

   
   return t;
}

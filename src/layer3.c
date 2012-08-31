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
//    This sections contains functions to send various L3-based PDUs such as
//    
//     * IP
//     
//     (ahem, yes this is currently all here...)
//     
// ***************************************************************************

#include "mz.h"
#include "cli.h"

#define MZ_IP_HELP \
   		"| IP type: Send raw IP packets.\n" \
		"|\n" \
		"| Supports L3 mode (automatic L2 creation) or 'L2-L3' mode (MAC addresses must be provided).\n" \
		"| In L3 mode the IP checksum and length cannot be manipulated to wrong values (currently).\n" \
		"| The L2-L3 mode is activated when specifying any MAC addresses on the command line\n" \
		"| (options -a, -b). \n" \
		"|\n" \
		"| The IP addresses can be specified via the -A and -B options, which identify the source\n" \
		"| and destination addresses, respectively. A dotted decimal notation, an IP range, or a\n" \
		"| FQDN can be used. The source address can also be random (-A rand).\n" \
		"|\n" \
		"| ARGUMENT SYNTAX:  [<comma separated parameter list>]\n" \
		"|\n" \
		"| Parameters:\n" \
		"|\n" \
		"|  len      0-65535        Only accessible in L2 mode\n" \
		"|  sum      0-65535        Only accessible in L2 mode (0 means auto-calculation)\n" \
		"|  tos      00-ff          Full 8-bit control via hex input (use this also for ECN bits).\n" \
		"|  dscp     0-63           Allows easier specification of DSCP (PHB and Drop Propability)\n" \
		"|  ttl      0-255\n" \
		"|  proto    0-255\n" \
		"|  frag     0-65535        Includes flags (MSB) and offset (LSB)\n" \
     		"|  df                      Sets the \"Don't Fragment\" flag\n" \
		"|  mf                      Sets the \"More Fragments\" flag\n" \
		"|  rf                      Sets the reserved flag.\n" \
		"|  id       0-65535\n" \
		"|  loose    <addresses>    Loose Source Route (LSR) option; specify a sequence of hops\n" \
		"|                          using the notation: 1.1.1.1+2.2.2.2+3.3.3.3+...\n" \
		"|  strict   <addresses>    Strict Source Route (SSR) option; same address notation as above\n" \
		"|  option   <hex_string>   Specify any IP option using a hexadecimal string (aa:bb:cc:...)\n" \
		"|\n" \
		"| Additionally the Ethertype can be specified:\n" \
		"|\n" \
		"|  ether_type 00:00-ff:ff  Only accessible in L2 mode (default = 08:00 = IPv4)\n" \
		"|  \n"


#define MZ_IP6_HELP \
   		"| IP type: Send raw IPv6 packets.\n" \
		"|\n" \
		"| Supports L3 mode (automatic L2 creation) or 'L2-L3' mode (MAC addresses must be provided).\n" \
		"| In L3 mode the IP checksum and length cannot be manipulated to wrong values (currently).\n" \
		"| The L2-L3 mode is activated when specifying any MAC addresses on the command line\n" \
		"| (options -a, -b). \n" \
		"|\n" \
		"| ARGUMENT SYNTAX:  [<comma separated parameter list>]\n" \
		"|\n" \
		"| Parameters:\n" \
		"|\n" \
		"|  len      0-65535        Only accessible in L2 mode\n" \
		"|  sum      0-65535        Only accessible in L2 mode (0 means auto-calculation)\n" \
		"|  tos      00-ff          Full 8-bit control via hex input (use this also for ECN bits).\n" \
		"|  dscp     0-63           Allows easier specification of DSCP (PHB and Drop Propability)\n" \
		"|  flow     0-1048575      Flow label\n" \
		"|  hop      0-255          Hop limit\n" \
		"|  next     0-255          Next protocol or header type\n" \
		"|  frag     0-65535        Includes flags (MSB) and offset (LSB)\n" \
		"|  mf                      Sets the \"More Fragments\" flag\n" \
		"|  frag_res1               Sets the reserved flag 1.\n" \
		"|  frag_res2               Sets the reserved flag 2.\n" \
		"|  id       0-65535	    Fragment ID\n" \
		"|  loose    <addresses>    Source Routing Header\n" \
		"|  rtype    0,2            Source Routing Type: 0 (Deprecated in RFC 5095) or 2 for Mobile IP\n" \
		"|  segments 0-255          Number of route segments left, used by RH0\n" \
		"|\n" \
		"| Additionally the Ethertype can be specified:\n" \
		"|\n" \
		"|  ether_type 00:00-ff:ff  Only accessible in L2 mode (default = 86:dd = IPv6)\n" \
		"|  \n"


// Only used to simplify initialization of libnet
// Return pointer to context
libnet_t* get_link_context()
{
   libnet_t * l;
   char errbuf[LIBNET_ERRBUF_SIZE];

   // Don't open context if only a help text is requested
   if  (getarg(tx.arg_string,"help", NULL)==1)
     {
	return NULL;
     }
   
   
   if (tx.packet_mode)  
     {  // Let libnet create an appropriate Ethernet frame
	if (ipv6_mode)
	  l = libnet_init (LIBNET_RAW6_ADV, tx.device, errbuf);
	else
	  l = libnet_init (LIBNET_RAW4_ADV, tx.device, errbuf);
     }
   else // User specified Ethernet header details (src or dst)
     {
	l = libnet_init (LIBNET_LINK_ADV, tx.device, errbuf);
     }
   
   if (l == NULL)
     {
	fprintf(stderr, "%s", errbuf);
	exit(EXIT_FAILURE);
     }
   return l;
}


//////////////////////////////////////////////////////////////////////////////
// Prepare IP packet
libnet_ptag_t  create_ip_packet (libnet_t *l)
{
   libnet_ptag_t  t; 
   char argval[MAX_PAYLOAD_SIZE];
   int i, T; // only an abbreviation for tx.packet_mode 

   if (ipv6_mode)
     return create_ip6_packet(l);

   // Default IP header fields
   tx.ip_len   = LIBNET_IPV4_H;  // Don't forget to add payload length
   tx.ip_id    = 0;
   tx.ip_frag  = 0;              // Flags and Offset !!!
   tx.ip_sum   = 0;              // default: automatically calculate checksum
   tx.ip_tos   = 0;
   tx.ip_ttl   = 255;

   
   // temporary variables
   unsigned int dummy;
   size_t len;
   char *s;

   
   T = tx.packet_mode; // >0 means automatic L2 creation
   
   if ( (getarg(tx.arg_string,"help", NULL)==1) && (mode==IP) )
     {
	if (mz_port)
	  {
	     cli_print(gcli, "%s", MZ_IP_HELP);
	     return -1;
	  }
	else
	  {
	     
	     fprintf(stderr,"\n" 
		     MAUSEZAHN_VERSION
		     "\n%s", MZ_IP_HELP);

	     exit(0);
	  }
     }

   // Check if hex_payload already specified (externally)
   if (tx.hex_payload_s)
     {
	memcpy( (void*) tx.ip_payload, (void*) tx.hex_payload, tx.hex_payload_s);
	tx.ip_payload_s = tx.hex_payload_s;
     }

   
   // Evaluate CLI parameters:

   if ( (getarg(tx.arg_string,"payload", argval)==1) || (getarg(tx.arg_string,"p", argval)==1))
     {
        if (mode==IP)
	  tx.ip_payload_s = str2hex (argval, tx.ip_payload, MAX_PAYLOAD_SIZE);
     }
   // else payload has been specified as ASCII text via -P option
   
   
   // NOTE: If 'mode' is NOT IP (e. g. UDP or TCP or something else)
   // then the argument 'len' and 'sum' is NOT meant for the IP header!
   // Instead the user can use 'iplen' and 'ipsum'.
   if (mode==IP)
     {
	if (getarg(tx.arg_string,"len", argval)==1)
	  {
	     if (T) fprintf(stderr, " IP_Warning: 'len' cannot be set in this mode.\n");
	     tx.ip_len = (u_int16_t) str2int(argval);
	  }
	else
	  {
	     tx.ip_len = LIBNET_IPV4_H + tx.ip_payload_s;
	  }
	
	if (getarg(tx.arg_string,"sum", argval)==1)
	  {
	     if (T) fprintf(stderr, " IP_Warning: 'sum' cannot be set in this mode.\n");
	     tx.ip_sum = (u_int16_t) str2int(argval);
	  }
     }
   else // mode is NOT IP
     {
	if (getarg(tx.arg_string,"iplen", argval)==1)
	  {
	     if (T) fprintf(stderr, " IP_Warning: 'len' cannot be set in this mode.\n");
	     tx.ip_len = (u_int16_t) str2int(argval);
	  }
	else
	  {
	     tx.ip_len = LIBNET_IPV4_H + tx.ip_payload_s;
	  }

	if (getarg(tx.arg_string,"ipsum", argval)==1)
	  {
	     if (T) fprintf(stderr, " IP_Warning: 'sum' cannot be set in this mode.\n");
	     tx.ip_sum = (u_int16_t) str2int(argval);
	  }
     }
   
   
   if (getarg(tx.arg_string,"tos", argval)==1)
     {
	tx.ip_tos = (u_int8_t) strtol(argval,NULL,16);
	dummy = (unsigned int) strtol(argval,NULL,16);
	if (dummy > 255) fprintf(stderr, " IP_Warning: 'tos' too big, adjusted to LSBs\n");
     }
   
   if (getarg(tx.arg_string,"dscp", argval)==1)
     {
	dummy = (unsigned int) str2int(argval);
	if (dummy > 63) 
	  { 
	     fprintf(stderr, " IP_Warning: 'dscp' too big, adjusted to 63\n");
	     dummy = 63;
	  }
	tx.ip_tos = (u_int8_t) dummy*4;
     }
   
   if (getarg(tx.arg_string,"id", argval)==1)
     {
	tx.ip_id = (u_int16_t) str2int(argval);
     }

   if (getarg(tx.arg_string,"frag", argval)==1)
     {
	tx.ip_frag = (u_int16_t) str2int(argval);
     }
   
   if (getarg(tx.arg_string,"df", NULL)==1)
     {
	tx.ip_frag |= 0x4000; 
     }
   
   if (getarg(tx.arg_string,"mf", NULL)==1)
     {
	tx.ip_frag |= 0x2000; 
     }
   
   if (getarg(tx.arg_string,"rf", NULL)==1)
     {
	tx.ip_frag |= 0x8000; 
     }
   
   
   if (getarg(tx.arg_string,"ttl", argval)==1)
     {
	tx.ip_ttl = (u_int8_t) str2int(argval);
     }
   
   if (getarg(tx.arg_string,"proto", argval)==1)
     {
	tx.ip_proto = (u_int8_t) str2int(argval);
     }


   if ((tx.ascii)&&(mode==IP)) // ASCII PAYLOAD overrides hex payload
     {
	strncpy((char *)tx.ip_payload, (char *)tx.ascii_payload, MAX_PAYLOAD_SIZE);
	tx.ip_payload_s = strlen((char *)tx.ascii_payload);
	tx.ip_len += tx.ip_payload_s;
     }

   
   /////////
   // Want some padding? The specified number of padding bytes are ADDED to the 
   // payload. Note that this is only evaluated if we are in IP mode because
   // UDP and TCP already might have been padded and set the ip_payload_s.
   // (Note the difference in send_eth() where you specified the total number
   // of bytes in the frame)
   // 
   if ((tx.padding)&&(mode==IP))
     {
	for (i=0; i<tx.padding; i++)
	  {
	     tx.ip_payload[tx.ip_payload_s+i] = 0x42; // pad with THE ANSWER (why random?)
	  }
	tx.ip_payload_s += tx.padding;
	tx.ip_len += tx.padding;
     }

   

     
   
   // Loose and Strict Source Route 
   // See RFC 791 for most the detailed description
   // 
   if ( (getarg(tx.arg_string,"loose", argval)==1) ||
	(getarg(tx.arg_string,"strict", argval)==1) )
     {
	len = strlen(argval);
	
	if (len<7) // not even a single dotted decimal IP address given!
	  {
	     fprintf(stderr, " IP_Warning: Source route option requires at least one IP address!\n");
	     // But we allow this :-)
	  }

	
	// determine how many IP addresses have been specified
	dummy=0;
	for (i=0; i<len; i++)
	  {
	     if (ispunct(*(argval+i))) dummy++ ;
	  }
	dummy = (dummy+1) / 4; // the number of IP addresses
	
	// Specify: type code, length, pointer
	if (getarg(tx.arg_string,"loose", argval)==1)
	  {
	     tx.ip_option[0] = 131; // loose source route
	  }
	else
	  {
	     tx.ip_option[0] = 137; // strict source route
	  }
	tx.ip_option[1] = 3+(dummy*4); // length
	tx.ip_option[2] = 4; // Use first IP address as next hop
	//tx.ip_option[2] = 4+4*dummy;   // smallest pointer, points to first address, which is
	                               // the 4th byte within this option
	
	tx.ip_option_s = 3;
	s = strtok(argval, ".+-:;/>");
	do
	  {
	     len--;
	     tx.ip_option[tx.ip_option_s] = (u_int8_t) str2int(s);
	     tx.ip_option_s++;
	  } while ( (s=strtok(NULL, ".+-:;/>")) != NULL );

	tx.ip_option_s++; // EOL
	
	// add empty space for record route: //// NONSENSE? /////
	/*
	 for (i=0; i<(4*dummy); i++)
	 {
	 tx.ip_option[tx.ip_option_s] = 0x00;
	 tx.ip_option_s++;
	 }
	 */
     }
   
   
   
   // Allow any IP option specified as hex string
   // An option can be a single byte or consist of multiple bytes in which case
   // a length field is needed, see RFC 791.
   if (getarg(tx.arg_string,"option", argval)==1)
     {
	// check if conflicting with argument "loose" or "strict"
	if (tx.ip_option_s)
	  {
	     fprintf(stderr, " IP_Error: Another IP option already specified. Please check your arguments.\n");
	     exit(1);
	  }
	
	tx.ip_option_s = str2hex (argval, tx.ip_option, 1023);
     }
   
   
   
   if (tx.ip_option_s)
     {
	t = libnet_build_ipv4_options (tx.ip_option,
				       tx.ip_option_s, 
				       l,
				       0);
	tx.ip_len += tx.ip_option_s;
     }
   
   
   ///////
   // Did the user specify ANY payload? We require at least one byte!
   /*
   if (!tx.ip_payload_s)
     {
	tx.ip_payload[0] = 0x42;
	tx.ip_payload_s = 1;
     }
   */
   
   t = libnet_build_ipv4 (tx.ip_len,
			  tx.ip_tos, 
			  tx.ip_id, 
			  tx.ip_frag,
			  tx.ip_ttl, 
			  tx.ip_proto,
			  tx.ip_sum, 
			  tx.ip_src, // init.c defaults this to own SA
			  tx.ip_dst, // init.c defaults this to 255.255.255.255
			  (mode==IP) ? (tx.ip_payload_s) ? tx.ip_payload : NULL : NULL,  // if e.g. mode=UDP ignore payload argument
			  (mode==IP) ? tx.ip_payload_s : 0,
			  
			  /*
			  (mode==IP) ? tx.ip_payload : NULL,  // if e.g. mode=UDP ignore payload argument
			  (mode==IP) ? tx.ip_payload_s : 0,
			   */
			  l, 
			  0);


   if (t == -1)
     {
	fprintf(stderr, " mz/create_ip_packet: Can't build IP header: %s\n", libnet_geterror(l));
	exit (0);
     }

   
   return t;
   
}

//////////////////////////////////////////////////////////////////////////////
// Prepare IPv6 packet
libnet_ptag_t  create_ip6_packet (libnet_t *l)
{
   libnet_ptag_t  t;
   char argval[MAX_PAYLOAD_SIZE];
   int i, T; // only an abbreviation for tx.packet_mode

   // Default IP header fields
   tx.ip_len   = 0;
   tx.ip_id    = 0;
   tx.ip6_segs = 0;
   tx.ip6_rtype = 0;
   tx.ip6_id   = 0;
   tx.ip_frag  = 0;              // Flags and Offset !!!
   tx.ip_tos   = 0;
   tx.ip_ttl   = 255;

   // temporary variables
   unsigned int dummy;
   size_t len;
   char *s;

   T = tx.packet_mode; // >0 means automatic L2 creation

   if ( (getarg(tx.arg_string,"help", NULL)==1) && (mode==IP) )
     {
	if (mz_port)
	  {
	     cli_print(gcli, "%s", MZ_IP6_HELP);
	     return -1;
	  }
	else
	  {
	     fprintf(stderr,"\n"
		     MAUSEZAHN_VERSION
		     "\n%s", MZ_IP6_HELP);

	     exit(0);
	  }
     }

   // Check if hex_payload already specified (externally)
   if (tx.hex_payload_s)
     {
	memcpy( (void*) tx.ip_payload, (void*) tx.hex_payload, tx.hex_payload_s);
	tx.ip_payload_s = tx.hex_payload_s;
     }

   // Evaluate CLI parameters:
   if ( (getarg(tx.arg_string,"payload", argval)==1) || (getarg(tx.arg_string,"p", argval)==1))
     {
        if (mode==IP)
	  tx.ip_payload_s = str2hex (argval, tx.ip_payload, MAX_PAYLOAD_SIZE);
     }
   // else payload has been specified as ASCII text via -P option

   // NOTE: If 'mode' is NOT IP (e. g. UDP or TCP or something else)
   // then the argument 'len' and 'sum' is NOT meant for the IP header!
   // Instead the user can use 'iplen' and 'ipsum'.
   if (mode==IP)
     {
	if (getarg(tx.arg_string,"len", argval)==1)
	  {
	     if (T) fprintf(stderr, " IP_Warning: 'len' cannot be set in this mode.\n");
	     tx.ip_len = (u_int16_t) str2int(argval);
	  }
	else
	  {
	     tx.ip_len += tx.ip_payload_s;
	  }
     }
   else // mode is NOT IP
     {
	if (getarg(tx.arg_string,"iplen", argval)==1)
	  {
	     if (T) fprintf(stderr, " IP_Warning: 'len' cannot be set in this mode.\n");
	     tx.ip_len = (u_int16_t) str2int(argval);
	  }
	else
	  {
	     tx.ip_len += tx.ip_payload_s;
	  }
     }


   if (getarg(tx.arg_string,"tos", argval)==1)
     {
	tx.ip_tos = (u_int8_t) strtol(argval,NULL,16);
	dummy = (unsigned int) strtol(argval,NULL,16);
	if (dummy > 255) fprintf(stderr, " IP_Warning: 'tos' too big, adjusted to LSBs\n");
     }

   if (getarg(tx.arg_string,"flow", argval)==1)
     {
	dummy = (unsigned int) strtol(argval,NULL,16);
	if (dummy > 1048575)
	  {
	    fprintf(stderr, " IP_Warning: 'flow label' too big, adjusted to 0xfffff\n");
	    dummy = 0xfffff;
	  }
        tx.ip_flow = dummy;
     }

   if (getarg(tx.arg_string,"dscp", argval)==1)
     {
	dummy = (unsigned int) str2int(argval);
	if (dummy > 63)
	  {
	     fprintf(stderr, " IP_Warning: 'dscp' too big, adjusted to 63\n");
	     dummy = 63;
	  }
	tx.ip_tos = (u_int8_t) dummy*4;
     }

   if (getarg(tx.arg_string,"id", argval)==1)
     {
	  tx.ip6_id = str2int(argval);
     }

   if (getarg(tx.arg_string,"frag", argval)==1)
     {
          tx.ip_frag = ((u_int16_t) str2int(argval)) << 3;
     }

   if (getarg(tx.arg_string,"mf", NULL)==1)
     {
	  tx.ip_frag |= 0x0001;
     }

   if (getarg(tx.arg_string,"frag_res1", NULL)==1)
     {
          tx.ip_frag |= 0x0002;
     }

   if (getarg(tx.arg_string,"frag_res2", NULL)==1)
     {
          tx.ip_frag |= 0x0004;
     }

   if (getarg(tx.arg_string,"hop", argval)==1)
     {
	tx.ip_ttl = (u_int8_t) str2int(argval);
     }

   if (getarg(tx.arg_string,"next", argval)==1)
     {
	tx.ip_proto = (u_int8_t) str2int(argval);
     }
   else if (mode==IP)
     {
	tx.ip_proto = 59; // No Next Header for IPv6
     }


   if ((tx.ascii)&&(mode==IP)) // ASCII PAYLOAD overrides hex payload
     {
	strncpy((char *)tx.ip_payload, (char *)tx.ascii_payload, MAX_PAYLOAD_SIZE);
	tx.ip_payload_s = strlen((char *)tx.ascii_payload);
	tx.ip_len += tx.ip_payload_s;
     }


   /////////
   // Want some padding? The specified number of padding bytes are ADDED to the
   // payload. Note that this is only evaluated if we are in IP mode because
   // UDP and TCP already might have been padded and set the ip_payload_s.
   // (Note the difference in send_eth() where you specified the total number
   // of bytes in the frame)
   //
   if ((tx.padding)&&(mode==IP))
     {
	for (i=0; i<tx.padding; i++)
	  {
	     tx.ip_payload[tx.ip_payload_s+i] = 0x42; // pad with THE ANSWER (why random?)
	  }
	tx.ip_payload_s += tx.padding;
	tx.ip_len += tx.padding;
     }

   if (tx.ip6_id) {
     t = libnet_build_ipv6_frag (tx.ip_proto,
				 0,
				 htons(tx.ip_frag),
				 htonl(tx.ip6_id),
				 (mode==IP) ? (tx.ip_payload_s) ? tx.ip_payload : NULL : NULL,
				 (mode==IP) ? tx.ip_payload_s : 0,
				 l,
				 0);
     tx.ip_len += LIBNET_IPV6_FRAG_H;
     tx.ip_payload_s = 0;
     tx.ip_proto = LIBNET_IPV6_NH_FRAGMENT;
   }

   // See RFC 2460 Routing Header
   //
   if ( (getarg(tx.arg_string,"segments", argval)==1) )
     {
        dummy = (unsigned int) str2int(argval);
        if (dummy > 255) {
          fprintf(stderr, " IP_Error: Maximal Routing Segments are 255!\n");
          exit(1);
        }
        tx.ip6_segs = dummy;
     }

   if ( (getarg(tx.arg_string,"rtype", argval)==1) )
     {
	dummy = (unsigned int) str2int(argval);
	if (dummy > 255) {
	  fprintf(stderr, " IP_Error: Maximum Routing Type is 255!\n");
	  exit(1);
	}
	tx.ip6_segs = dummy;
     }

   if ( (getarg(tx.arg_string,"loose", argval)==1) )
     {
	// Fill reserved
	memset(tx.ip_option, 0, 4);
	tx.ip_option_s=4;

	len = strlen(argval);
	s = strtok(argval, ".+-;/>");
	do
	  {
	     len--;
	     *((struct libnet_in6_addr *) &tx.ip_option[tx.ip_option_s]) = libnet_name2addr6 (l, s, LIBNET_DONT_RESOLVE);
	     tx.ip_option_s += 16;
	  } while ( (s=strtok(NULL, ".+-;/>")) != NULL );

	if (!tx.ip_option_s) {
	  fprintf(stderr, " IP_Error: No Routing Hops found!\n");
	  exit(1);
	}

	if (mode==IP && tx.ip_payload_s)
	  memmove(tx.ip_payload+tx.ip_option_s, tx.ip_payload, tx.ip_payload_s);
	else
	  tx.ip_payload_s = 0;

        memcpy(tx.ip_payload, tx.ip_option, tx.ip_option_s);
        tx.ip_payload_s += tx.ip_option_s;

	t = libnet_build_ipv6_routing(tx.ip_proto,
				      (tx.ip_option_s -4) / 8,
				      tx.ip6_rtype,
				      tx.ip6_segs,
				      tx.ip_payload,
				      tx.ip_payload_s,
				      l,
				      0);
	tx.ip_len += LIBNET_IPV6_ROUTING_H + tx.ip_option_s;
	tx.ip_payload_s = 0;
	tx.ip_proto = LIBNET_IPV6_NH_ROUTING;
     }

   t = libnet_build_ipv6 (tx.ip_tos,
			  tx.ip_flow,
			  tx.ip_len,
			  tx.ip_proto,
			  tx.ip_ttl,
			  tx.ip6_src,
			  tx.ip6_dst,
			  (mode==IP) ? (tx.ip_payload_s) ? tx.ip_payload : NULL : NULL,
			  (mode==IP) ? tx.ip_payload_s : 0,
			  l,
			  0);

   if (t == -1)
     {
	fprintf(stderr, " mz/create_ip_packet: Can't build IPv6 header: %s\n", libnet_geterror(l));
	exit (0);
     }

   return t;
}


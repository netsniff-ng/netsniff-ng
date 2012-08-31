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




// ****************************************************************************
// Two features here: 
//   1. Initialize globals
//   2. Handle arguments in *argv[] and make a mode decision
// ****************************************************************************

#include "mz.h"
#include "cli.h"
#include "mops.h"

// Purpose: reset globals, global structs, etc.
int reset()
{
   int i;
   time_t t;

   // Determine platform type sizes:
   MZ_SIZE_LONG_INT = sizeof(long int);	     

   mz_default_config_path[0] = 0x00;
   mz_default_log_path[0] = 0x00;
	
   // Reset globals:
   quiet = 0;
   ipv6_mode = 0;
   verbose = 0;
   simulate = 0;
   filename[0] = '\0';
   path[0] = '\0';
   gind=0;
   gind_max = TIME_COUNT;
   fp = NULL;
   fp2 = NULL;
   mz_port = 0;
   mz_rand = 0;
   mp_head = NULL;
   
   for (i=0;i<TIME_COUNT_MAX;i++) jitter[i] = 0;      

   time0_flag = 0; // If set then time0 has valid data
   sqnr0_flag = 0; // If set then sqnr_last and sqnr_next has valid data
   rtp_log = 0;
   mz_ssrc[0]=0; mz_ssrc[1]=0; mz_ssrc[2]=0; mz_ssrc[3]=0;
	
   // Reset mgmt parameters of TX:
   tx.packet_mode = 1;     // assume we don't care about L2
   tx.count = 1;  
   tx.delay = DEFAULT_DELAY;      
   tx.arg_string[0] = '\0';
   
   // Reset Ethernet parameters of TX:
   tx.eth_params_already_set = 0;
   for (i=0; i<6; i++)   tx.eth_dst[i] = 0xff;
   for (i=0; i<6; i++)   tx.eth_src[i] = 0; // TODO: Get own MAC !!!
   tx.eth_dst_txt[0] = '\0';
   tx.eth_src_txt[0] = '\0';
   tx.eth_dst_rand = 0;
   tx.eth_src_rand = 0;
   
   tx.eth_type = 0x800;
   tx.eth_len = 0;
   tx.eth_payload[0] = '\0';
   tx.eth_payload_s = 0;
   tx.padding = 0;

   // Reset CDP parameters for TX:
   tx.cdp_sum  = 0;
   tx.cdp_version = 0;
   tx.cdp_ttl = 0;
   tx.cdp_payload[0] = '\0';
   tx.cdp_payload_s = 0;
   tx.cdp_tlv_id[0] = '\0';
   tx.cdp_tlv_id_len = 0;
   
   // Reset 802.1Q parameters of TX:
   tx.dot1Q=0;           
   tx.dot1Q_txt[0] = '\0';

   // ASCII Payload:
   tx.ascii = 0;                       // 1 if specified
   tx.ascii_payload[0]= '\0';

   // HEX Payload:
   tx.hex_payload_s = 0;
   
   // Reset MPLS parameters of TX:
   tx.mpls = 0;
   tx.mpls_txt[0] = '\0';
   tx.mpls_label = 0;
   tx.mpls_exp = 0;
   tx.mpls_bos = 1;
   tx.mpls_ttl = 255;
   tx.mpls_verbose_string[0] = '\0';
   
   // Reset IP parameters of TX:
   tx.ip_src_txt[0] = '\0';
   tx.ip_src_rand = 0;
   tx.ip_dst_txt[0] = '\0';
   tx.ip_src_isrange = 0;
   tx.ip_src_start = 0;
   tx.ip_src_stop = 0;
   
   tx.ip_dst_start = 0;
   tx.ip_dst_stop = 0;   
   tx.ip_dst_isrange = 0;

   tx.ip_len = 0;
   tx.ip_payload[0]= '\0';
   tx.ip_payload_s = 0;
   tx.ip_option[0]= '\0';
   tx.ip_option_s = 0;

   // Reset ICMP parameters:
   tx.icmp_type=0;
   tx.icmp_code=0;
   tx.icmp_chksum=0;            // 0=autofill
   tx.icmp_ident=0x42;
   tx.icmp_sqnr=0x1;
   tx.icmp_payload_s=0;
   
   // Reset general L4 parameters:
   tx.sp = 0;
   tx.dp = 0;
   tx.sp_start = 0; 
   tx.sp_stop = 0;
   tx.dp_start = 0;
   tx.dp_stop = 0;
   tx.sp_isrange = 0;
   tx.dp_isrange = 0;

   // Reset UDP parameters of TX:
   
   tx.udp_len = 0;                    // If set to zero then create_udp_packet will calculate it
   tx.udp_sum = 0;
   tx.udp_payload[0] = '\0';
   tx.udp_payload_s = 0;
   
   // Reset TCP parameters of TX:

   tx.tcp_seq = 42;
   tx.tcp_seq_stop = 42;
   tx.tcp_seq_delta = 0;              // also used as 'isrange' meaning
   tx.tcp_ack = 42;
   tx.tcp_control = 0;
   tx.tcp_win = 10000;
   tx.tcp_sum = 0;
   tx.tcp_urg = 0;
   tx.tcp_len = 20;                   // Least size (TCP header only)
   tx.tcp_payload[0] = '\0';
   tx.tcp_payload_s = 0;

   // Reset RTP parameters of TX:
   tx.rtp_sqnr = 0;
   tx.rtp_stmp = 0;
   
   // Initialize random generator
   time(&t);
   srand((unsigned int)t);

   // Reset device_list
   for (i=0; i<MZ_MAX_DEVICES; i++) {
	   device_list[i].arprx_thread = 0;
	   device_list[i].p_arp = NULL;
	   device_list[i].arp_table = NULL;
	   device_list[i].ps=-1;
	   device_list[i].cli=0;
	   device_list[i].mgmt_only=0;
   }
	
   return 0;
}



// Purpose: Properly handle arguments and configure global structs (tx)
int getopts (int argc, char *argv[])
{
	int i, c, rargs, RX=0, count_set=0, delay_set=0;
	unsigned int time_factor;
	char *packet_type=NULL, *mops_type=NULL;
	char *dum;
	unsigned char *dum1, *dum2;
	
	libnet_t       *l;
	char err_buf[LIBNET_ERRBUF_SIZE];
	struct libnet_ether_addr *mymac;
	
	FILE *afp;
	char hexpld[MAX_PAYLOAD_SIZE*2];
	int hexpld_specified=0;
	
	opterr = 1; // let getopt print error message if necessary
	
	
	while ((c = getopt (argc, argv, "46hqvVSxra:A:b:B:c:d:E:f:F:p:P:t:T:M:Q:X:")) != -1)
		switch (c) {
		 case '4':
			tx.eth_type = 0x0800;
			ipv6_mode=0;
			break;
		 case '6':
			tx.eth_type = 0x86dd;
			ipv6_mode=1;
			break;
		 case 'h':
			usage();
			break;
		 case 'q':
			quiet=1;
			break;
		 case 'v':
			verbose=1;
			break;
		 case 'V':
			verbose=2;
			break;
		 case 'S':
			simulate=1;
			break;
		 case 'x':
			mz_port = MZ_DEFAULT_PORT;
			break;
		 case 'a':
			strncpy (tx.eth_src_txt, optarg, 32);
			tx.packet_mode = 0;
			break;
		 case 'A':
			strncpy (tx.ip_src_txt, optarg, sizeof(tx.ip_src_txt));
			break;
		 case 'b':
			strncpy (tx.eth_dst_txt, optarg, 32);
			tx.packet_mode = 0;
			break;
		 case 'B':
			strncpy (tx.ip_dst_txt, optarg, sizeof(tx.ip_dst_txt));
			break;
		 case 'c':
			errno=0;
			tx.count = strtol(optarg, (char **)NULL, 10);
			if ((errno == ERANGE && (tx.count == LONG_MAX || tx.count == LONG_MIN))
			    || (errno != 0 && tx.count == 0)) {
				perror("strtol");
				return (-1);
			}
			if (tx.count<0) tx.count=1;	  //TODO: Allow count=0 which means infinity (need to update all send_functions)
			count_set=1;
			break;
		 case 'd': 
			errno=0;
			// determine whether seconds or msecs are used
			// default is usec!!!
			time_factor=1;
			if (exists(optarg,"s") || exists(optarg,"sec")) time_factor=1000000;
			if (exists(optarg,"m") || exists(optarg,"msec")) time_factor=1000;
			dum = strtok(optarg,"ms");
			tx.delay = strtol(dum, (char **)NULL, 10) * time_factor;
			if ((errno == ERANGE && (tx.delay == LONG_MAX || tx.delay == LONG_MIN))
			    || (errno != 0 && tx.delay == 0)) {
				perror("strtol");
				return (-1);
			}
			if (tx.delay<0) tx.delay=0; // no delay
			delay_set=1;
			break;
		 case 'p':
			errno=0;
			tx.padding = strtol(optarg, (char **)NULL, 10);
			if ((errno == ERANGE && (tx.padding == LONG_MAX || tx.padding == LONG_MIN))
			    || (errno != 0 && tx.padding == 0))  {
				perror("strtol");
				return (-1);
			}
			if (tx.padding>10000) {
				fprintf(stderr, " Warning: Padding must not exceed 10000!\n");
				return -1;
			}
			break;
		 case 't':
			packet_type = optarg; // analyzed below
			break;
		 case 'X':
			mops_type = optarg; // MOPS TRANSITION STRATEGY -- analyzed below
			break;
		 case 'T':
			packet_type = optarg;
			RX = 1;
			break;
		 case 'r':
			mz_rand = 1;
			break;
		 case 'M':
			if (strncmp(optarg,"help",4)==0) {
				(void) get_mpls_params("help ");
			}
			else {	
				strncpy (tx.mpls_txt, optarg, 128);
				tx.eth_type = ETHERTYPE_MPLS;
				tx.packet_mode = 0;
				tx.mpls=1;
			}
			break;
		 case 'P':  // ASCII payload
			strncpy((char*)tx.ascii_payload,  optarg, MAX_PAYLOAD_SIZE);
			tx.ascii = 1;
			break;
		 case 'f': // ASCII payload in FILE
			afp = fopen(optarg, "r");
			if (fgets((char*)tx.ascii_payload, MAX_PAYLOAD_SIZE, afp) == NULL)
				fprintf(stderr, " mz/getopts: File empty?\n");
			fclose(afp);
			tx.ascii = 1;
			break;
		 case 'F': // HEX payload in FILE
			afp = fopen(optarg, "r");
			i=0;
			while ( (hexpld[i]=fgetc(afp))!=EOF ) {
				if (isspace(hexpld[i])) {
					hexpld[i]=':';
				}
				i++;
			}
			hexpld[i]='\0';
			fclose(afp);
			hexpld_specified=1;
			break;
		 case 'Q': // VLAN TAG
			if (strncmp(optarg,"help",4)==0) { 
				print_dot1Q_help(); // ugly but most simple and safe solution
			}
			else {
				strncpy (tx.dot1Q_txt, optarg, 32);
				tx.dot1Q=1;
				// determine number of VLAN tags
				for (i=0; i<strlen(tx.dot1Q_txt); i++) {
					if (tx.dot1Q_txt[i]==',') tx.dot1Q++; 
				}
				tx.packet_mode = 0;
			}
			break;
		 case '?':
			if ((optopt == 'a') || (optopt == 'b') || (optopt = 'c') ||
			    (optopt == 'd') || (optopt == 'f') || (optopt = 'p') ||
			    (optopt == 't') || (optopt == 'm'))
				fprintf (stderr, " mz/getopts: Option -%c requires an argument.\n", optopt);
			else if (isprint (optopt))
				fprintf (stderr, " mz/getopts: Unknown option -%c'.\n", optopt);
			else
				fprintf (stderr, " mz/getopts: Unknown option character \\x%x'.\n", optopt);
			return 1;
		 default:
			fprintf (stderr," mz/getopts: Could not handle arguments properly!\n");
			return 1;
		}
   
	// ********************************************
	//       Handle additional arguments
	// ********************************************
	// 
	// Greeting text
	if (verbose) {
		fprintf(stderr,"\n"
			MAUSEZAHN_VERSION
			"\n"
			"Use at your own risk and responsibility!\n"
			"-- Verbose mode --\n"
			"\n");
	}
   
	if (argc<2) {
		usage();
	}
   
	if ((rargs=argc-optind)>2) {  // number of remaining arguments
		fprintf(stderr," mz/getopts: Too many arguments!\n");
		return -1;
	}

   
	// There can be 0-2 additional arguments
	switch (rargs) {
	 case 0: 
		if (lookupdev()) { // no device found
			if (verbose) fprintf(stderr, " mz: no active interfaces found!\n");
			strcpy(tx.device, "lo");
		}
		if (verbose) // device found
			fprintf(stderr," mz: device not given, will use %s\n",tx.device);
		break;
	 case 1: // arg_string OR device given => find out!
		if ( (strncmp(argv[optind],"eth",3)==0) 
		     || (strncmp(argv[optind],"ath",3)==0)
		     || ((strncmp(argv[optind],"lo",2)==0)&&(strncmp(argv[optind],"log",3)!=0))
		     || (strncmp(argv[optind],"vmnet",5)==0)
		     || (strncmp(argv[optind],"wifi",4)==0) ) {
			// device has been specified!
			strncpy (tx.device, argv[optind], 16);
		}
		else { /// arg_string given => no device has been specified -- let's find one!
			strncpy (tx.arg_string, argv[optind], MAX_PAYLOAD_SIZE);
			if (lookupdev()) { // no device found
				if (verbose) fprintf(stderr, " mz: no active interfaces found!\n");
				strcpy(tx.device, "lo");
			}
			if (verbose)
				fprintf(stderr," mz: device not given, will use %s\n",tx.device);
		}
		break;
	 case 2: // both device and arg_string given
		strncpy (tx.device, argv[optind], 16);
		strncpy (tx.arg_string, argv[optind+1], MAX_PAYLOAD_SIZE);
		break;
	 default:
		fprintf(stderr," mz/getopts: Unknown argument problem!\n");
		return 1;
	}
	
	if (hexpld_specified) {
		strcat(tx.arg_string, ",p=");
		strcat(tx.arg_string, hexpld);
	}
	
   
	//////////////////////////////////////////////////////////////////////////
	//
	// Initialize MAC and IP Addresses.
	// 
	// - tx.eth_src = own interface MAC 
	// - tx.ip_src  = own interface IP or user specified 
	// - tx.ip_dst  = 255.255.255.255 or user specified (can be a range)
	// - tx.ip_src_rand ... is set if needed.
	// 
   
	// Get own device MAC address:
	// Don't open context if only a help text is requested
	if  (getarg(tx.arg_string,"help", NULL)!=1) {
		l = libnet_init (LIBNET_LINK_ADV, tx.device, err_buf );
		if (l == NULL) {
			fprintf(stderr, " mz/getopts: libnet_init() failed (%s)", err_buf);
			return -1;
		}
		mymac = libnet_get_hwaddr(l);
		for (i=0; i<6; i++) {
			tx.eth_src[i] = mymac->ether_addr_octet[i];
			tx.eth_mac_own[i] = mymac->ether_addr_octet[i];
		}
	
		// Set source IP address:
		if (strlen(tx.ip_src_txt)) { // option -A has been specified
			if (mz_strcmp(tx.ip_src_txt, "bcast", 2)==0) {
				tx.ip_src = libnet_name2addr4 (l, "255.255.255.255", LIBNET_DONT_RESOLVE);
			} else if (strcmp(tx.ip_src_txt, "rand") == 0) {
				tx.ip_src_rand = 1;
				tx.ip_src_h  = (u_int32_t) ( ((float) rand()/RAND_MAX)*0xE0000000); //this is 224.0.0.0
			}
			else if (get_ip_range_src(tx.ip_src_txt)) { // returns 1 when no range has been specified
				// name2addr4 accepts a DOTTED DECIMAL ADDRESS or a FQDN:
				if (ipv6_mode)
					tx.ip6_src = libnet_name2addr6 (l, tx.ip_src_txt, LIBNET_RESOLVE);
				else
					tx.ip_src = libnet_name2addr4 (l, tx.ip_src_txt, LIBNET_RESOLVE);
			}
		}
		else { // no source IP specified: by default use own IP address
			if (ipv6_mode) {
				tx.ip6_src = libnet_get_ipaddr6(l);
				if (strncmp((char*)&tx.ip6_src,(char*)&in6addr_error,sizeof(in6addr_error))==0)
					printf("Failed to set source IPv6 address: %s", l->err_buf);
			}
			else
				tx.ip_src = libnet_get_ipaddr4(l);
		}
		
		// Set destination IP address:
		if (strlen(tx.ip_dst_txt)) {  // option -B has been specified
			if (mz_strcmp(tx.ip_dst_txt, "rand", 2)==0) {
				fprintf(stderr, "Option -B does not support random destination IP addresses currently.\n");
				return 1;
			}
		  
			if (mz_strcmp(tx.ip_dst_txt, "bcast", 2)==0) {
				tx.ip_dst = libnet_name2addr4 (l, "255.255.255.255", LIBNET_DONT_RESOLVE);	
			} else if (get_ip_range_dst(tx.ip_dst_txt)) { // returns 1 when no range has been specified
				// name2addr4 accepts a DOTTED DECIMAL ADDRESS or a FQDN:
				if (ipv6_mode)
					tx.ip6_dst = libnet_name2addr6 (l, tx.ip_dst_txt, LIBNET_RESOLVE);
				else
					tx.ip_dst = libnet_name2addr4 (l, tx.ip_dst_txt, LIBNET_RESOLVE);
			}
		}
		else { // no destination IP specified: by default use broadcast
			tx.ip_dst = libnet_name2addr4 (l, "255.255.255.255", LIBNET_DONT_RESOLVE);	
		}

		// Initialize tx.ip_src_h and tx.ip_dst_h which are used by 'print_frame_details()' 
		// in verbose mode. See 'modifications.c'.

		if (tx.ip_src_rand) { // ip_src_h already given, convert to ip_src
			dum1 = (unsigned char*) &tx.ip_src_h;
			dum2 = (unsigned char*) &tx.ip_src;
		}
		else { // ip_src already given, convert to ip_src_h
			dum1 = (unsigned char*) &tx.ip_src;
			dum2 = (unsigned char*) &tx.ip_src_h;
		}
	     
		*dum2 = *(dum1+3);
		dum2++;
		*dum2 = *(dum1+2);
		dum2++;
		*dum2 = *(dum1+1);
		dum2++;
		*dum2 = *dum1;
	
		dum1 = (unsigned char*) &tx.ip_dst;
		dum2 = (unsigned char*) &tx.ip_dst_h;
		
		*dum2 = *(dum1+3);
		dum2++;
		*dum2 = *(dum1+2);
		dum2++;
		*dum2 = *(dum1+1);
		dum2++;
		*dum2 = *dum1;
	
		libnet_destroy(l);
	}
   
	//
	// END OF ADDRESS INITIALIZATION
	// 
	//////////////////////////////////////////////////////////////////////////

	
	////// retrieve interface parameters ///////
	
	for (i=0; i<device_list_entries; i++) {
		get_dev_params(device_list[i].dev);
	}
	
   
	//////////////////////////////////////////////////////////////////////////
	// 
	//  Mausezahn CLI desired?
	if (mz_port) {
		// has port number been specified?
		if (strlen(tx.arg_string)) {
			mz_port = (int) str2int (tx.arg_string);
		}
	
		if (!quiet) {
			fprintf(stderr, "Mausezahn accepts incoming Telnet connections on port %i.\n", mz_port);
		}
	
		mz_cli_init();
		cli();
	}
   
	//////////////////////////////////////////////////////////////////////////
	//
	//                 Mode decision
	// 
	// Consider -t and -m option (used exclusively)
	//   -t => special packet types, stateless
	// 
	// If -t not present then evaluate arg_string which must 
	// contain a byte-string in hexadecimal notation.
	// 
	// 
   
	// ***** NEW: MOPS TRANSITION STRATEGY *****
	if (mops_type != NULL) {
		
		if (mz_strcmp(mops_type,"lldp",4)==0) {
			mops_direct(tx.device, MOPS_LLDP, tx.arg_string);
		}
	}
	
	
   if (packet_type == NULL) { // raw hex string given
	   mode = BYTE_STREAM;
   }
	else if (strcmp(packet_type,"arp")==0) {
		mode = ARP;
	}
	else if (strcmp(packet_type,"bpdu")==0) {
		mode = BPDU;
	}
	else if (strcmp(packet_type,"ip")==0) {
		mode = IP;
	}
	else if (strcmp(packet_type,"udp")==0) {
		mode = UDP;
	}
	else if (strcmp(packet_type,"icmp")==0) {
		mode = ICMP;
	}
	else if (strcmp(packet_type,"icmp6")==0) {
		mode = ICMP6;
	}
	else if (strcmp(packet_type,"tcp")==0) {
		mode = TCP;
	}
	else if (strcmp(packet_type,"dns")==0) {
		mode = DNS;
	}
	else if (strcmp(packet_type,"cdp")==0) {
		mode = CDP;
	}
	else if (strcmp(packet_type,"syslog")==0) {
		mode = SYSLOG;
	}
	else if (strcmp(packet_type,"lldp")==0) {
		mode = LLDP;
		tx.packet_mode=0; // create whole frame by ourself
	}
	else if (strcmp(packet_type,"rtp")==0) {
		if (RX) {
			mode = RX_RTP;
		}
		else {
			mode = RTP;
			if (!count_set) tx.count = 0;  
			if (!delay_set) tx.delay = 20000; // 20 msec inter-packet delay for RTP
		}
	}
	else if (strcmp(packet_type,"help")==0) {
		fprintf(stderr, "\n"
			MAUSEZAHN_VERSION
			"\n"
			"|  The following packet types are currently implemented:\n"
			"|\n"
			"|  arp            ... sends ARP packets\n"
			"|  bpdu           ... sends BPDU packets (STP or PVST+)\n"
			"|  cdp            ... sends CDP messages\n"
			"|  ip             ... sends IPv4 packets\n"
			"|  udp            ... sends UDP datagrams\n"
			"|  tcp            ... sends TCP segments\n"
			"|  icmp           ... sends ICMP messages\n"
			"|  dns            ... sends DNS messages\n"
			"|  rtp            ... sends RTP datagrams\n"
			"|  syslog         ... sends Syslog messages\n"
			"|\n"
			"| Of course you can build any other packet type 'manually' using the direct layer 2 mode.\n"
			"| FYI: The interactive mode supports additional protocols. (Try mz -x <port>)\n"
			"\n"
			);
		exit(1);
	}
	else {
		fprintf(stderr, " mz: you must specify a valid packet type!\n");
	}
	
   
	//////////////////////////////////////////////////////////////////////////   
   
	// TODO: Implement macro support
	//       Check macro types here 
   
	return 0;

}





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



#ifndef __MAUSEZAHN__
#define __MAUSEZAHN__

#define _GNU_SOURCE

#include <libnet.h>
#include <pcap.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <stdarg.h>
#include <math.h>

//#include <ctype.h>


////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
//
#define MAUSEZAHN_VERSION "Mausezahn 0.40 - (C) 2007-2010 by Herbert Haas - http://www.perihel.at/sec/mz/"
#define MAUSEZAHN_VERSION_SHORT "0.40"
//
//
////////////////////////////////////////////////////////////////////////////////////////////////////////////


// "Dies ist ein schrecklicher Ort."

#define MZ_DEFAULT_CONFIG_PATH "/etc/mausezahn/"   // see also mz_default_config_path below
#define MZ_DEFAULT_LOG_PATH "/var/log/mausezahn/"  // see also mz_default_log_path below

#define SLEEP usleep               // The sleep function to use. Consider 'nanosleep' in future.
#define DEFAULT_DELAY 0
#define PCAP_READ_TIMEOUT_MSEC 1   // The read timeout for pcap_open_live() 
#define MZ_MAX_DEVICES 10          // Max number of network devices supported
#define MAX_PAYLOAD_SIZE 3*8192
#define MAX_DNS_NAME 256
#define MAX_8021Q_TAGS 16         
#define TIME_COUNT_MAX 10000       // the size of the timestamp arrays timeRX and timeTX upon creation
#define TIME_COUNT 100             // the default used-size of the timestamp arrays timeRX and timeTX
#define MAX_DATA_BLOCKS 1000       // how many data blocks of size TIME_COUNT-1 should be written per file
#define MAXBYTES_TO_READ 1500      // how many bytes the pcap routine should read from net
#define RCV_RTP_MAX_BAR_WIDTH 500  // max line-width printed in BAR mode (see rcv_rtp.c)

#define ETH_SRC 1   // These are only some symbols used by some functions. (Don't touch)
#define ETH_DST 2   // These are only some symbols used by some functions.
#define SRC_PORT 1  // These are only some symbols used by some functions.
#define DST_PORT 2  // These are only some symbols used by some functions.

#define TEST fprintf(stderr, "HERE at line %i in file %s\n", __LINE__,__FILE__ ); fflush(stderr);


// -----  PCAP-specific definitions: ---------------------
#define IPADDRSIZE 46


int MZ_SIZE_LONG_INT;

char mz_default_config_path[256];
char mz_default_log_path[256];


struct arp_table_struct {
	int               index;     // an entry index (1, 2, ...) for easier user access
	u_int8_t          sa[6];     // sent by this MAC SA
	u_int8_t          smac[6];   // announced MAC
	u_int8_t          smac_prev[6];   // previously announced MAC
	u_int8_t          sip[4];    // announced IP
	unsigned long int uni_rq;    // count unidirectional ARP requests for this IP
	unsigned long int bc_resp;   // count broadcast ARP responses for this IP
	unsigned long int uni_resp;  // count normal (unidir) ARP responses for this IP
	unsigned long int changed;   // count how often the MAC address has changed!
	int               locked;    // 1=this entry cannot be overidden anymore
	int               dynamic;   // 1=learned dynamically, 0=configured by user
	int               flags;     // anomaly information (length anomaly: bit 0, sa!=smac: bit 1 , ...)
	int               gw;        // 1=Default GW
	char              when[10];  // human readable timestamp (e. g. "11:42:53")
	u_int32_t sec, nsec;         // timestamp of last ARP response
	u_int32_t sec_prev, nsec_prev;         // timestamp of previous ARP response
	//-----------------//
	struct arp_table_struct *next;
};

// Device list
struct device_struct
{
	char       dev[16];               // Device name
	int        index;                 // Device index (assigned by OS)
	int        phy;                   // 1 if physical, 0 if not (e. g. loopback)
	int        mtu;
	int        cli;                   // if set to 1 then the CLI connection must terminate here
	int        mgmt_only;             // if set to 1 then no data traffic is allowed through that interface
	// ---- MAC addresses ----
	u_int8_t   mac[6];                // Real MAC address
	u_int8_t   mac_mops[6];           // MAC address to be used
	// ---- IP related -----
	char       ip_str[IPADDRSIZE+1];  // Real IP address as string in dotted decimal notation		
	u_int8_t   ip[4];                 // Real IP address
	u_int8_t   net[4];                // Real network
	u_int8_t   mask[4];               // Real mask
	u_int8_t   ip_mops[4];            // IP address to be used
	// ---- Default Gateway per interface:
	u_int8_t   mac_gw[6];             // MAC address of default gateway
	u_int8_t   ip_gw[4];              // IP address of default gateway
	// ---- various device-specific handles ----
	pthread_t  arprx_thread;            
   	pcap_t     *p_arp;                  // pcap handle
	struct arp_table_struct *arp_table; // dedicated ARP table
	int        ps;                    // packet socket
} device_list[MZ_MAX_DEVICES];

int device_list_entries;
               

#pragma pack(1)
struct struct_ethernet
{
      u_int8_t   eth_da[6];
      u_int8_t   eth_sa[6];
      u_int16_t  eth_type;
};

struct struct_arp
{
   u_int16_t arp_hrd;  // hardware address format
   u_int16_t arp_pro;  // protocol address format 
   u_int8_t  arp_hln;  // hardware address length
   u_int8_t  arp_pln;  // protocol address length
   u_int16_t arp_op;   // ARP operation type
   u_int8_t  arp_smac[6];  // sender's hardware address
   u_int8_t  arp_sip[4];  // sender's protocol address
   u_int8_t  arp_tmac[6];  // target hardware address
   u_int8_t  arp_tip[4];  // target protocol address
};



//#pragma pack(1)
struct struct_ip
{
   u_int8_t 
     hlen :4, 
     ver  :4; 
   u_int8_t 
     tos; 
   u_int16_t 
     len; 
   
   u_int16_t  
     id,      
     offset;   // flags and fragment offset field

   u_int8_t
     ttl,      
     proto;   
   u_int16_t
     sum;
   
   u_int8_t  src[4];
   u_int8_t  dst[4];
};

//#pragma pack(1)
struct struct_udp {
	u_int16_t 
		sp,
		dp,
		len,
		sum;
};

//#pragma pack(1)
struct struct_rtp {
	u_int8_t 
		byte1,
		ptype;
	u_int16_t
		sqnr;
	u_int32_t
		timestamp,  // official timestamp, created by codecs
		ssrc;
        	//   csrc,      // only used by mixers
	u_int16_t
		ext_id,
		ext_len;
	u_int32_t
		time_sec,
		time_nsec,
		time_sec2,
		time_nsec2;
};

// ---------End of PCAP-specific definitions---------------




// ************************************
// 
//  Global variables
//
// ************************************

enum operating_modes
{
   BYTE_STREAM, 
     ARP, 
     BPDU, 
     IP, 
     ICMP,
     ICMP6,
     UDP, 
     TCP,
     DNS,
     CDP,
     RTP,
     RX_RTP,
     SYSLOG,
     LLDP
} mode;


int ipv6_mode;
int quiet;           // don't even print 'important standard short messages'
int verbose;         // report character
int simulate;        // if 1 then don't really send frames

char path[256];
char filename[256];
FILE *fp, *fp2;             // global multipurpose file pointer

long double total_d;
clock_t mz_start, mz_stop;

enum rtp_display_mode {
	BAR, NCURSES, TEXT
} rtp_dm;
	

int mz_rand;
int bwidth;

struct mz_timestamp {
	u_int32_t sec; 
	u_int32_t nsec;
};

struct mz_timestamp 
	tv, 
	timeTX[TIME_COUNT_MAX],  
	timeRX[TIME_COUNT_MAX];

int32_t
  time0,
  jitter_rfc,
  jitter[TIME_COUNT_MAX];   

int 
  rtp_log,
  time0_flag,        // If set then time0 has valid data
  sqnr0_flag;  

u_int8_t
  mz_ssrc[4];     // holds RTP stream identifier for rcv_rtp()

u_int16_t 
  sqnr_cur,
  sqnr_last, 
  sqnr_next;

u_int32_t
  drop,    // packet drop count
  dis,     // packet disorder count
  gind,      // a global index to run through deltaRX, deltaTX, and jitter
  gind_max,  // the amount of entries used in the (ugly oversized) arrays; per default set to TIME_COUNT
  gtotal;    // counts number of file write cycles (see "got_rtp_packet()") 


char rtp_filter_str[64];

struct tx_struct
{
   // Management issues for TX
   char device[16];           // every packet could be sent through a different device
   int  packet_mode;          // 0 means use LIBNET_LINK_ADV, 1 means LIBNET_RAW4
   unsigned int count;        // 0 means infinite, 1 is default
   unsigned int delay;        // Delay in microseconds, 0 means no delay (default)
   char arg_string[MAX_PAYLOAD_SIZE];  // Argument-string when -t is used
   
   // Ethernet and 802.3 parameters
   int eth_params_already_set; // if set to 1 then send_eth should only send the frame
   u_int8_t  eth_mac_own[6];  // Contains own interface MAC if needed by some modules
   char      eth_dst_txt[32]; // Text version of eth_dst (or keyword such as 'rand')
   u_int8_t  eth_dst[6];
   int       eth_dst_rand;    // 1 if random
   char      eth_src_txt[32]; // Text version of eth_src (or keyword such as 'rand')
   u_int8_t  eth_src[6];
   int       eth_src_rand;    // 1 if random
   u_int16_t eth_type;
   u_int16_t eth_len;
   u_int8_t  eth_payload[MAX_PAYLOAD_SIZE];
   u_int32_t eth_payload_s;
   unsigned int padding;

   // CDP parameters
   u_int8_t 
     cdp_version, 
     cdp_ttl,
     cdp_payload[MAX_PAYLOAD_SIZE],
     cdp_tlv_id[2048];               // The ID is the only required TLV
   u_int16_t 
     cdp_sum;
   u_int32_t 
     cdp_tlv_id_len,
     cdp_payload_s;
   
   // 802.1Q VLAN Tag
   int       dot1Q;           // 1 if specified
   char      dot1Q_txt[32];   // contains 802.1p(CoS) and VLAN-ID ("5:130" or only VLAN "130")
   u_int8_t  dot1Q_CoS;
   u_int16_t dot1Q_vlan;
   u_int8_t  dot1Q_header[256]; // Contains the complete 802.1Q/P headers (but NOT the Ethernet header!)
   u_int8_t  dot1Q_header_s;
   int       dot1Q_at_least_two_headers; // If '1' then we have at least QinQ (or more VLAN tags)
   
   // ASCII PAYLOAD
   int       ascii;           // 1 if specified
   u_int8_t  ascii_payload[MAX_PAYLOAD_SIZE];

   // HEX PAYLOAD
   u_int8_t  hex_payload[MAX_PAYLOAD_SIZE];
   u_int32_t hex_payload_s;   // >0 if hex payload is specified
   
   // MPLS Parameters
   char      mpls_txt[128];   // contains MPLS parameters (label, exp, S, TTL)
   char      mpls_verbose_string[1024]; // contains all labels for print_frame_details()
   int       mpls;            // 1 if specified
   u_int32_t mpls_label;
   u_int8_t  mpls_exp;
   u_int8_t  mpls_bos;
   u_int8_t  mpls_ttl;
   
   // IP parameters
   u_int32_t ip_src;          // has always network byte order(!)
   struct libnet_in6_addr ip6_src;
   char      ip_src_txt[256];
   int       ip_src_rand;     // if set to 1 then SA should be random
   u_int32_t ip_src_h;        // mirror of ip_src (NOT network byte order => easy to count)
   u_int32_t ip_src_start;    // start of range (NOT network byte order => easy to count)
   u_int32_t ip_src_stop;     // stop of range  (NOT network byte order => easy to count)
   int       ip_src_isrange;  // if set to 1 then the start/stop values above are valid.
   u_int32_t ip_dst;          // has always network byte order(!)
   struct libnet_in6_addr ip6_dst;
   char      ip_dst_txt[256];
   u_int32_t ip_dst_h;        // mirror of ip_dst (NOT network byte order => easy to count)
   u_int32_t ip_dst_start;    // start of range (NOT network byte order => easy to count)
   u_int32_t ip_dst_stop;     // stop of range  (NOT network byte order => easy to count)
   int       ip_dst_isrange;  // if set to 1 then the start/stop values above are valid.
   u_int16_t 
     ip_len,
     ip_id,
     ip_frag,                 // Flags and Offset !!!
     ip_sum;  
   u_int8_t 
     ip_tos,
     ip_ttl,
     ip6_rtype,
     ip6_segs,
     ip_proto;
   u_int8_t 
     ip_option[1024],
     ip_payload[MAX_PAYLOAD_SIZE];
   u_int32_t 
     ip_flow,
     ip6_id,
     ip_option_s,
     ip_payload_s;

   // ICMP
   char 
     icmp_verbose_txt[256]; // used for verbose messages in send.c
   u_int8_t
     icmp_type,
     icmp_code;
   u_int16_t icmp_ident;    // ATTENTION: libnet.h already #defines 'icmp_id', 'icmp_sum', and 'icmp_num'
   u_int16_t  icmp_chksum;  //            therefore I needed a renaming here -- be careful in future...
   u_int16_t  icmp_sqnr;    //            
   u_int32_t
     icmp_gateway,
     icmp_payload_s;
   u_int8_t
     icmp_payload[MAX_PAYLOAD_SIZE];

   // General L4 parameters:
   char *layer4;
   u_int16_t 
     sp, dp, 
     sp_start, sp_stop,
     dp_start, dp_stop;
   int 
     sp_isrange,               // if set to 1 then start/stop values above are valid
     dp_isrange;               // if set to 1 then start/stop values above are valid
   
   // UDP parameters
   u_int16_t 
     udp_len,                  // includes header size (8 bytes)
     udp_sum;
   u_int8_t 
     udp_payload[MAX_PAYLOAD_SIZE];
   u_int32_t 
     udp_payload_s;
   
   // TCP parameters
   u_int32_t 
     tcp_seq, 
     tcp_seq_start,
     tcp_seq_stop,                  // is always set! Usually seq_start = seq_stop (=no range)
     tcp_seq_delta,                 // Also used instead of an 'isrange' variable
     tcp_ack;
   u_int8_t 
     tcp_offset,
     tcp_control;
   u_int16_t 
     tcp_win, 
     tcp_sum, 
     tcp_urg, 
     tcp_len;                       // only needed by libnet and must include header size 
   u_int8_t 
     tcp_payload[MAX_PAYLOAD_SIZE];
   u_int32_t 
     tcp_sum_part,
     tcp_payload_s;

   // RTP parameters
   u_int32_t
     rtp_sqnr,
     rtp_stmp;
   
} tx;  // NOTE: tx elements are considered as default values for MOPS





u_int8_t  gbuf[MAX_PAYLOAD_SIZE];  // This is only a generic global buffer to handover data more easily
u_int32_t gbuf_s;                  //


// ************************************
// 
//  Prototypes: General Tools
//
// ************************************
		  
void clean_up(int sig);
int reset();
void usage();
int getopts(int argc, char *argv[]);
int getarg(char *str, char *arg_name, char *arg_value);
unsigned long int str2int(char *str);       // converts "65535" to 65535
unsigned long long int str2lint(char *str); // same but allows 64-bit integers
unsigned long int xstr2int(char *str);      // converts "ffff" to 65535
unsigned long long int xstr2lint(char *str);     // same but allows 64-bit integers
int mz_strisbinary(char *str);
int mz_strisnum(char *str);
int mz_strishex(char *str);
int str2bin8 (char *str);
long int str2bin16 (char *str);
int char2bits (char c, char *str);
int mz_strcmp(char* usr, char* str, int min);
int mz_tok(char * str, char * delim, int anz, ...);
int delay_parse (struct timespec *t, char *a, char *b);

// ************************************
// 
//  Prototypes: Layer1
//
// ************************************
 
int            send_eth();
libnet_ptag_t  create_eth_frame (libnet_t *l, libnet_ptag_t  t3, libnet_ptag_t  t4);

// ************************************
// 
//   Prototypes: Layer 2
//
// ************************************

int send_arp ();
int send_bpdu ();
int send_cdp ();

// ************************************
// 
//   Prototypes: Layer 3
//
// ************************************


libnet_t*      get_link_context();
libnet_ptag_t  create_ip_packet (libnet_t *l);
libnet_ptag_t  create_ip6_packet (libnet_t *l);
int            send_frame (libnet_t *l, libnet_ptag_t  t3, libnet_ptag_t  t4);



// ************************************
// 
//   Prototypes: Layer 4
//
// ************************************
libnet_ptag_t  create_udp_packet (libnet_t *l);  
libnet_ptag_t  create_icmp_packet (libnet_t *l);  	
libnet_ptag_t  create_icmp6_packet (libnet_t *l);
libnet_ptag_t  create_tcp_packet (libnet_t *l);


// ************************************
// 
//   Prototypes: Layer 7
//
// ************************************
int  create_dns_packet ();
int  create_rtp_packet();
int create_syslog_packet();

// ************************************
// 
//   Prototypes: Helper functions for 
//               byte manipulation, 
//               address conversion, 
//               etc
//
// ************************************

// Converts MAC address specified in str into u_int8_t array
// Usage: str2hex_mac ( "00:01:02:aa:ff:ee", src_addr )
int str2hex_mac (char* str, u_int8_t *addr);

// Converts ascii hex values (string) into integer array, similarly as above but for any size.
// Example: "1a 00:00-2f" => {26, 0, 0, 47}
// Note: apply any improvements here and prefer this function in future!
// Return value: Number of converted elements (=length of array)
int str2hex (char* str, u_int8_t *hp, int n);

// Converts ascii numbers (string) into integer array
// Every byte can be specified as integers {0..255}
// For example "192.16.1.1" will be converted to {C0, 10, 01, 01} 
int num2hex(char* str, u_int8_t *hp);

// Convert array of integers into string of hex. Useful for verification messages.
// Example: {0,1,10} => "00-01-0A"
// Usage: bs2str ( src_mac, src_mac_txt, 6 )  
int bs2str (u_int8_t *bs, char* str, int len);

// Extract contiguous sequence of bytes from an array. First element has index 1 !!!
// Usage: getbytes (bs, da, 1, 6);
int getbytes(u_int8_t *source, u_int8_t *target, int from, int to);

// For any IP address given in 'dotted decimal' returns an unsigned 32-bit integer.
// Example: "192.168.0.1" => 3232235521
// Note: Result is in LITTLE ENDIAN but usually with IP you need BIG ENDIAN, see next.
u_int32_t str2ip32 (char* str);

// For any IP address given in 'dotted decimal' into an unsigned 32-bit integer
// This version does the same as str2ip32() but in BIG ENDIAN.
// Note: With netlib you need this one, not the previous function.
u_int32_t str2ip32_rev (char* str);

// Converts a 2-byte value (e. g. a EtherType field)
// into a nice string using hex notation.
// Useful for verification messages.
// Example: type2str (tx.eth_type, msg) may result in msg="08:00"
// Return value: how many hex digits have been found.
int type2str(u_int16_t type, char *str);


// Parses string 'arg' for an IP range and finds start and stop IP addresses.
// Return value: 0 upon success, 1 upon failure.
// 
// NOTE: The results are written in the following variables:
// 
//   (u_int32_t) tx.ip_dst_start    ... contains start value 
//   (u_int32_t) tx.ip_dst_stop     ... contains stop value
//   int         tx.ip_dst_isrange  ... set to 1 if above values valid
//   
// The other function does the same for the source address!
//   
// Possible range specifications:
// 
//   1) 192.168.0.0-192.168.0.12
//   2) 10.2.11.0-10.55.13.2
//   3) 172.18.96.0/19
// 
// That is: 
// 
//   FIRST detect a range by scanning for the "-" OR "/" chars
//   THEN determine start and stop value and store them as normal unsigned integers
// 
int get_ip_range_dst (char *arg);
int get_ip_range_src (char *arg);

// Sets a random SA for a given IP packet.
// Return value: 0 upon success, 1 upon failure
// 
int set_rand_SA (libnet_t *l, libnet_ptag_t t3);

// Scans tx.eth_dst_txt or tx.eth_src_txt and sets the corresponding
// MAC addresses (tx.eth_dst or tx.eth_src) accordingly.
// Argument: What string should be checked, ETH_SRC or ETH_DST.
// Return value: 
//       0 when a MAC address has been set or
//       1 upon failure.
// Currently eth_src|dst_txt can be:
//   'rand', 'own', 'bc'|'bcast', 'stp', 'pvst',
//   or a real mac address.
// 
int check_eth_mac_txt(int src_or_dst);

// Scans argument for a port number or range
// and sets the corresponding values in the 
// tx struct.
// 
// Arguments: sp_or_dp is either SRC_PORT or DST_PORT
// Return value: 0 on success, 1 upon failure
// 
int get_port_range (int sp_or_dp, char *arg);

// Return a 4-byte unsigned int random number
u_int32_t  mz_rand32 ();

// Scans argument for TCP flags and sets 
// tx.tcp_control accordingly.
// 
// Valid keywords are: fin, syn, rst, psh, ack, urg, ecn, cwr
// Valid delimiters are: | or + or -
// Return value: 0 on success, 1 upon failure
// 
int get_tcp_flags (char*  flags);

// Scans string 'params' for MPLS parameters 
// and sets tx.mpls_* accordingly.
// 
// CLI Syntax Examples:
// 
// -M help       .... shows syntax
// 
// -M 800        .... label=800
// -M 800:S      .... label=800 and BOS flag set
// -M 800:S:64   .... label=800, BOS, TTL=64
// -M 800:64:S   .... same
// -M 64:77      .... label=64, TTL=77
// -M 64:800     .... INVALID
// -M 800:64     .... label=800, TTL=64
// -M 800:3:S:64 .... additionall the experimental bits are set (all fields required!)
// 
// Note: S = BOS(1), s = NOT-BOS(0)
// 
// Valid delimiters: :-.,+
// Return value: 0 on success, 1 upon failure
int get_mpls_params(char *params);

// Parses str for occurence of character or sequence ch.
// Returns number of occurences 
int exists(char* str, char* ch);


// Applies another random Ethernet source address to a given Ethernet-PTAG.
// (The calling function should check 'tx.eth_src_rand' whether the SA 
// should be randomized.)
int update_Eth_SA(libnet_t *l, libnet_ptag_t t);


// Update timestamp and sequence number in the RTP header.
// The actual RTP message is stored in tx.udp_payload.
int update_RTP(libnet_t *l, libnet_ptag_t t);

  
// Applies another SOURCE IP address, 
//  - either a random one (tx.ip_src_rand==1)
//  - or from a specified range (tx.ip_src_isrange==1) 
// to a given IP-PTAG.
// 
// Note: tx.ip_src MUST be already initialized with tx.ip_src_start.
//       This is done by 'get_ip_range_src()' in tools.c.
// 
// RETURNS '1' if tx.ip_src restarts
int update_IP_SA (libnet_t *l, libnet_ptag_t t);


// Applies another DESTINATION IP address from a specified range (tx.ip_dst_isrange==1) 
// to a given IP-PTAG.
// 
// Note: tx.ip_dst MUST be already initialized with tx.ip_dst_start.
//       This is done by 'get_ip_range_dst()' in tools.c.
// 
// RETURN VALUE: '1' if tx.ip_dst restarts
int update_IP_DA(libnet_t *l, libnet_ptag_t t);


// Applies another DESTINATION PORT from a specified range to a given UDP- or TCP-PTAG.
// 
// Note: tx.dp MUST be already initialized with tx.dp_start
//       This is done by 'get_port_range()' in tools.c.
//
// RETURN VALUE: '1' if tx.dp restarts
int update_DPORT(libnet_t *l, libnet_ptag_t t);


// Applies another SOURCE PORT from a specified range to a given UDP- or TCP-PTAG.
// 
// Note: tx.sp MUST be already initialized with tx.sp_start
//       This is done by 'get_port_range()' in tools.c.
//       
// RETURN VALUE: '1' if tx.sp restarts
int update_SPORT(libnet_t *l, libnet_ptag_t t);


// Applies another TCP SQNR from a specified range to a given TCP-PTAG
// 
// RETURN VALUE: '1' if tx.txp_seq restarts
// 
int update_TCP_SQNR(libnet_t *l, libnet_ptag_t t);

int update_ISUM(libnet_t *l, libnet_ptag_t t);
int update_USUM(libnet_t *l, libnet_ptag_t t);
int update_TSUM(libnet_t *l, libnet_ptag_t t);

//
//
int print_frame_details();


// Calculates the number of frames to be sent.
// Should be used as standard output except the
// 'quiet' option (-q) has been specified.
int complexity();


// Purpose: Calculate time deltas of two timestamps stored in struct timeval.
// Subtract the "struct timeval" values X and Y, storing the result in RESULT.
// Return 1 if the difference is negative, otherwise 0.
int timestamp_subtract (struct mz_timestamp *x,
			struct mz_timestamp *y, 
			struct mz_timestamp *result);

void timestamp_add (struct mz_timestamp *x, 
		    struct mz_timestamp *y, 
		    struct mz_timestamp *result);

// Returns a human readable timestamp in the string result.
// Optionally a prefix can be specified, for example if the
// timestamp is part of a filename.
// 
// Example: 
//    char myTimeStamp[128];
//    
//    timestamp_human(myTimeStamp, NULL);
//    
//    => "20080718_155521"
//    
//    /* or with prefix */
//    
//    timestamp_human(myTimeStamp, "MZ_RTP_jitter_");
// 
//    => MZ_RTP_jitter_20080718_155521
// 
int timestamp_human(char* result, const char* prefix);

// Returns a human readable timestamp in the string result.
// Optionally a prefix can be specified, for example if the
// timestamp is part of a filename.
// 
// Example: 
//    char myTimeStamp[8];
//    
//    timestamp_hms (myTimeStamp);
//    
//    => "15:55:21"
int timestamp_hms(char* result);

// Initialize the rcv_rtp process: Read user parameters and initialize globals
int rcv_rtp_init();
  
// Defines the pcap handler and the callback function
int rcv_rtp();

// Print current RFC-Jitter on screen
void print_jitterbar (long int j, unsigned int d);

// Compares two 4-byte variables byte by byte
// returns 0 if identical, 1 if different
int compare4B (u_int8_t *ip1, u_int8_t *ip2);

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
int lookupdev();


// For a given device name, find out the following parameters:
// 
//  - MTU
//  - Network
//  - Mask
//  - Default GW (IP)
//  
int get_dev_params (char *name);

// Handler function to do something when RTP messages are received
void got_rtp_packet(u_char *args,
		    const struct pcap_pkthdr *header, // statistics about the packet (see 'struct pcap_pkthdr')
		    const u_char *packet);            // the bytestring sniffed


// Check if current system supports the nanosecond timer functions.
// Additionally, measure the precision.
// This function should be called upon program start.
// 
int check_timer();

// This is the replacement for gettimeofday() which would result in 'jumps' if
// the system clock is adjusted (e. g. via a NTP process) and finally the jitter
// measurement would include wrong datapoints.
// 
// Furthermore the function below utilizes the newer hi-res nanosecond timers.
inline void getcurtime (struct mz_timestamp *t);

// Only print out the help text for the 02.1Q option
void print_dot1Q_help(void);

// Determines ip and mac address of specified interface 'ifname'
// Caller must provide an unsigned char ip[4], mac[6]
//
int get_if_addr (char *ifname, unsigned char *ip, unsigned char *mac);

// Takes filename and prepends valid configuration/logging directory
// NOTE: filename is overwritten and must be big enough to hold full path!
int getfullpath_cfg (char *filename);
int getfullpath_log (char *filename);

// A safer replacement for strncpy which ensures \0-termination
char * mz_strncpy(char *dest, const char *src, size_t n);

// Helper function to count the number of arguments
// in the Mausezahn argument string (comma separated args)
// RETURN VALUE: Number of arguments
int number_of_args (char *str);

int arptable_add(struct device_struct *dev, 
		 u_int8_t *sa, 
		 u_int8_t *da, 
		 u_int8_t *smac, 
		 u_int8_t *sip, 
		 u_int32_t sec, 
		 u_int32_t nsec);

// Validate ARP requests
int arpwatch(struct device_struct *dev, 
	     u_int8_t *sa, 
	     u_int8_t *da, 
	     u_int8_t *smac, 
	     u_int8_t *sip, 
	     u_int8_t *tmac,
	     u_int8_t *tip,
	     u_int32_t sec,
	     u_int32_t nsec);


#endif

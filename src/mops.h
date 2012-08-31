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


#ifndef __MOPS__
#define __MOPS__


#define MOPS_VERSION "0.3"
#define MOPS_CODENAME "Cyanistes caeruleus (DE+150)"
#define AUTOMOPS_ENABLED    0             // Automops subsystem (currently in development)
#define MAX_MOPS_FRAME_SIZE 8192          // total max frame size (=all headers plus payload)
#define MIN_MOPS_FRAME_SIZE 15            // total min frame size 
#define MOPS_SIZE_MARGIN    50            // User limit: MAX_MOPS_FRAME_SIZE - MOPS_SIZE_MARGIN
#define MAX_MOPS_MSG_SIZE 7500            // payload limit
#define MAX_MOPS_MSG_CHUNK_SIZE 1000      // Chunks size when read data from a file for the payload
#define MAX_MOPS_COUNTERS_PER_PACKET 10   // number of user-defined counters per packet
#define MAX_MOPS_PACKET_NAME_LEN 32       // Each packet must have an unique name
#define MAX_MOPS_DESCRIPTION_LEN 80       // Max length of packet description string
#define MAX_MOPS_DOT1Q_TAGS 64            // Max number of 802.1Q tags within a frame (too many, practically ;-))
#define MAX_MOPS_MPLS_TAGS 64             // Max number of MPLS tags within a frame (again too many, practically)
#define XN_MAX_STACK  7                   // max nesting depth

#define AUTOMOPS_MAX_FILE_SIZE  200000    // Max file size in bytes for AMP protocol definitions
#define AUTOMOPS_MAX_NAME_LEN       32    // used for all names (valname, field name, protocol name)
#define AUTOMOPS_MAX_SHORTDESC_LEN  64

#define XML_MAX_TAG_LEN             16   
#define XML_STRLEN                  64   // required length of user string to hold tag
                                         // but also alternatively an error message


#define MAX_LLDP_OPT_TLVS          500   // How many bytes are reserved for optional TLVs within an LLDP message?

//#define MAX_MOPS_PACKETS 1000             // number of packet slots *** DEPRECATED ***
#define MAX_CLI_LINE_BYTES 32             // How many bytes 'mops_print_frame' should print before line break

// Basic layers; see mops_clear_layers()
// Also used by automops (see layers_on, layers_off)
#define MOPS_ALL       127    
#define MOPS_ETH         1
#define MOPS_SNAP        2    // either LLC, LLC+SNAP
#define MOPS_dot1Q       4
#define MOPS_MPLS        8
#define MOPS_IP         16
#define MOPS_UDP        32
#define MOPS_TCP        64

// The following definitions are needed as values for (int) p_desc_type
// which identifies the exact type of (void *) p_desc.
#define MOPS_NO_PDESC 100
#define MOPS_ARP      101
#define MOPS_BPDU     102
#define MOPS_CDP      103
#define MOPS_DNS      104
#define MOPS_ICMP     105
#define MOPS_LLDP     106
#define MOPS_RTP      107
#define MOPS_SYSLOG   108
#define MOPS_IGMP     109

// packet states (variable 'state')
// NOTE: every state >2 (i. e. 3, 4, ...) is an active state, i. e. packet should 
//       be blocked from configurations etc.
#define MOPS_STATE_NULL   0   // transition state, only initially
#define MOPS_STATE_INIT   1   
#define MOPS_STATE_CONFIG 2   // normal state (when configured)
#define MOPS_STATE_ACTIVE 3   // has associated sending thread
#define MOPS_STATE_SEQACT 4   // packet is member of an active sequence

// Return values of mops_pdesc utility functions (see mops_ext.c)
#define MOPS_PDESC_SUCCESS      0   // Value assigned properly | string present
#define MOPS_PDESC_FAILURE      1   // Unspecified problem | string not present
#define MOPS_PDESC_LOW          2   // Value smaller than lower bound - but will set
#define MOPS_PDESC_HIGH         3   // Value larger than upper bound  - but will set
#define MOPS_PDESC_OVERFLOW     4   // Value exceeded possible range
#define MOPS_PDESC_NO_MAC       5   // Invalid MAC address
#define MOPS_PDESC_NO_IP        6   // Invalid IP address

// These definitions are (should be) only used in mops_ext.c
#define MOPS_EXT_ARP    struct mops_ext_arp *
#define MOPS_EXT_BPDU   struct mops_ext_bpdu *
#define MOPS_EXT_CDP    struct mops_ext_cdp *
#define MOPS_EXT_DNS    struct mops_ext_dns *
#define MOPS_EXT_ICMP   struct mops_ext_icmp *
#define MOPS_EXT_LLDP   struct mops_ext_lldp *
#define MOPS_EXT_RTP    struct mops_ext_rtp *
#define MOPS_EXT_SYSLOG struct mops_ext_syslog *
#define MOPS_EXT_IGMP   struct mops_ext_igmp *

// Very specific definitions here:
#define MOPS_RTP_EXT_MZID  0xcaca // first 16 bit of the Mausezahn RTP extension header
#define DSP_SOURCE         100    // any number >0 indicating /dev/dsp to be used as RTP payload
#define MOPS_RTP_MAX_PAYLOAD_SIZE 200

#include <pthread.h>


// These are initialized with the definitions MIN_MOPS_FRAME_SIZE and 
// MAX_MOPS_FRAME_SIZE above but can be overridden by the user (without
// extending these limits)
unsigned int min_frame_s;
unsigned int max_frame_s;

struct mops_counter
{
   int         use;     // 1 = counter active
   int         offset;  // points to counter location in *msg*
   int         random;  // 1=random, 0=use start/stop/step
   u_int32_t   start;   // HOST BYTE ORDER
   u_int32_t   stop;    // HOST BYTE ORDER
   u_int32_t   step;    // HOST BYTE ORDER
   u_int32_t   cur;     // current value (HOST BYTE ORDER)
   int         bytes;   // number of bytes used (1|2|4) - selects hton2 or hton4
                        // and enables proper wraparounds (mod 256, mod 65536, ...)
};


enum amperr {
	ampSuccess, 
	ampInvalidIndex, 
        ampInvalidName,
	ampDuplicateName,
	ampDescTooLong, 
	ampInvalidType,
	ampInvalidLayer,
	ampTCPandUDP,
	ampUnknownKeyword, 
	ampSingleWordRequired,
	ampRangeError,
	ampPayloadLen,
	ampPayloadType,
	ampUnknownTag
};

enum fieldtypes {
	Byte8, Byte16, Byte32, Flag_in_Byte, MultiBytes, MultiBytesHex,
	TLV // TODO: different/standard TLV formats (Cisco CDP, LLCP, ...)
};
	

struct fields {
	struct fields *next;
	char name[AUTOMOPS_MAX_NAME_LEN+1]; 	// Official name of field -- CASE INSENSITIVE
	char shortdesc[AUTOMOPS_MAX_SHORTDESC_LEN+1];   // One-line description
	char * longdesc;                                // Long (multiline) description (helptext)
	enum fieldtypes type;    // Field type corresponds to length
	int  constant;           // 1: only default value allowed, not changeable

	int i;     // unique internal field entry index (strongly monotonic increasing!)
	           // Note: first entry starts with 0.
	
	int index; // protocol field index; Note: First field has index 1.
	           // successive fields have same index in two cases:
	           //      1) several flags within same byte
	           //      2) several different valname/val pairs for same field index. In this
	           //         case the successive field-entries must only contain the valname
	           //         and a corresponding value.

	// may contain a reserved value *name*, usually used with multiple
	// successive fields with same field index N.
	char valname[AUTOMOPS_MAX_NAME_LEN+1];

	u_int32_t
		tlv_type, 
		tlv_len,
		val,      // default initial value
		min,      // range min value
		max;      // range max value

	int leftshift;    // when type=Flag_in_Byte
	
	u_int8_t *str;    // default initial characters or hex values (when type=MultiByte or TLV)
	int str_s;        // length of str
};


// Each automops object identifies another dynamically specified protocol.
// 
// Usage and structure:
// 
//  1) Doubly linked list to store new (dynamically defined) protocols.
//     Protocol definitions are typically loaded from a file and converted
//     to an automops entry via parse_protocol() defined in parse_xml.c
//  
//  2) When the user chooses one of these protocols to be used for a mops
//     then best is to copy the whole automops to the current mops; this
//     way the protocol's field values can be easily modified and 
//     automops_update() can be directly applied to that automops entity.
//     
//  If you cannot understand anything you are maybe already mausezahn'ed  ;-)
//     
struct automops {
	struct automops *next;
	struct automops *prev;
		
	char    name[AUTOMOPS_MAX_NAME_LEN+1];  // Protocol name
	char    desc[AUTOMOPS_MAX_SHORTDESC_LEN+1]; // One-line description               

	// Specify required and allowed layers using the definitions above
	// for example MOPS_ETH, MOPS_SNAP, MOPS_dot1Q, MOPS_MPLS, 
	//             MOPS_IP, MOPS_UDP, and MOPS_TCP
	int 
		layers_on,  // which layers are REQUIRED
		layers_off; // which layers MUST be DISABLED because of conflicts
	                    // Not mentioned layers are arbitrary (e. g. MOPS_dot1Q)
	// Protocol-specific addresses
	//    Usually only destination address/port is specific but there are some
	//    exceptions (e. g. DHCP uses well known sp/dp pair). 
        //    Value zero means ignore; otherwise copy to mops.
	u_int16_t etype;    // EtherType
	u_int8_t  proto;    // IP protocol number
        u_int8_t  sa[6], da[6];   // source/destination MAC address
        u_int32_t SA, DA;   // source/destination IPv4 address
	int     sp, dp;     // Well-known port numbers


	int     payload_type;     // 0=none, 1=ascii, 2=hex, 3=any
	char    *payload;         // default payload data (if above is true) 
	int     payload_s;
	
	struct fields *field; // points to single linked list describing each field
	                      // or NULL 
	
	/// ---- internal data -----
	int defined_externally; // 0=built-in, 1=file, -1=undefined		   
	int used; // number of mopses using this automops;
	          // = -1   when allocated 
	          // =  0   when got valid data
		  // = >0   when used by some mopses
};


struct automops * amp_head;


struct mops
{
   struct mops *next;
   struct mops *prev;
   
   // *** The Header ***
   // Management issues for TX
   int  state;                                      // see above
   int  id;                                         // UNIQUE Identifier (NOTE: MUST ALLOW -1)
   int  mz_system;                                  // identifies user and system packets (such as ARP)
   int  verbose;                                    // Be more or less verbose when processing that MOPS
   char packet_name[MAX_MOPS_PACKET_NAME_LEN];      // Each packet must have unique name
   char description[MAX_MOPS_DESCRIPTION_LEN];      // An optional short packet description

   pthread_t        mops_thread;                    // associated transmission thread
   pthread_t        interval_thread;
	
   pthread_mutex_t  mops_mutex;                     // mutex to savely access mops data
   
   char device[16];           // every packet could be sent through a different device
                              // NOTE that we do NOT store the index of device_list[] because after
			      // a re-discovery of the network interfaces the same index could map
			      // to a different physical network device. Instead the device's name
			      // does not change (however, might be not available, but then we report
			      // an error message and the user can assign another interface)
			      // 
			      // See function mops_get_device_index()
			      
   unsigned long count;       // Desired number of packets to be sent. 0 means infinite.
   unsigned long cntx;        // This value actually counts sent packets. 
                              // NOTE: Count _down_ for finite count, count _up_ for infinite count.

   struct timespec ndelay;    // Inter-packet delay; contains two members: 
	                      // tv_sec and tv_nsec (0 to 999999999)

   struct timespec interval;  // An optional global interval
   int             interval_used;  // 0=none, 1=configured, 2=active (i. e. interval_thread is valid)
   
   struct timespec delay_sigma;  // Standard deviation

   int           delay_pd;    // Which propability distribution (density)
                              //      MOPS_DELAY_GAUSS
                              //      MOPS_DELAY_EXP will result in a Poisson process with lambda=delay
			     
	
   int  auto_delivery_off;    // 0 means, the destination MAC address will be chosen automatically (for IP packets)
	                      // depending on the IP destination address ('direct or indirect delivery', i. e. based
			      // on ARP). 
			      // 
			      // 1 means, the user-provided destination MAC address will be used.
	
   // ******************
   
   // Data section
   
   int 
     use_ETHER,     // if unset (=0) then complete raw frame given in frame[]
     use_SNAP,      // NOTE: use_SNAP=1 may indicate either 802.3+LLC alone or 802.3+LLC+SNAP
     use_dot1Q,
     use_MPLS,
     use_IP,
     use_UDP,
     use_TCP;

   int                        // pointers to important positions
     begin_IP,                // marks byte position of IP header within frame
     begin_UDP,               // marks byte position of UDP header within frame
     begin_TCP,               // marks byte position of TCP header within frame
     begin_MSG;               // marks byte position of first message byte (=payload) within frame
   
   int  // **** get payload (message) from a file ****
     MSG_use_RAW_FILE,            // 1 means update function should copy next chunk from file
     MSG_use_HEX_FILE,            // same but assumes file content such as "aa:bb:cc:f3:1e:..."
     MSG_use_ASC_FILE;            // same but interpretes file content as ASCII characters
        // NOTE: if one of these are set to 1 then a filepointer is open !!!
   
   // A protocol descriptor (p_desc) is only used for some statically 
   // defined protocols. Originally intended for more complicated protocols
   // such as DNS.
   void * p_desc;       // optionally points to protocol descriptor (e. g. for DNS, CDP, etc)
   int    p_desc_type;  // identifies the exact type of p_desc
	
	
	
   // AutoMOPS provides a dynamic method to define new protocols. Here we need a pointer
   // to the protocol definition for convenience and the complete protocol header field
   // which is created by automops_update()
   // 
   // Note: The used 'amp' should be memcpy'd for this particular mops
   //       because then we can store current PDU values here and the 
   //       user can modify it later arbitrarily.
   // 
   //       Use  automops_clone_automops()  in automops.c for this.
   // 
   struct automops         *amp;  // points to protocol definition
   u_int8_t            *amp_pdu;  // contains the complete PDU as bytestring
   int                amp_pdu_s;
	
	
   // Resulting frame:
   u_int8_t   frame[MAX_MOPS_FRAME_SIZE];  // will hold the complete frame
   u_int32_t  frame_s;                     // indicates the total frame size
   
   
   // Ethernet parameters:
   u_int8_t  eth_dst[6];
   u_int8_t  eth_src[6];
   int       eth_src_israndom; // if set to 1 then the source address is to be randomized
   u_int16_t eth_type;
   u_int16_t eth_type_backup;  // if original type must be restored (e. g. when removing MPLS labels)
   
   // 802.3 parameters: LLC/SNAP
   u_int16_t eth_len;
   u_int8_t  eth_snap[16]; // AA-AA-03-<OUI>-<TYPE>
   int       eth_snap_s;   // usually 8 bytes

      
   // 802.1Q VLAN Tag   !!! NOTE: outer tag has lower index number (same byte-order as in frame[]) !!!
   u_int8_t  dot1Q[MAX_MOPS_DOT1Q_TAGS*4]; // All successive 802.1Q/P headers, 4 bytes per header: 0x8100, pri, cfi, id
   int       dot1Q_s;       // how many bytes from above are really used
   int       dot1Q_isrange; // if 1, only the outer tag loops through the range.
   int       dot1Q_start;
   int       dot1Q_stop;
		
	
   // MPLS label stack
   u_int8_t mpls[MAX_MOPS_MPLS_TAGS*4];   // All successive labels
   int      mpls_s;       // how many bytes from above are really used
   int      mpls_isrange; // if 1, only the outer tag loops through the range.
   int      mpls_start;  
   int      mpls_stop;
	
   // IP parameters -- NOTE: Everything here is in HOST BYTE ORDER !!!

   u_int32_t ip_src;          // By default interface address
   u_int32_t ip_src_start;    // start of range (HOST byte order => easy to count)
   u_int32_t ip_src_stop;     // stop of range  (HOST byte order => easy to count)
   int       ip_src_isrange;  // if set to 1 then the start/stop values above are valid.
   int       ip_src_israndom; // if set to 1 then the source address is to be randomized
   u_int32_t ip_dst;          // (HOST byte order)
   u_int32_t ip_dst_start;    // start of range (NOT network byte order => easy to count)
   u_int32_t ip_dst_stop;     // stop of range  (NOT network byte order => easy to count)
   int       ip_dst_isrange;  // if set to 1 then the start/stop values above are valid.
   u_int16_t 
     ip_len,
     ip_id,
     ip_frag_offset,          // 13 bit Offset: allowed values: 0..8191
     ip_sum;                  // TODO: provide variable 'ip_sum_false' to create false checksum for various tests
   int       ip_IHL_false;    // Default=0, set to 1 if user configured own (typically false) header length
   int       ip_len_false;    // Default=0, set to 1 if user configured own (typically false) total length
   int       ip_sum_false;    // Default=0, set to 1 if user configured own (typcially false) checksum
   u_int8_t 
     ip_version,
     ip_IHL,                  // header length (4 bits = 0..15)
     ip_tos,
     ip_flags_RS,             // 0|1 ... Reserved flag "must be zero"
     ip_flags_DF,             // 0|1 ... Don't Fragment 
     ip_flags_MF,             // 0|1 ... More Fragments
     ip_fragsize,             // if >0 it activates auto-fragmentation
     ip_frag_overlap,         // if >0 then all fragments overlap. Must be multiple of 8 but smaller than fragsize.
     ip_ttl,
     ip_proto;
   u_int8_t 
     ip_option[1024];         // Any IP Option used?
   int ip_option_used;        // >0 if yes. The exact number also indicates which option(s) used - see mops_ip.c
   u_int32_t 
     ip_option_s;


   // General L4 parameters:
   u_int16_t 
     sp, dp, 
     sp_start, sp_stop,
     dp_start, dp_stop;
   int 
     sp_isrand,                // if set to 1 then use random port number for each sent packet
     dp_isrand,                // if set to 1 then use random port number for each sent packet
     sp_isrange,               // if set to 1 then start/stop values above are valid
     dp_isrange;               // if set to 1 then start/stop values above are valid
   
   // UDP parameters
   u_int16_t 
     udp_len,                  // includes header size (8 bytes)
     udp_sum;
   int   udp_sum_false;        // Default=0, set to 1 if user configured own (typcially false) checksum
   int   udp_len_false;        // Default=0, set to 1 if user configured own (typcially false) length
   
   // TCP parameters (RFC 793)
   // 
   //     0                   1                   2                   3   
   //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   //    |          Source Port          |       Destination Port        |
   //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   //    |                        Sequence Number                        |
   //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   //    |                    Acknowledgment Number                      |
   //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   //    |  Data |           |U|A|P|R|S|F|                               |
   //    | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   //    |       |           |G|K|H|T|N|N|                               |
   //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   //    |           Checksum            |         Urgent Pointer        |
   //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   //    |                    Options                    |    Padding    |
   //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   //    |                             data                              |
   //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   // 
   u_int32_t 
     tcp_seq, 
     tcp_seq_start,
     tcp_seq_stop,             
     tcp_seq_delta,            // Also used instead of an 'isrange' variable
     tcp_ack,
     tcp_ack_start,
     tcp_ack_stop,
     tcp_ack_delta;            // Also used instead of an 'isrange' variable
   u_int8_t 
     tcp_offset,               // Header length in multiples of 32 bit (4 bit value, 0..15)
     tcp_res,                  // reserved (4 bits)
     tcp_ctrl_CWR,             // 0|1 - Congestion Window Reduced [RFC-3168]
     tcp_ctrl_ECE,             // 0|1 - ECN-Echo [RFC-3168]
     tcp_ctrl_URG,             // 0|1 
     tcp_ctrl_ACK,             // 0|1 
     tcp_ctrl_PSH,             // 0|1 
     tcp_ctrl_RST,             // 0|1 
     tcp_ctrl_SYN,             // 0|1 
     tcp_ctrl_FIN;             // 0|1 
   u_int16_t 
     tcp_win, 
     tcp_sum, 
     tcp_urg,
     tcp_len;                  // Only needed for the checksum calculation and is not transmitted (host order!)
     
   int
     tcp_sum_false,            // Default=0, set to 1 if user configured own (typcially false) checksum
     tcp_offset_false;         // Default=0, set to 1 if user configured own (typcially false) offset
   u_int8_t
     tcp_option[1024];
   u_int32_t
     tcp_option_s;
   int tcp_option_used;        // >0 if yes. The exact number also indicates which option(s) used - see mops_tcp.c
   
   
   // Message:
   u_int8_t   msg[MAX_MOPS_MSG_SIZE];
   u_int32_t  msg_s;  
   FILE *fp;  // points to file if MSG_use_RAW_FILE or MSG_use_HEX_FILE or MSG_use_ASC_FILE is set to 1
   u_int32_t  chunk_s;  // max chunk size to be copied from file
   
   
   // User-defined counters:
   struct mops_counter counter[MAX_MOPS_COUNTERS_PER_PACKET];
   int used_counters;   // number of currently defined counters
   
};



struct mops_ext_arp 
{
   u_int16_t  hw_type;
   u_int16_t  pr_type;
   u_int8_t   hw_size;
   u_int8_t   pr_size;
   u_int16_t  opcode;
   u_int8_t   sender_mac[6];
   u_int8_t   sender_ip[4];
   u_int8_t   target_mac[6];
   u_int8_t   target_ip[4];
   u_int16_t  trailer;
};



struct mops_ext_bpdu // TODO
{
   u_int16_t  id;       
   u_int8_t   version;       // 0=802.1D, 2=RSTP(802.1w)
   u_int8_t   bpdu_type;     // 0=conf, 1=topology change (actually in big endian!), 2=RSTP/MSTP
   u_int8_t   flags;            // X... .... = TCN ACK
                                // .X.. .... = Agreement
                                // ..X. .... = Forwarding
			        // ...X .... = Learning
			        // .... XX.. = Port Role (e. g. 11=Desgn)
			        // .... ..X. = Proposal
			        // .... ...X = TCN
   u_int8_t   root_id[8];    // Root BID 
   u_int32_t  root_pc;       // Root Path Cost
   u_int8_t   bridge_id[8];  // Own BID
   u_int16_t  port_id;       // Port Identifier
   u_int16_t  message_age;   // All timers are multiples of 1/256 sec. Thus times range from 0 to 256 seconds.
   u_int16_t  max_age; 
   u_int16_t  hello_time;
   u_int16_t  f_delay;
   u_int8_t   trailer[8];    // either all-zero or 34:00:02:VLAN(16bit):00:00 when PVST+

   int rstp; // 1 = RSTP
   int pvst; // 1=PVST+ , 0 = 802.1D
   int mstp; // 1 = Multiple Instance STP
   
};

struct mops_ext_lldp {
	int non_conform; // if 1 then the order of TLVs is arbitrary
	int chassis_id_subtype;
	int chassis_id_len;
	u_int8_t *chassis_id;
	int port_id_subtype;
	int port_id_len;
	u_int8_t *port_id;
	int TTL;
	int optional_tlvs_s;
	u_int8_t *optional_tlvs;
	
};

enum igmp_type {IGMP_GENERAL_QUERY, 
		IGMP_GSPEC_QUERY, 
		IGMP_V2_REPORT, 
		IGMP_V1_REPORT, 
		IGMP_LEAVE};

struct igmp_sa_struct { // For single linked list to hold unicast addresses for IGMPv3 query
	u_int32_t sa;
	struct igmp_sa_struct *next;
};

struct igmp_aux_struct { // For single linked list to hold auxilary data for IGMPv3 report
	u_int32_t aux_data;
	struct igmp_aux_struct *next;
};


struct igmp_group_struct { // For single linked list to hold IGMPv3 group records
	u_int8_t       record_type;
	u_int8_t       aux_data_len;
	u_int16_t      nr_sources;
	u_int32_t      mcast_addr;
	struct igmp_sa_struct  *sa_list;
	struct igmp_aux_struct *aux_list;
	struct igmp_group_struct *next;
};



struct mops_ext_igmp  {
	int        version;       // internal, not in header
	u_int8_t   type;
	u_int8_t   max_resp_code; // equally: 'max response time' for IGMPv2
	u_int16_t  sum;
	int        sum_false;     // if '1' then sum contains user-provided checksum; if '0' then autocompute!
	u_int32_t  group_addr;
	u_int8_t 
		resv4,          // resv4 + S + QRV => one byte in IGMPv3 query
		S,              // S = Suppress Router-Side Processing
		QRV;            // QRV = Querier's Robustness Variable
	u_int8_t   resv8;       // needed in IGMPv3 response AND IGMPv1 query+response
	u_int16_t  resv16;      // needed in IGMPv3 response       
	u_int8_t   QQIC;        // Querier's Query Interval Code
	u_int16_t  nr_entries;  // either number of sources (=query) or group records (=response)
	struct igmp_sa_struct *sa_list;
};


struct mops_ext_cdp // TODO
{
   u_int8_t   id;
   u_int16_t  hw_type;
};

struct mops_ext_dns // TODO: complete
{
   // Main 16-bit fields
   u_int16_t  id;
   u_int16_t  num_queries;
   u_int16_t  num_answers;
   u_int16_t  num_author;
   u_int16_t  num_add;
   u_int16_t  type;
   
   // Flags (1 bit, except where noted)
   u_int8_t   qr;
   u_int8_t   opcode;  // 4 bits
   u_int8_t   aa;
   u_int8_t   tc;
   u_int8_t   rd;
   u_int8_t   ra;
   u_int8_t   z;       // 3 bits
   u_int8_t   rcode;   // 4 bits
   
};


struct mops_ext_icmp // TODO
{
   u_int8_t   id;
   u_int16_t  hw_type;
};

struct mops_ext_rtp 
{
   // Vars to hold flag values:
   u_int8_t   v,
	      p,
	      x,  // only sets the flag; if you really want an extension header also set "x_type" (see below)
	      cc, // csrc_count visible in header (has no further meaning, thus support for "wrong" headers)
	      cc_real, // real csrc_count (only used internally to create CSRC list)
	      m,
	      pt; // selects inter-packet delay and payload_s;
	
   u_int16_t  sqnr;  // initial sqnr
   u_int32_t  tst;   // initial timestamp
   u_int32_t  ssrc;  // !!! also used to identify measurement streams !!!
   u_int32_t  csrc[16]; // NOTE: only up to 15 CSRC's are allowed according RFC 3550
	
   // additionally:
   int        tst_inc;        // The increment of the tst (depends on codec)
   u_int8_t   payload[MOPS_RTP_MAX_PAYLOAD_SIZE];   // 
   int        payload_s;      // is the same as tst_inc when codec is G.711 but different with other codecs!
   int        source;         // Optionally draw data from file or /dev/dsp or such [TODO]
   int        rtp_header_len; // will be set by mops_update_rtp()
   // one optional header extension:
   int        x_type; // IMPORTANT: which extension header to use: 0 = none, 42 = Mausezahn, 1 = Aero
   u_int8_t   extension[64]; // a user configurable extension header [CURRENTLY UNUSED]
};



struct mops_ext_syslog //TODO
{
   u_int16_t  hw_type;
   u_int16_t  pr_type;
};

   
/////////////////////////////////////////////////////////////////

struct mops *mp_head; // This global will point to the head of the mops list

/////////////////////////////////////////////////////////////////
// MOPS Prototypes:

inline void mops_hton2 (u_int16_t *host16, u_int8_t *net16);
inline void mops_hton4 (u_int32_t *host32, u_int8_t *net32);

int  mops_get_proto_info (struct mops *mp, char *layers, char *proto);

// Inserts value in 'flag' (up to 7 bits are useful) into the target
// with an optional left-shift. For example if flag contains a 4-bit value
// and should be placed within the target in bit positions 3-6 like:
// 
//   7  6  5  4  3  2  1  0   
// +--+--+--+--+--+--+--+--+
// |  |  FLAGS    |  |  |  |
// +--+--+--+--+--+--+--+--+
// 
// then simply call: 
// 
//    (void)  mops_flags ( &target, &flag, 3 );
// 
// Note:
//     1) shift=0 means no shift
//     2) Because of speed we do not check if the arguments are reasonable
//     
inline void mops_flags (u_int8_t *target, u_int8_t *flag, int shift);

u_int16_t mops_sum16 (u_int16_t len, u_int8_t buff[]);

struct mops * mops_init ();
struct mops * mops_alloc_packet (struct mops *cur);
struct mops * mops_delete_packet (struct mops *cur);
int mops_reset_packet(struct mops *cur);
	
int    mops_dump_all (struct mops* list, char* str);
struct mops * mops_search_name (struct mops* list, char *key);
struct mops * mops_search_id (struct mops* list, u_int32_t key);

void   mops_delete_all (struct mops* list);
void   mops_cleanup   (struct mops* list);

// State functions
int mops_state (struct mops *mp);
int mops_is_active (struct mops *mp);
void mops_set_conf (struct mops *mp);
void mops_set_active (struct mops *mp);
void mops_set_seqact (struct mops *mp);
int mops_is_seqact (struct mops *mp);
int mops_is_any_active (struct mops *mp);

// For debugging purposes
int   mops_print_frame (struct mops *mp, char *str);

// sets UDP or TCP checksum within mp->frame
// TODO: copying the whole segment is ugly and slow;
//       make it more efficient and realize it in-place.
//         
int  mops_get_transport_sum  (struct mops *mp);

// returns new counter index for given packet
// or -1 if all counters used already
int mops_get_counter (struct mops *mp);

// This is the very basic MOPS update function. It simply updates the whole
// MOPS frame specified by pointer mp. If you only want to update specific
// details then please see the other related specialized functions which are
// faster.
int mops_update (struct mops *mp);

int mops_set_defaults (struct mops *mp);

// Get global device index for a given device name.
int mops_get_device_index(char *devname);

// Assign device-specific addresses to packet.
int mops_use_device(struct mops * clipkt, int i);

// Find and returns a new unique packet id
// If none can be found, returns -1.
int mops_get_new_pkt_id (struct mops *mp);

// Simply sets specified 'layer switches' in struct mops to zero
int mops_clear_layers (struct mops *mp, int l);

// Transmission functions
int mops_tx_simple (struct mops *mp);
void *mops_tx_thread_native (void *arg);
void *mops_interval_thread (void *arg);
void *mops_sequence_thread (void *arg);


int mops_destroy_thread (struct mops *mp);

// Utility functions for packet headers (aka *** METHODS *** for the object-oriented nerds)
int mops_dot1Q_remove (struct mops *mp, int k);
int mops_dot1Q_nocfi (struct mops *mp, int k);
int mops_dot1Q_cfi (struct mops *mp, int k);
int mops_dot1Q (struct mops *mp, int i, int m, u_int16_t v, u_int16_t c);

int mops_mpls_remove (struct mops *mp, int j);
int mops_mpls_bos (struct mops *mp, int k);
int mops_mpls_nobos (struct mops *mp, int k);
int mops_mpls(struct mops *mp, int i, int m, u_int32_t Label, u_int8_t Exp, u_int8_t TTL);

int mops_ip_get_dst_mac(struct device_struct *dev, u_int8_t *ip, u_int8_t *mac);
int mops_ip_dscp(struct mops *mp, char *argv);
int mops_ip_tos (struct mops* mp, int ipp, int tos, int mbz);
int mops_ip_option_ra (struct mops* mp, int value);
int mops_ip_option_remove_all (struct mops* mp);

u_int32_t mops_tcp_complexity_sqnr (struct mops * mp);
u_int32_t mops_tcp_complexity_acknr (struct mops * mp);

// Prints current flag settings in the provided string 'str'.
int mops_tcp_flags2str (struct mops* mp, char *str);

int mops_tcp_add_option (struct mops* mp, 
			 int mss, 
			 int sack,
			 int scale, 
			 u_int32_t tsval, 
			 u_int32_t tsecr);


//////////////////////////////////////////////////////////////////////////////
//
// ****** The following are important to easily create new packet types ******
//
//////////////////////////////////////////////////////////////////////////////

// Adds single byte to msg
int mops_msg_add_byte (struct mops *mp, u_int8_t data);

// Adds bit field in *previous* msg-byte using optional left-shift
int mops_msg_add_field (struct mops *mp, u_int8_t data, int shift);

// Adds two bytes in network byte order to msg
int mops_msg_add_2bytes (struct mops *mp, u_int16_t data);

// Adds four bytes in network byte order to msg
int mops_msg_add_4bytes (struct mops *mp, u_int32_t data);

// Adds string of bytes with lenght len 
int mops_msg_add_string (struct mops *mp, u_int8_t *str, int len);

// Add counter to message
int mops_msg_add_counter (struct mops *mp,
			  int         random,  // 1=random, 0=use start/stop/step
			  u_int32_t   start,   // HOST BYTE ORDER
			  u_int32_t   stop,    // HOST BYTE ORDER
			  u_int32_t   step,    // HOST BYTE ORDER
			  int         bytes   // number of bytes used (1|2|4) - selects hton2 or hton4
			  );

// Returns 0 if identical, 1 if different
int compare_ip (u_int8_t *ip1, u_int8_t *ip2);

// Returns 0 if identical, 1 if different
int compare_mac (u_int8_t *mac1, u_int8_t *mac2);

// Converts a 'struct timespec' value into a human readable string
int timespec2str(struct timespec *t, char *str);

// -------------------------------------------------------------------------------

// Add protocol descriptor of type ptype
// 
// Smart behaviour: If a p_desc has been already assigned, this function 
// clears and frees everything before assigning another p_desc structure.
// 
int mops_ext_add_pdesc (struct mops *mp, int ptype);

// Create msg based on p_desc data.
// After that call mops_update and the frame is complete.
int mops_ext_update (struct mops *mp);

// Delete any protocol descriptor
int mops_ext_del_pdesc (struct mops *mp);

// Initialization functions for p_desc
int mops_init_pdesc_arp(struct mops *mp);
int mops_init_pdesc_bpdu(struct mops *mp);
int mops_init_pdesc_cdp(struct mops *mp);
int mops_init_pdesc_dns(struct mops *mp);
int mops_init_pdesc_icmp(struct mops *mp);
int mops_init_pdesc_igmp(struct mops *mp);
int mops_init_pdesc_lldp(struct mops *mp);
int mops_init_pdesc_syslog(struct mops *mp);
int mops_init_pdesc_rtp(struct mops *mp);

int mops_create_igmpv2 (struct mops *mp,
			int override,   // normally zero, but if '1' the user want to override defaults
			int igmp_type, // IGMP_GENERAL_QUERY, IGMP_GSPEC_QUERY, IGMP_V2_REPORT, IGMP_V1_REPORT, IGMP_LEAVE
			int  mrt, // max response time
			int  sum, //-1 means auto-compute, other values means 'use this user-defined value'
			u_int32_t group_addr);


// Update functions for p_desc => msg
int mops_update_arp(struct mops * mp);
int mops_update_bpdu(struct mops * mp);
int mops_update_igmp (struct mops * mp);
int mops_update_lldp (struct mops * mp);
int mops_update_rtp (struct mops * mp);
int mops_update_rtp_dynamics (struct mops * mp);

// Utility functions for p_desc
int mops_pdesc_mstrings (char *dst, char* argv[], int argc, int max);
int mops_pdesc_1byte (u_int8_t *dst, char* usr, int spec, int min, int max);
int mops_pdesc_2byte (u_int16_t *dst, char* usr, int spec, int min, int max);
int mops_pdesc_4byte (u_int32_t *dst, char* usr, int spec, unsigned long int min, unsigned long int max);
int mops_pdesc_mac (u_int8_t *dst, char* usr);
int mops_pdesc_ip (u_int8_t *dst, char* usr);

// Other p_desc related functions
int mops_create_bpdu_bid(struct mops * mp, int pri, int esi, char *mac, int bid_or_rid);
int mops_create_bpdu_trailer (struct mops * mp, u_int16_t vlan);
int mops_lldp_tlv (u_int8_t *tlv, int type, int len, u_int8_t *value);
int mops_lldp_tlv_chassis (u_int8_t *tlv, int subtype, int len, u_int8_t *cid);
int mops_lldp_tlv_port (u_int8_t *tlv, int subtype, int len, u_int8_t *pid);
int mops_lldp_tlv_TTL (u_int8_t *tlv, int ttl);
int mops_lldp_tlv_end (u_int8_t *tlv);
int mops_lldp_opt_tlv_bad (struct mops *mp, int type, int badlen, int len, u_int8_t *value);
int mops_lldp_opt_tlv_org (struct mops *mp, int oui, int subtype, int len, u_int8_t *inf);
int mops_lldp_opt_tlv_chassis (struct mops *mp, int subtype, int len, u_int8_t *cid);
int mops_lldp_opt_tlv_port (struct mops *mp, int subtype, int len, u_int8_t *pid);
int mops_lldp_opt_tlv_TTL (struct mops *mp, int ttl);
int mops_lldp_opt_tlv_vlan (struct mops *mp, int vlan);
int mops_lldp_opt_tlv (struct mops *mp, int type, int len, u_int8_t *value);
int mops_lldp_opt_tlv_end (struct mops *mp) ;


/////////////////////////// Services /////////////////////////////

// ARP Service: Resolves MAC address of given IP address and interface
int service_arp(char *dev, u_int8_t *ip, u_int8_t *mac);

int mops_rx_arp ();
void *rx_arp (void *arg);
void got_arp_packet (u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


//////////////////// directmops prototypes: ///////////////////////////
int mops_direct(char* dev, int mops_type, char* argstring);


//////////////////// automops prototypes: //////////////////////////////////


struct automops * automops_init();
struct automops * automops_alloc_protocol();
struct automops * automops_delete_protocol();
struct automops * automops_search_protocol();
int               automops_dump_all (struct automops* list);
void              automops_set_defaults(struct automops * cur);
struct fields *   automops_add_field (struct automops *amp);
void              automops_field_set_defaults(struct fields *f);
int               automops_delete_fields (struct automops *amp);
int               mops_str2layers(char *d);
int               amp_add_pentry (struct automops *amp, int xntag, char *d);
int               amp_add_fentry (struct automops *amp, struct fields *f, int xntag, char *d);
int               amp_checkindex(struct automops *amp, int i);
int               amp_str2type(char *d);
int               amp_type2str(int t, char *s);
struct fields *   amp_getfield_byname(struct automops *amp, char *d);
struct automops * amp_getamp_byname(struct automops *head, char *d);
// Creates an independent automops element for mops
// (it will be not part of any linked list so, next=prev=NULL)
struct automops * automops_clone_automops(struct automops * amp);
int               amperr2str (int e, char *s);

// Create automops PDU within *mp based on data in *amp
// 
int automops_update (struct mops *mp, struct automops *amp);
void automops_cleanup (struct automops *list);

char * mapfile (char *fn);

//////////////////////////  XML support //////////////////////////////
//
//


// Simple stack needed to check proper XML nesting.
// The corresponding methods are defined at the bottom.
struct xnstack {
	int data[XN_MAX_STACK];
	int cursize;
};

enum xml_tags { // mention all allowed tags here!
        	xml_protocol,
		xml_field,
		xml_name,
		xml_desc,
		xml_requires,
		xml_conflicts,
		xml_payloadtype,
		xml_payload,
		xml_payloadhex,
		xml_index,
		xml_longdesc,
		xml_type,
		xml_constant,
		xml_value,
		xml_valname,
		xml_min,
		xml_max,
		xml_tlvt,
		xml_tlvl,
		xml_lshift
};


int xml_check_parent(int t, int p);
int xml_tag2int (char *t);

int parse_protocol (char *p);
int xml_getnext_tag (char *p, char *t);
int xml_canonic (char *p);
int xml_get_data (char *p, char *t);
int xml_readin (struct automops *amp, char *p);

void xnstack_init(struct xnstack *s);
int xnstack_get_top(struct xnstack *s);
int xnstack_push(struct xnstack *s, int d);
int xnstack_pop(struct xnstack *s);
int xnstack_size(struct xnstack *s);

#endif


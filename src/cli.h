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



#ifndef __MAUSEZAHN_CLI__
#define __MAUSEZAHN_CLI__

#include <libcli.h>
#include "mops.h"

#define CLI_DEBUG_PACKET      0x0001

#define MZ_MODE_BENCHMARK     1002
#define MZ_MODE_SCAN          1003

#define MZ_MODE_PACKET        1100

#define MZ_MODE_PACKET_ARP    1101
#define MZ_MODE_PACKET_BPDU   1102
#define MZ_MODE_PACKET_CDP    1103
#define MZ_MODE_PACKET_DNS    1104
#define MZ_MODE_PACKET_IP     1105
#define MZ_MODE_PACKET_ICMP   1106
#define MZ_MODE_PACKET_LLDP   1107
#define MZ_MODE_PACKET_RTP    1108
#define MZ_MODE_PACKET_SYSLOG 1109
#define MZ_MODE_PACKET_TCP    1110
#define MZ_MODE_PACKET_UDP    1111
#define MZ_MODE_PACKET_ETH    1112
#define MZ_MODE_PACKET_IGMP   1113

#define MZ_MODE_INTERFACE     1200
#define MZ_MODE_SEQUENCE      1300

#define MZ_BANNER_TEXT  \
     "\n" \
     "------------------------------------------\n" \
     "Mausezahn, version " MAUSEZAHN_VERSION_SHORT " \n" \
     "Copyright (C) 2007-2009 by Herbert Haas.\n" \
     "------------------------------------------\n\n" \
     "Mausezahn comes with ABSOLUTELY NO WARRANTY; for details\n" \
     "type 'warranty'.  This is free software, and you are welcome\n" \
     "to redistribute it under certain conditions; see COPYING\n" \
     "(included in the Mausezahn source package) for details.\n\n" \
     "For Mausezahn NEWS visit http://www.perihel.at/sec/mz/\n\n"


#define MZ_WARRANTY_TEXT \
     "\nMausezahn, version " MAUSEZAHN_VERSION_SHORT " - a fast versatile traffic generator.\n" \
     "Copyright (C) 2007-2009 by Herbert Haas ~ www.perihel.at\n" \
     "\n" \
     "This program is free software; you can redistribute it and/or modify it under\n" \
     "the terms of the GNU General Public License version 2 as published by the \n" \
     "Free Software Foundation.\n" \
     "\n" \
     "This program is distributed in the hope that it will be useful, but WITHOUT\n" \
     "ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS\n" \
     "FOR A PARTICULAR PURPOSE. See the GNU General Public License for more \n" \
     "details.\n" \
     "\n" \
     "You should have received a copy of the GNU General Public License along with\n" \
     "this program; if not, see http://www.gnu.org/licenses/gpl-2.0.html\n\n" 

#define MZ_PROMPT "mz-" MAUSEZAHN_VERSION_SHORT

#define MZ_DEFAULT_USERNAME "mz"
#define MZ_DEFAULT_PASSWORD "mz"
#define MZ_DEFAULT_ENABLE_PASSWORD "mops"
#define MZ_DEFAULT_PORT     25542     // Towel day and 42

struct cli_def *gcli;

char mz_username[32];
char mz_password[32];
char mz_enable[32];
int mz_port;
struct mops *clipkt; // actual packet used by CLI thread
	
int clidev;

// =================================================================
int cli_debug;

// Flags from 0x0000 to 0xFFFF
// cli_debug & 8000  => Developer specific debugs
// cli_debug & 0001  => Packet transmission debugging
// ...

// =================================================================


///////////////////////////////////////////////////////////////////////////////
// Prototypes

void mz_cli_init();
int cli_read_cfg(char *str);
int mz_def16 (char *def, u_int16_t val, char *str256);
int cli();

int debug_all (struct cli_def *cli, char *command, char *argv[], int argc);
int debug_packet (struct cli_def *cli, char *command, char *argv[], int argc);

int cmd_end_to_config(struct cli_def *cli, char *command, char *argv[], int argc);
int tx_switch(struct cli_def *cli);
int cmd_test(struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_reset_interface (struct cli_def *cli, char *command, char *argv[], int argc);
  
int show_system(struct cli_def *cli, char *command, char *argv[], int argc);
int show_packets(struct cli_def *cli, char *command, char *argv[], int argc);
int show_set(struct cli_def *cli, char *command, char *argv[], int argc);
int show_interfaces(struct cli_def *cli, char *command, char *argv[], int argc);
int show_mops(struct cli_def *cli, char *command, char *argv[], int argc);
int show_arp (struct cli_def *cli, char *command, char *argv[], int argc);

int cmd_set(struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_run_id (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_run_name (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_run_sequence (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_run_all (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_stop (struct cli_def *cli, char *command, char *argv[], int argc);

int launch_bpdu (struct cli_def *cli, char *command, char *argv[], int argc);
int launch_synflood (struct cli_def *cli, char *command, char *argv[], int argc);

int stop_mausezahn(struct cli_def *cli, char *command, char *argv[], int argc);
int warranty(struct cli_def *cli, char *command, char *argv[], int argc);
int transmit (struct cli_def *cli, char *command, char *argv[], int argc);
int clear_all(struct cli_def *cli, char *command, char *argv[], int argc);
int clear_packet(struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_reset_packet(struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_load (struct cli_def *cli, char *command, char *argv[], int argc);

int enter_interface (struct cli_def *cli, char *command, char *argv[], int argc);
int conf_ip_address (struct cli_def *cli, char *command, char *argv[], int argc);
int conf_mac_address (struct cli_def *cli, char *command, char *argv[], int argc);
int conf_tag_dot1q (struct cli_def *cli, char *command, char *argv[], int argc);
int conf_tag_mpls (struct cli_def *cli, char *command, char *argv[], int argc);

int conf_frame_limit (struct cli_def *cli, char *command, char *argv[], int argc);

int conf_sequence (struct cli_def *cli, char *command, char *argv[], int argc);
int sequence_add (struct cli_def *cli, char *command, char *argv[], int argc);
int sequence_delay (struct cli_def *cli, char *command, char *argv[], int argc);
int sequence_remove (struct cli_def *cli, char *command, char *argv[], int argc);
int sequence_show (struct cli_def *cli, char *command, char *argv[], int argc);


int enter_packet (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_packet_type(struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_packet_end(struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_packet_clone (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_packet_name (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_packet_description (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_packet_count (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_packet_delay (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_packet_interval (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_packet_bind (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_packet_mac_address_source (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_packet_mac_address_destination (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_eth_type (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_eth_length (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_eth_llc (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_eth_snap (struct cli_def *cli, char *command, char *argv[], int argc);

int cmd_packet_dot1q (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_packet_mpls (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_packet_payload_hex (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_packet_payload_ascii (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_packet_payload_raw (struct cli_def *cli, char *command, char *argv[], int argc);

int cmd_port_source (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_port_destination (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_udp_sum (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_udp_len (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_udp_end(struct cli_def *cli, char *command, char *argv[], int argc);

int cmd_tcp_seqnr (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_tcp_acknr (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_tcp_offset (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_tcp_res (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_tcp_flags (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_tcp_cwr (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_tcp_ece (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_tcp_urg (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_tcp_ack (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_tcp_psh (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_tcp_rst (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_tcp_syn (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_tcp_fin (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_tcp_window (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_tcp_sum (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_tcp_urgptr(struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_tcp_options (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_tcp_end(struct cli_def *cli, char *command, char *argv[], int argc);

int cmd_dns_query(struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_dns_answer(struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_dns_ttl(struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_dns_end(struct cli_def *cli, char *command, char *argv[], int argc);

int cmd_arp_hwtype (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_arp_prtype (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_arp_hwaddrsize (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_arp_praddrsize (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_arp_opcode (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_arp_smac (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_arp_sip (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_arp_tmac (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_arp_tip (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_arp_trailer (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_arp_end(struct cli_def *cli, char *command, char *argv[], int argc);

int cmd_bpdu_id (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_bpdu_version (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_bpdu_type (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_bpdu_flags (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_bpdu_rid (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_bpdu_pc (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_bpdu_bid (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_bpdu_pid (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_bpdu_age (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_bpdu_maxage (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_bpdu_hello (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_bpdu_fwd (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_bpdu_mode (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_bpdu_vlan(struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_bpdu_end(struct cli_def *cli, char *command, char *argv[], int argc);

int cmd_igmpv2_genquery (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_igmpv2_specquery (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_igmpv2_report (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_igmpv2_leave (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_igmpv1_query (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_igmpv1_report (struct cli_def *cli, char *command, char *argv[], int argc);

int cmd_lldp_conformance (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_lldp_chassis_id (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_lldp_port_id (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_lldp_ttl (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_lldp_vlan (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_lldp_opt_tlv (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_lldp_opt_tlv_bad (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_lldp_opt_org (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_lldp_endtlv (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_lldp_reset (struct cli_def *cli, char *command, char *argv[], int argc);

int cmd_ip_address_source (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_ip_address_destination (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_ip_version (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_ip_ttl (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_ip_protocol (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_ip_hlen (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_ip_len (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_ip_id (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_ip_offset (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_ip_sum (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_ip_tos (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_ip_dscp (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_ip_rsv (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_ip_df (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_ip_mf (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_ip_fragsize (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_ip_fragoverlap (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_ip_option (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_ip_delivery (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_ip_end(struct cli_def *cli, char *command, char *argv[], int argc);

int cmd_rtp_version (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_rtp_padding (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_rtp_xten (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_rtp_marker (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_rtp_cc (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_rtp_pt (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_rtp_ssrc (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_rtp_sqnr (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_rtp_time (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_rtp_extension (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_rtp_source (struct cli_def *cli, char *command, char *argv[], int argc);
int cmd_rtp_cclist (struct cli_def *cli, char *command, char *argv[], int argc);

#endif


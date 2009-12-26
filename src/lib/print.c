/* XXX: Coding Style - use the tool indent with the following (Linux kernel
 *                     code indents)
 *
 * indent -nbad -bap -nbc -bbo -hnl -br -brs -c33 -cd33 -ncdb -ce -ci4  \
 *        -cli0 -d0 -di1 -nfc1 -i8 -ip0 -l80 -lp -npcs -nprs -npsl -sai \
 *        -saf -saw -ncs -nsc -sob -nfca -cp33 -ss -ts8 -il1
 *
 *
 * netsniff-ng
 *
 * High performance network sniffer for packet inspection
 *
 * Copyright (C) 2009, 2010  Daniel Borkmann <danborkmann@googlemail.com>
 *
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation; either version 2 of the License, or (at 
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License 
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
 *
 * Note: Your kernel has to be compiled with CONFIG_PACKET_MMAP=y option in 
 *       order to use this.
 */

/*
 * Contains: 
 *    Packet printing routines
 */

/*
 * XXX: Some thoughts:
 *    There could be several printing modes for several needs ... e.g.
 *        * A mode that only prints IPs and their corresponding MACs to 
 *          debug ARP related stuff
 *        * A mode that only prints DNS lookups
 *        * A mode that greps for plaintext passwords
 *        * ...
 *    These functions will be registered during startup to a global list 
 *    ids --> will be shown within -h or -ids and can be selected by user, 
 *    so we have kinda plugin system.
 *
 * XXX: Some more thoughts:
 *    We have a plugin system... plugin/ folder. A plugin consists of 
 *    a static BPF code to load and a special print function, so we can define 
 *    special things for special purposes.
 *    These plugins will be called via command param and the ids are shown 
 *    within help (-h), so users can contribute special plugins ;)
 */

#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <linux/if.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>

#include <netsniff-ng/macros.h>
#include <netsniff-ng/types.h>
#include <netsniff-ng/print.h>

static void inline dump_hex(const char *desc, ring_buff_bytes_t * buff, int len)
{
	dbg("%s", desc);

	while (len--) {
		dbg("%.2x ", *buff);
		buff++;
	}

	dbg("\n");
}

/*
 * Just plain dumb formatting, for -ccc
 */
static void inline dump_ethhdr_all(struct ethhdr *eth)
{
	dbg("  Ethernet Hdr\n");

	dump_hex("    Dst MAC:   ", eth->h_dest, ETH_ALEN);
	dump_hex("    Src MAC:   ", eth->h_source, ETH_ALEN);
	dump_hex("    Proto:     ", (ring_buff_bytes_t *) & eth->h_proto, 2);
}

/*
 * Just plain dumb formatting, for -ccc
 */
static void inline dump_iphdr_all(struct iphdr *ip)
{
	dbg("  IP Hdr\n");

	dbg("    Dst Addr:  %u.%u.%u.%u\n", ((uint8_t *) & ip->daddr)[0],
	    ((uint8_t *) & ip->daddr)[1], ((uint8_t *) & ip->daddr)[2],
	    ((uint8_t *) & ip->daddr)[3]);
	dbg("    Src Addr:  %u.%u.%u.%u\n", ((uint8_t *) & ip->saddr)[0],
	    ((uint8_t *) & ip->saddr)[1], ((uint8_t *) & ip->saddr)[2],
	    ((uint8_t *) & ip->saddr)[3]);
	dbg("    Proto:     %u\n", ip->protocol);
	dbg("    TTL:       %u\n", ip->ttl);
	dbg("    TOS:       %u\n", ntohs(ip->tos));
	dbg("    Version:   %u\n", ntohs(ip->version));
	dbg("    IHL:       %u\n", ntohs(ip->ihl));
	dbg("    Total len: %u\n", ntohs(ip->tot_len));
	dbg("    ID:        %u\n", ntohs(ip->id));
	dbg("    Frag off:  %u\n", ip->frag_off);
	dbg("    Checksum:  %x\n", ntohs(ip->check));
}

/*
 * Just plain dumb formatting, for -ccc
 */
static void inline dump_tcphdr_all(struct tcphdr *tcp)
{
	dbg("  TCP Hdr\n");

	dbg("    Src Port:  %u\n", ntohs(tcp->source));
	dbg("    Dst Port:  %u\n", ntohs(tcp->dest));
	dbg("    SN:        %x\n", ntohs(tcp->seq));
	dbg("    AckN:      %x\n", ntohs(tcp->ack_seq));
	dbg("    Data off:  %d\n", ntohs(tcp->doff));
	dbg("    Res 1:     %d\n", ntohs(tcp->res1));
	dbg("    Flags:\n");

	if (tcp->urg == 1) {
		dbg("        URG\n");
	}
	if (tcp->ack == 1) {
		dbg("        ACK\n");
	}
	if (tcp->psh == 1) {
		dbg("        PSH\n");
	}
	if (tcp->rst == 1) {
		dbg("        RST\n");
	}
	if (tcp->syn == 1) {
		dbg("        SYN\n");
	}
	if (tcp->fin == 1) {
		dbg("        FIN\n");
	}
	if (tcp->ece == 1) {
		dbg("        ECE\n");
	}
	if (tcp->cwr == 1) {
		dbg("        CWR\n");
	}

	dbg("    Window:    %d\n", ntohs(tcp->window));
	dbg("    Hdr sum:   %d\n", ntohs(tcp->check));
	dbg("    Urg ptr:   %u\n", ntohs(tcp->urg_ptr));
}

/**
 * print_packet_buffer_mode_1 - Prints packets according to verbose mode -c
 * @rbb:                       payload
 * @len:                       len of payload
 */
void print_packet_buffer_mode_1(ring_buff_bytes_t * rbb, int len)
{
	dbg("%d Byte\n", len);

	dump_ethhdr_all((struct ethhdr *)rbb);

	/* Check for IP */
	if (ntohs(((struct ethhdr *)rbb)->h_proto) == ETH_P_IP) {
		dump_iphdr_all((struct iphdr *)(rbb + sizeof(struct ethhdr)));

//                /* Check for TCP */
//                if(ntohs(((struct iphdr *) (rbb + sizeof(struct ethhdr)))->protocol) == )
//                {
//                        dump_tcphdr_all((struct tcphdr *) (rbb + sizeof(struct ethhdr) + sizeof(struct iphdr)));
//                }
	}
}

/**
 * print_packet_buffer_mode_2 - Prints packets according to verbose mode -cc
 * @rbb:                       payload
 * @len:                       len of payload
 */
void print_packet_buffer_mode_2(ring_buff_bytes_t * rbb, int len)
{
	dbg("%d Byte\n", len);

	/* Print proto stuff */
	dbg("  T: 0x%02x%02x\n", rbb[12], rbb[13]);

	/* Source host stuff */
	dbg("  S: %02x:%02x:%02x:%02x:%02x:%02x\n",
	    rbb[6], rbb[7], rbb[8], rbb[9], rbb[10], rbb[11]);

	/* Destination host stuff */
	dbg("  D: %02x:%02x:%02x:%02x:%02x:%02x\n",
	    rbb[0], rbb[1], rbb[2], rbb[3], rbb[4], rbb[5]);

	/* Print MAC Manufacturer */

	/* Print TCP Flags, UDP'n'stuff */

	/* Check checksum --> Print if bogus */
}

/**
 * print_packet_buffer_mode_3 - Prints packets according to verbose mode -ccc
 * @rbb:                       payload
 * @len:                       len of payload
 */
void print_packet_buffer_mode_3(ring_buff_bytes_t * rbb, int len)
{
	dbg("%d Byte\n", len);

	/* Print proto stuff */
	dbg("  T: 0x%02x%02x\n", rbb[12], rbb[13]);

	/* Source host stuff */
	dbg("  S: %02x:%02x:%02x:%02x:%02x:%02x\n",
	    rbb[6], rbb[7], rbb[8], rbb[9], rbb[10], rbb[11]);

	/* Destination host stuff */
	dbg("  D: %02x:%02x:%02x:%02x:%02x:%02x\n",
	    rbb[0], rbb[1], rbb[2], rbb[3], rbb[4], rbb[5]);

	/* Print whole payload, readable and bytewise */
}

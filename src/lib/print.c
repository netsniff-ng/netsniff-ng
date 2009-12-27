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
#include <ctype.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <linux/if.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <netsniff-ng/macros.h>
#include <netsniff-ng/types.h>
#include <netsniff-ng/print.h>

static void inline dump_hex(ring_buff_bytes_t * buff, int len)
{
	while (len-- > 0) {
		dbg("%.2x ", *buff);
		buff++;
	}
}

static void inline dump_printable(ring_buff_bytes_t * buff, int len)
{
	while (len-- > 0) {
		dbg("%c ", (isprint(*buff) ? *buff : '.'));
		buff++;
	}
}

/*
 * dump_ethhdr_all - Just plain dumb formatting, for -ccc
 * @eth:            ethernet header
 */
static void inline dump_ethhdr_all(struct ethhdr *eth)
{
	dbg(" [ ");

	dbg("MAC (%.2x:%.2x:%.2x:%.2x:%.2x:%.2x => %.2x:%.2x:%.2x:%.2x:%.2x:%.2x), ",
	    /* Source MAC */
	    ((uint8_t *) eth->h_source)[6], ((uint8_t *) eth->h_source)[7],
	    ((uint8_t *) eth->h_source)[8], ((uint8_t *) eth->h_source)[9],
	    ((uint8_t *) eth->h_source)[10], ((uint8_t *) eth->h_source)[11],
	    /* Destination MAC */
	    ((uint8_t *) eth->h_dest)[0], ((uint8_t *) eth->h_dest)[1],
	    ((uint8_t *) eth->h_dest)[2], ((uint8_t *) eth->h_dest)[3],
	    ((uint8_t *) eth->h_dest)[4], ((uint8_t *) eth->h_dest)[5]);

	dbg("Proto (0x%.2x%.2x)",
	    ((uint8_t *) & eth->h_proto)[0], ((uint8_t *) & eth->h_proto)[1]);

	dbg(" ] ");
}

/*
 * dump_iphdr_all - Just plain dumb formatting, for -ccc
 * @ip:            ip header
 */
static void inline dump_iphdr_all(struct iphdr *ip)
{
	dbg(" [ ");

	dbg("Addr (%u.%u.%u.%u => %u.%u.%u.%u), ",
	    ((uint8_t *) & ip->saddr)[0], ((uint8_t *) & ip->saddr)[1],
	    ((uint8_t *) & ip->saddr)[2], ((uint8_t *) & ip->saddr)[3],
	    ((uint8_t *) & ip->daddr)[0], ((uint8_t *) & ip->daddr)[1],
	    ((uint8_t *) & ip->daddr)[2], ((uint8_t *) & ip->daddr)[3]);

	dbg("Proto (%u), ", ip->protocol);
	dbg("TTL (%u), ", ip->ttl);
	dbg("TOS (%u), ", ntohs(ip->tos));
	dbg("Ver (%u), ", ntohs(ip->version));
	dbg("IHL (%u), ", ntohs(ip->ihl));
	dbg("Tlen (%u), ", ntohs(ip->tot_len));
	dbg("ID (%u), ", ntohs(ip->id));
	dbg("Frag off (%u), ", ip->frag_off);
	dbg("Chsum (0x%x)", ntohs(ip->check));

	dbg(" ] ");
}

/*
 * dump_udphdr_all - Just plain dumb formatting, for -ccc
 * @udp:            udp header
 */
static void inline dump_udphdr_all(struct udphdr *udp)
{
	dbg(" [ ");

	dbg("Port (%u => %u), ", ntohs(udp->source), ntohs(udp->dest));
	dbg("Len (%u), ", ntohs(udp->len));
	dbg("Chsum (0x%x)", ntohs(udp->check));

	dbg(" ] ");
}

/*
 * dump_tcphdr_all - Just plain dumb formatting, for -ccc
 * @tcp:            tcp header
 */
static void inline dump_tcphdr_all(struct tcphdr *tcp)
{
	dbg(" [ ");

	dbg("Port (%u => %u), ", ntohs(tcp->source), ntohs(tcp->dest));
	dbg("SN (0x%x), ", ntohs(tcp->seq));
	dbg("AN (0x%x), ", ntohs(tcp->ack_seq));
	dbg("Data off (%d), ", ntohs(tcp->doff));
	dbg("Res 1 (%d), ", ntohs(tcp->res1));

	dbg("Flags (");

	if (tcp->urg == 1) {
		dbg("URG ");
	}
	if (tcp->ack == 1) {
		dbg("ACK ");
	}
	if (tcp->psh == 1) {
		dbg("PSH ");
	}
	if (tcp->rst == 1) {
		dbg("RST ");
	}
	if (tcp->syn == 1) {
		dbg("SYN ");
	}
	if (tcp->fin == 1) {
		dbg("FIN ");
	}
	if (tcp->ece == 1) {
		dbg("ECE ");
	}
	if (tcp->cwr == 1) {
		dbg("CWR ");
	}

	dbg("), ");

	dbg("Window (%d), ", ntohs(tcp->window));
	dbg("Hdrsum (0x%x), ", ntohs(tcp->check));
	dbg("Urg ptr (%u)", ntohs(tcp->urg_ptr));

	dbg(" ] ");
}

/*
 * dump_payload_hex_all - Just plain dumb formatting, for -ccc
 * @rbb:                 payload bytes
 * @len:                 len
 */
static void inline dump_payload_hex_all(ring_buff_bytes_t * rbb, int len)
{
	dbg(" [ Payload hex  (");
	dump_hex(rbb, len);
	dbg(") ] ");
}

/*
 * dump_payload_char_all - Just plain dumb formatting, for -ccc
 * @rbb:                  payload bytes
 * @len:                  len
 */
static void inline dump_payload_char_all(ring_buff_bytes_t * rbb, int len)
{
	dbg(" [ Payload char (");
	dump_printable(rbb, len);
	dbg(") ] ");
}

/**
 * print_packet_buffer_mode_1 - Prints packets according to verbose mode -c
 * @rbb:                       payload
 * @tp:                        kernel packet header
 */
void print_packet_buffer_mode_1(ring_buff_bytes_t * rbb,
				const struct tpacket_hdr *tp)
{
	size_t off_n, off_o;

	dbg("%d Byte, %u.%u s \n", tp->tp_len, tp->tp_sec, tp->tp_usec);	/*tp->tp_snaplen, */

	dump_ethhdr_all((struct ethhdr *)rbb);
	dbg("\n");
	off_n = sizeof(struct ethhdr);

	/* Check for IP */
	if (ntohs(((struct ethhdr *)rbb)->h_proto) == ETH_P_IP) {
		dump_iphdr_all((struct iphdr *)(rbb + off_n));
		dbg("\n");
		off_o = off_n;
		off_n += sizeof(struct iphdr);

		/* Check for TCP */
		if (((struct iphdr *)(rbb + off_o))->protocol == IPPROTO_TCP) {
			dump_tcphdr_all((struct tcphdr *)(rbb + off_n));
			dbg("\n");
			off_o = off_n;
			off_n += sizeof(struct tcphdr);
		} else if (((struct iphdr *)(rbb + off_o))->protocol ==
			   IPPROTO_UDP) {
			dump_udphdr_all((struct udphdr *)(rbb + off_n));
			dbg("\n");
			off_o = off_n;
			off_n += sizeof(struct udphdr);
		}
	}

	dump_payload_hex_all(rbb + off_n, (tp->tp_len - off_n));
	dbg("\n");
	dump_payload_char_all(rbb + off_n, (tp->tp_len - off_n));
	dbg("\n");

	dbg("\n");
}

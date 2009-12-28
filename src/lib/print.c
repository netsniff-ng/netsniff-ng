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
#include <netsniff-ng/system.h>

static void inline dump_hex(ring_buff_bytes_t * buff, int len, size_t tty_len,
			    size_t tty_off)
{
	for (; len-- > 0; tty_off += 3, buff++) {
		if (unlikely(tty_off >= tty_len - 3)) {
			info("\n   ");
			tty_off = 0;
		}
		info("%.2x ", *buff);
	}
}

static void inline dump_printable(ring_buff_bytes_t * buff, int len,
				  size_t tty_len, size_t tty_off)
{
	for (; len-- > 0; tty_off += 2, buff++) {
		if (unlikely(tty_off >= tty_len - 3)) {
			info("\n   ");
			tty_off = 0;
		}
		info("%c ", (isprint(*buff) ? *buff : '.'));
	}
}

/*
 * dump_ethhdr_all - Just plain dumb formatting, for -ccc
 * @eth:            ethernet header
 */
static void inline dump_ethhdr_all(struct ethhdr *eth)
{
	info(" [ ");

	info("MAC (%.2x:%.2x:%.2x:%.2x:%.2x:%.2x => %.2x:%.2x:%.2x:%.2x:%.2x:%.2x), ",
	     /* Source MAC */
	     ((uint8_t *) eth->h_source)[6], ((uint8_t *) eth->h_source)[7],
	     ((uint8_t *) eth->h_source)[8], ((uint8_t *) eth->h_source)[9],
	     ((uint8_t *) eth->h_source)[10], ((uint8_t *) eth->h_source)[11],
	     /* Destination MAC */
	     ((uint8_t *) eth->h_dest)[0], ((uint8_t *) eth->h_dest)[1],
	     ((uint8_t *) eth->h_dest)[2], ((uint8_t *) eth->h_dest)[3],
	     ((uint8_t *) eth->h_dest)[4], ((uint8_t *) eth->h_dest)[5]);

	info("Proto (0x%.2x%.2x)",
	     ((uint8_t *) & eth->h_proto)[0], ((uint8_t *) & eth->h_proto)[1]);

	info(" ] ");
}

/*
 * dump_iphdr_all - Just plain dumb formatting, for -ccc
 * @ip:            ip header
 */
static void inline dump_iphdr_all(struct iphdr *ip)
{
	info(" [ ");

	info("Addr (%u.%u.%u.%u => %u.%u.%u.%u), ",
	     ((uint8_t *) & ip->saddr)[0], ((uint8_t *) & ip->saddr)[1],
	     ((uint8_t *) & ip->saddr)[2], ((uint8_t *) & ip->saddr)[3],
	     ((uint8_t *) & ip->daddr)[0], ((uint8_t *) & ip->daddr)[1],
	     ((uint8_t *) & ip->daddr)[2], ((uint8_t *) & ip->daddr)[3]);

	info("Proto (%u), ", ip->protocol);
	info("TTL (%u), ", ip->ttl);
	info("TOS (%u), ", ntohs(ip->tos));
	info("Ver (%u), ", ntohs(ip->version));
	info("IHL (%u), ", ntohs(ip->ihl));
	info("Tlen (%u), ", ntohs(ip->tot_len));
	info("ID (%u), ", ntohs(ip->id));
	info("Frag off (%u), ", ip->frag_off);
	info("Chsum (0x%x)", ntohs(ip->check));

	info(" ] ");
}

/*
 * dump_udphdr_all - Just plain dumb formatting, for -ccc
 * @udp:            udp header
 */
static void inline dump_udphdr_all(struct udphdr *udp)
{
	info(" [ ");

	info("Port (%u => %u), ", ntohs(udp->source), ntohs(udp->dest));
	info("Len (%u), ", ntohs(udp->len));
	info("Chsum (0x%x)", ntohs(udp->check));

	info(" ] ");
}

/*
 * dump_tcphdr_all - Just plain dumb formatting, for -ccc
 * @tcp:            tcp header
 */
static void inline dump_tcphdr_all(struct tcphdr *tcp)
{
	info(" [ ");

	info("Port (%u => %u), ", ntohs(tcp->source), ntohs(tcp->dest));
	info("SN (0x%x), ", ntohs(tcp->seq));
	info("AN (0x%x), ", ntohs(tcp->ack_seq));
	info("Data off (%d), ", ntohs(tcp->doff));
	info("Res 1 (%d), ", ntohs(tcp->res1));

	info("Flags (");

	if (tcp->urg == 1) {
		info("URG ");
	}
	if (tcp->ack == 1) {
		info("ACK ");
	}
	if (tcp->psh == 1) {
		info("PSH ");
	}
	if (tcp->rst == 1) {
		info("RST ");
	}
	if (tcp->syn == 1) {
		info("SYN ");
	}
	if (tcp->fin == 1) {
		info("FIN ");
	}
	if (tcp->ece == 1) {
		info("ECE ");
	}
	if (tcp->cwr == 1) {
		info("CWR ");
	}

	info("), ");

	info("Window (%d), ", ntohs(tcp->window));
	info("Hdrsum (0x%x), ", ntohs(tcp->check));
	info("Urg ptr (%u)", ntohs(tcp->urg_ptr));

	info(" ] ");
}

/*
 * dump_payload_hex_all - Just plain dumb formatting, for -ccc
 * @rbb:                 payload bytes
 * @len:                 len
 */
static void inline dump_payload_hex_all(ring_buff_bytes_t * rbb, int len,
					int tty_len)
{
	info(" [ Payload hex  (");
	dump_hex(rbb, len, tty_len, 14);
	info(") ] ");
}

/*
 * dump_payload_char_all - Just plain dumb formatting, for -ccc
 * @rbb:                  payload bytes
 * @len:                  len
 */
static void inline dump_payload_char_all(ring_buff_bytes_t * rbb, int len,
					 int tty_len)
{
	info(" [ Payload char (");
	dump_printable(rbb, len, tty_len, 14);
	info(") ] ");
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
	int tty_len = get_tty_length();

	info("%d Byte, %u.%u s \n", tp->tp_len, tp->tp_sec, tp->tp_usec);

	dump_ethhdr_all((struct ethhdr *)rbb);
	info("\n");
	off_n = sizeof(struct ethhdr);

	/* Check for IP */
	if (ntohs(((struct ethhdr *)rbb)->h_proto) == ETH_P_IP) {
		dump_iphdr_all((struct iphdr *)(rbb + off_n));
		info("\n");
		off_o = off_n;
		off_n += sizeof(struct iphdr);

		/* Check for TCP */
		if (((struct iphdr *)(rbb + off_o))->protocol == IPPROTO_TCP) {
			dump_tcphdr_all((struct tcphdr *)(rbb + off_n));
			info("\n");
			off_o = off_n;
			off_n += sizeof(struct tcphdr);
		} else if (((struct iphdr *)(rbb + off_o))->protocol ==
			   IPPROTO_UDP) {
			dump_udphdr_all((struct udphdr *)(rbb + off_n));
			info("\n");
			off_o = off_n;
			off_n += sizeof(struct udphdr);
		}
	}

	dump_payload_hex_all(rbb + off_n, (tp->tp_len - off_n), tty_len - 20);
	info("\n");
	dump_payload_char_all(rbb + off_n, (tp->tp_len - off_n), tty_len - 20);
	info("\n");

	info("\n");
}

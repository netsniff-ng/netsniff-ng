/* XXX: Coding Style - use the tool indent with the following (Linux kernel
 *                     code indents)
 *
 * indent -nbad -bap -nbc -bbo -hnl -br -brs -c33 -cd33 -ncdb -ce -ci4   \
 *        -cli0 -d0 -di1 -nfc1 -i8 -ip0 -l120 -lp -npcs -nprs -npsl -sai \
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
#include <assert.h>
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

uint8_t is_on(const uint64_t value, const uint64_t bitmask)
{
	return(((value & bitmask) == bitmask) ? 1 : 0);
}

/*
 * dump_hex - Prints payload as bytes to our tty
 * @buff:          payload
 * @len:           len of buff
 * @tty_len:       width of terminal
 * @tty_off:       current offset of tty_len
 */
void dump_hex(const void const * to_print, int len, size_t tty_len, size_t tty_off)
{
	assert(to_print);

	uint8_t * buff = (uint8_t *) to_print;

	for (; len-- > 0; tty_off += 3, buff++) {
		if (unlikely(tty_off >= tty_len - 3)) {
			info("\n   ");
			tty_off = 0;
		}
		info("%.2x ", *buff);
	}
}

/*
 * dump_printable - Prints human readable chars to our tty
 * @buff:          payload
 * @len:           len of buff
 * @tty_len:       width of terminal
 * @tty_off:       current offset of tty_len
 */
void dump_printable(const void const * to_print, int len, size_t tty_len, size_t tty_off)
{
	assert(to_print);

	uint8_t * buff = (uint8_t *) to_print;

	for (; len-- > 0; tty_off += 2, buff++) {
		if (unlikely(tty_off >= tty_len - 3)) {
			info("\n   ");
			tty_off = 0;
		}
		info("%c ", (isprint(*buff) ? *buff : '.'));
	}
}

/*
 * dump_ethhdr_all - Just plain dumb formatting
 * @eth:            ethernet header
 */
void dump_ethhdr_all(struct ethhdr *eth)
{	
	uint8_t * src_mac = eth->h_source;
	uint8_t * dst_mac = eth->h_dest;
	__be16 proto;

	assert(eth);
	proto = eth->h_proto;

	info(" [ ");

	info("MAC (%.2x:%.2x:%.2x:%.2x:%.2x:%.2x => %.2x:%.2x:%.2x:%.2x:%.2x:%.2x), ",src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5], dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);

	info("Proto (0x%.4x)", ntohs(proto));

	info(" ] ");
}

/*
 * dump_iphdr_all - Just plain dumb formatting
 * @ip:            ip header
 */
void dump_iphdr_all(struct iphdr *ip)
{
	/* XXX Version check */
	assert(ip);
	char src_ip[INET_ADDRSTRLEN] = {0};
	char dst_ip[INET_ADDRSTRLEN] = {0};
	uint16_t printable_frag_off;

	if (ip->version != IPVERSION)
	{
		info("Version is %u %u\n", ip->version, ntohs(ip->version));
		return;
	}

	inet_ntop(AF_INET, &ip->saddr, src_ip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ip->daddr, dst_ip, INET_ADDRSTRLEN);
	printable_frag_off = ntohs(ip->frag_off);

	info(" [ IP ");
	info("Addr (%s => %s), ", src_ip, dst_ip);
	info("Proto (%u), ", ip->protocol);
	info("TTL (%u), ", ip->ttl);
	info("TOS (%u), ", ip->tos);
	info("Ver (%u), ", ip->version);
	info("IHL (%u), ", ntohs(ip->ihl));
	info("Tlen (%u), ", ntohs(ip->tot_len));
	info("ID (%u), ", ntohs(ip->id));
	/* FIXME fragoff is fragment offset + flags */
	info("Res: %u NoFrag: %u MoreFrag: %u offset (%u), ", is_on(printable_frag_off, 1<<15), is_on(printable_frag_off, 1<<14), is_on(printable_frag_off, 1<<13), printable_frag_off & (1<<12));
	info("Chsum (0x%x)", ntohs(ip->check));

	info(" ] ");
}

/*
 * dump_udphdr_all - Just plain dumb formatting
 * @udp:            udp header
 */
void dump_udphdr_all(struct udphdr *udp)
{
	info(" [ UDP ");

	info("Port (%u => %u), ", ntohs(udp->source), ntohs(udp->dest));
	info("Len (%u), ", ntohs(udp->len));
	info("Chsum (0x%x)", ntohs(udp->check));

	info(" ] ");
}

/*
 * dump_tcphdr_all - Just plain dumb formatting
 * @tcp:            tcp header
 */
static void inline dump_tcphdr_all(struct tcphdr *tcp)
{
	info(" [ TCP ");

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
 * dump_payload_hex_all - Just plain dumb formatting
 * @rbb:                 payload bytes
 * @len:                 len
 * @tty_len:             width of terminal
 */
static void inline dump_payload_hex_all(const uint8_t * const rbb, int len, int tty_len)
{
	info(" [ Payload hex  (");
	dump_hex(rbb, len, tty_len, 14);
	info(") ] ");
}

/*
 * dump_payload_char_all - Just plain dumb formatting
 * @rbb:                  payload bytes
 * @len:                  len
 * @tty_len:              width of terminal
 */
static void inline dump_payload_char_all(const uint8_t * const rbb, int len, int tty_len)
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
void print_packet_buffer_mode_1(ring_buff_bytes_t * rbb, const struct tpacket_hdr *tp)
{
	size_t l2_offset, l3_offset;
	uint16_t l2_flags = 0, l3_flags = 0;
	int tty_len = get_tty_length();

	assert(rbb);
	assert(tp);

	l2_flags = ntohs(((struct ethhdr *)rbb)->h_proto);

	info("%d Byte, Timestamp (%u.%u s) \n", tp->tp_len, tp->tp_sec, tp->tp_usec);

	dump_ethhdr_all((struct ethhdr *)rbb);
	info("\n");
	l2_offset = sizeof(struct ethhdr);

	switch(l2_flags)
	{
		case ETH_P_IP:
			l3_offset = sizeof(struct iphdr);
			dump_iphdr_all((struct iphdr *)(rbb + l2_offset));
			l3_flags = ((struct iphdr *)(rbb + l2_offset))->protocol;

			switch(l3_flags)
			{
				case IPPROTO_TCP:
					dump_tcphdr_all((struct tcphdr *)(rbb + l2_offset + l3_offset));
				break;

				case IPPROTO_UDP:
					dump_udphdr_all((struct udphdr *)(rbb + l2_offset + l3_offset));
				break;

				default:
					info("protocol %x not supported\n", l3_flags);
				break;
			}
		break;

		default:
			info("Ethertype %x not supported\n", l2_flags);
		break;
		info("\n");
	}

	/* FIXME, the last LSB of the payload are not the same as what is taken from wireshark */
	dump_payload_hex_all(rbb + l2_offset + l3_offset, tp->tp_len - l2_offset - l3_offset, tty_len - 20);
	info("\n");
	dump_payload_char_all(rbb + l2_offset + l3_offset, tp->tp_len - l2_offset - l3_offset, tty_len - 20);
	info("\n");

	info("\n");
}

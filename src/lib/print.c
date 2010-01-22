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
 * Copyright (C) 2009, 2010  Daniel Borkmann <danborkmann@googlemail.com> and 
 *                           Emmanuel Roullit <emmanuel.roullit@googlemail.com>
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
#include <netsniff-ng/print/l2/ethernet.h>
#include <netsniff-ng/print/l2/vlan.h>
#include <netsniff-ng/print/l2/arp.h>
#include <netsniff-ng/print/l3/ip.h>
#include <netsniff-ng/print/l3/ipv6.h>
#include <netsniff-ng/print/l4/tcp.h>
#include <netsniff-ng/print/l4/udp.h>
#include <netsniff-ng/packet.h>
#include <netsniff-ng/system.h>

/*
 * dump_hex - Prints payload as bytes to our tty
 * @buff:          payload
 * @len:           len of buff
 * @tty_len:       width of terminal
 * @tty_off:       current offset of tty_len
 */
void dump_hex(const void const *to_print, int len, size_t tty_len, size_t tty_off)
{
	assert(to_print);

	uint8_t *buff = (uint8_t *) to_print;

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
void dump_printable(const void const *to_print, int len, size_t tty_len, size_t tty_off)
{
	assert(to_print);

	uint8_t *buff = (uint8_t *) to_print;

	for (; len-- > 0; tty_off += 2, buff++) {
		if (unlikely(tty_off >= tty_len - 3)) {
			info("\n   ");
			tty_off = 0;
		}
		info("%c ", (isprint(*buff) ? *buff : '.'));
	}
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
	info(") ]\n");
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
	info(") ]\n");
}

void versatile_print(ring_buff_bytes_t * rbb, const struct tpacket_hdr *tp)
{
	int len;
	packet_t pkt;
	uint16_t l4_type = 0;
	uint8_t *buffer = (uint8_t *) rbb;
	int tty_len = get_tty_length();

	assert(buffer);
	assert(tp);

	len = tp->tp_len;
	memset(&pkt, 0, sizeof(pkt));

	parse_packet(buffer, len, &pkt);

	info("%d Byte, Timestamp (%u.%u s) \n", tp->tp_len, tp->tp_sec, tp->tp_usec);

	print_ethhdr(pkt.ethernet_header);

	switch (get_ethertype(pkt.ethernet_header)) {
	case ETH_P_8021Q:
		print_vlan(pkt.vlan_header);
		break;

	case ETH_P_ARP:
		print_arphdr(pkt.arp_header);
		break;

	case ETH_P_IP:
		print_iphdr(pkt.ip_header);
		l4_type = get_l4_type_from_ipv4(pkt.ip_header);
		break;

	case ETH_P_IPV6:
		print_ipv6hdr(pkt.ipv6_header);
		l4_type = get_l4_type_from_ipv6(pkt.ipv6_header);
		break;
	}

	switch (l4_type) {
	case IPPROTO_TCP:
		print_tcphdr(pkt.tcp_header);
		break;

	case IPPROTO_UDP:
		print_udphdr(pkt.udp_header);
		break;

	default:

		break;
	}

	dump_payload_hex_all(pkt.payload, pkt.payload_len, tty_len - 20);
	dump_payload_char_all(pkt.payload, pkt.payload_len, tty_len - 20);

	info("\n");
	return;
}

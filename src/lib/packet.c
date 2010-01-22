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

#include <stdint.h>
#include <assert.h>

#include <netsniff-ng/packet.h>

static inline void set_pkt_step(packet_t * pkt, uint16_t type)
{
	assert(pkt);
	pkt->pkt[pkt->step++] = type;
}

int parse_packet(uint8_t * raw, uint32_t len, packet_t * pkt)
{
	uint8_t ** buffer = &raw;
	uint32_t tmp_len = len;
#error "Compile here"
	info("WTF\n");
	pkt->raw = raw;
	pkt->ethernet_header = get_ethhdr(buffer, &tmp_len);
	set_pkt_step(pkt, ETHERNET);

	/* Parse l2/l3 */
	info("Parse\n");
	switch(get_ethertype(pkt->ethernet_header))
	{
		case ETH_P_8021Q:
		case ETH_P_8021QinQ:
			pkt->vlan_header = get_vlan_hdr(buffer, &tmp_len);
			set_pkt_step(pkt, ETH_P_8021Q);
		break;

		case ETH_P_IP:
			pkt->ip_header = get_iphdr(buffer, &tmp_len);
			set_pkt_step(pkt, ETH_P_IP);
		break;

		case ETH_P_IPV6:
			pkt->ipv6_header = get_ipv6hdr(buffer, &tmp_len);
			set_pkt_step(pkt, ETH_P_IPV6);
		break;

		default:
		break;
	}

	info("%p %p %u\n", buffer, *buffer, tmp_len);
	pkt->payload = *buffer;
	pkt->payload_len = tmp_len;

	return (0);
}

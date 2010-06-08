/*
 * Copyright (C) 2009, 2010  Daniel Borkmann <daniel@netsniff-ng.org> and 
 *                           Emmanuel Roullit <emmanuel@netsniff-ng.org>
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <netdb.h>
#include <regex.h>
#include <errno.h>
#include <strings.h>

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
#include <netsniff-ng/read.h>
#include <netsniff-ng/print.h>
#include <netsniff-ng/protocols/layers_all.h>
#include <netsniff-ng/packet.h>
#include <netsniff-ng/system.h>
#include <netsniff-ng/replay.h>
#include <netsniff-ng/config.h>
#include <netsniff-ng/signal.h>
#include <netsniff-ng/bpf.h>

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

void reduced_print(ring_buff_bytes_t * rbb, const struct tpacket_hdr *tp)
{
	uint16_t l4_type = 0;	
	packet_t pkt;
	
	parse_packet(rbb, tp->tp_len, &pkt);

	info("%d Byte, %u.%u s, %s%s%s, ", tp->tp_len, tp->tp_sec, tp->tp_usec, 
					   colorize_start(bold),
					   ether_types_find_less(pkt.ethernet_header->h_proto),
					   colorize_end());

	switch (get_ethertype(pkt.ethernet_header)) {
	case ETH_P_8021Q:
		print_vlanhdr_less(pkt.vlan_header);
		break;

	case ETH_P_ARP:
		print_ethhdr_less(pkt.ethernet_header);
		print_arphdr_less(pkt.arp_header);
		break;

	case ETH_P_IP:
		print_iphdr_less(pkt.ip_header);
		l4_type = get_l4_type_from_ipv4(pkt.ip_header);
		break;

	case ETH_P_IPV6:
		print_ipv6hdr_less(pkt.ipv6_header);
		l4_type = get_l4_type_from_ipv6(pkt.ipv6_header);
		break;
	default:
		print_ethhdr_less(pkt.ethernet_header);
		break;
	}

	switch (l4_type) {
	case IPPROTO_TCP:
		print_tcphdr_less(pkt.tcp_header);
		break;

	case IPPROTO_UDP:
		print_udphdr_less(pkt.udp_header);
		break;

	case IPPROTO_ICMP:
		print_icmphdr_less(pkt.icmp_header);
		break;

	default:
		info("\n");
		break;
	}	
}

static regex_t *regex = NULL;

void init_regex(char *pattern)
{
	int ret;

	regex = malloc(sizeof(*regex));
	if (!regex) {
		err("Cannot malloc regex");
		exit(EXIT_FAILURE);
	}

	memset(regex, 0, sizeof(*regex));

	ret = regcomp(regex, pattern, REG_EXTENDED | REG_NOSUB);
	if (ret != 0) {
		size_t len;
		char *buffer;

		len = regerror(ret, regex, NULL, 0);
		buffer = malloc(len);
		if (!buffer) {
			err("Cannot malloc regex error buffer");
			exit(EXIT_FAILURE);
		}

		regerror(ret, regex, buffer, len);

		warn("Regular expression error: %s\n", buffer);

		free(buffer);
		regfree(regex);
		free(regex);

		exit(EXIT_FAILURE);
	}
}

void cleanup_regex(void)
{
	regfree(regex);
	free(regex);
}

void regex_print(ring_buff_bytes_t * rbb, const struct tpacket_hdr *tp)
{
	int i;

	packet_t pkt;
	uint8_t *t_rbb = NULL;

	assert(regex);

	parse_packet(rbb, tp->tp_len, &pkt);

	/* XXX: This is a very slow path! */
	t_rbb = malloc(pkt.payload_len + 1);
	if (!t_rbb) {
		err("Cannot malloc t_rbb");
		exit(EXIT_FAILURE);
	}

	/* If we won't copy, regexec stops at the first \0 byte :( */
	for (i = 0; i < pkt.payload_len; ++i) {
		t_rbb[i] = (isprint(pkt.payload[i]) ? pkt.payload[i] : '.');
	}

	t_rbb[pkt.payload_len] = 0;
	if (regexec(regex, (char *)t_rbb, 0, NULL, 0) != REG_NOMATCH) {
		versatile_print(rbb, tp);
	}

	free(t_rbb);
}

void payload_human_only_print(ring_buff_bytes_t * rbb, const struct tpacket_hdr *tp)
{
	packet_t pkt;

	int tty_len = get_tty_length();

	assert(rbb);
	assert(tp);

	parse_packet(rbb, tp->tp_len, &pkt);
	info("   ");
	dump_printable(pkt.payload, pkt.payload_len, tty_len - 20, 0);
	info("\n\n");
}

void payload_hex_only_print(ring_buff_bytes_t * rbb, const struct tpacket_hdr *tp)
{
	packet_t pkt;

	int tty_len = get_tty_length();

	assert(rbb);
	assert(tp);

	parse_packet(rbb, tp->tp_len, &pkt);
	info("   ");
	if(pkt.payload_len != 0)
		dump_hex(pkt.payload, pkt.payload_len, tty_len - 20, 0);
	else
		info("(no payload)");
	info("\n\n");
}

void all_hex_only_print(ring_buff_bytes_t * rbb, const struct tpacket_hdr *tp)
{
	int tty_len = get_tty_length();

	assert(rbb);
	assert(tp);

	info("   ");
	dump_hex(rbb, tp->tp_len, tty_len - 20, 0);
	info("\n\n");
}

static inline void __versatile_header_only_print(ring_buff_bytes_t * rbb, const struct tpacket_hdr *tp, packet_t * pkt)
{
	uint16_t l4_type = 0;

	assert(rbb);
	assert(tp);
	assert(pkt);

	parse_packet(rbb, tp->tp_len, pkt);

	info("%d Byte, Timestamp (%u.%u s) \n", tp->tp_len, tp->tp_sec, tp->tp_usec);

	print_ethhdr(pkt->ethernet_header);

	switch (get_ethertype(pkt->ethernet_header)) {
	case ETH_P_8021Q:
		print_vlanhdr(pkt->vlan_header);
		break;

	case ETH_P_ARP:
		print_arphdr(pkt->arp_header);
		break;

	case ETH_P_IP:
		print_iphdr(pkt->ip_header);
		l4_type = get_l4_type_from_ipv4(pkt->ip_header);
		break;

	case ETH_P_IPV6:
		print_ipv6hdr(pkt->ipv6_header);
		l4_type = get_l4_type_from_ipv6(pkt->ipv6_header);
		break;
	}

	switch (l4_type) {
	case IPPROTO_TCP:
		print_tcphdr(pkt->tcp_header);
		break;

	case IPPROTO_UDP:
		print_udphdr(pkt->udp_header);
		break;

	case IPPROTO_ICMP:
		print_icmphdr(pkt->icmp_header);
		break;

	default:

		break;
	}

	return;
}

void versatile_header_only_print(ring_buff_bytes_t * rbb, const struct tpacket_hdr *tp)
{
	packet_t pkt;

	__versatile_header_only_print(rbb, tp, &pkt);
	info("\n");
}

void versatile_print(ring_buff_bytes_t * rbb, const struct tpacket_hdr *tp)
{
	packet_t pkt;
	int tty_len = get_tty_length();

	assert(rbb);
	assert(tp);

	__versatile_header_only_print(rbb, tp, &pkt);

	dump_payload_hex_all(pkt.payload, pkt.payload_len, tty_len - 20);
	dump_payload_char_all(pkt.payload, pkt.payload_len, tty_len - 20);

	info("\n");
}

void display_packets(system_data_t * sd)
{
	struct tpacket_hdr header;
	ring_buff_bytes_t buff[TPACKET_ALIGNMENT << 7] = {0};

	assert(sd);

	info("--- Printing ---\n\n");

	while (pcap_fetch_next_packet(sd->pcap_fd, &header, (struct ethhdr *)buff) && likely(!sigint)) {
		if (sd->print_pkt)
			if (bpf_filter(sd->bpf, (uint8_t *) buff, header.tp_len))
				sd->print_pkt((uint8_t *) buff, &header);
	}

	close(sd->pcap_fd);
}

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
 */

#include <stdio.h>

#include <netsniff-ng/macros.h>
#include <netsniff-ng/types.h>
#include <netsniff-ng/print.h>

/**
 * print_packet_buffer_mode_1 - Prints packets according to verbose mode -c
 * @rbb:                       payload
 * @len:                       len of payload
 */
void print_packet_buffer_mode_1(ring_buff_bytes_t * rbb, int len)
{
	dbg("%d Byte\n", len);

	/* Print proto stuff */
	dbg("  T: 0x%02x%02x\n", rbb[12], rbb[13]);

	/* Print VLAN-ID if 8100 */

	/* Source host stuff */
	dbg("  S: %02x:%02x:%02x:%02x:%02x:%02x\n",
	    rbb[6], rbb[7], rbb[8], rbb[9], rbb[10], rbb[11]);

	/* Destination host stuff */
	dbg("  D: %02x:%02x:%02x:%02x:%02x:%02x\n",
	    rbb[0], rbb[1], rbb[2], rbb[3], rbb[4], rbb[5]);

	/* Check for IP, then UDP / TCP */
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
	int i;

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

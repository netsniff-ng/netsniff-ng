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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include <netsniff-ng/replay.h>
#include <netsniff-ng/macros.h>

int pcap_has_packets(int pcap_fd)
{
	return 1;
}

void pcap_fetch_dummy_packet(int pcap_fd, uint8_t * pkt, size_t * len)
{
	assert(pkt);
	assert(len);
}

/* For replaying PCAP not activated for now */
#if 0
FILE *pcap_validate(FILE * pcap)
{
	struct pcap_file_header hdr;

	if (pcap == NULL) {
		errno = EINVAL;
		err("Can't open file");
		return (NULL);
	}

	if (fread((char *)&hdr, 1, sizeof(hdr), pcap) != sizeof(hdr)) {
		if (ferror(pcap)) {
			err("Error reading dump file");
		} else {
			err("Truncated dump file");
		}

		return (NULL);
	}

	if (hdr.magic != TCPDUMP_MAGIC
	    || hdr.version_major != PCAP_VERSION_MAJOR
	    || hdr.version_minor != PCAP_VERSION_MINOR || hdr.linktype != LINKTYPE_EN10MB) {
		errno = EINVAL;
		err("This file is certainly not a valid pcap");
		return (NULL);
	}

	return (pcap);
}

struct ethhdr *pcap_fetch_packet(FILE * pcap, struct ethhdr *pkt)
{
	struct pcap_sf_pkthdr sf_hdr;

	if (pcap == NULL) {
		errno = EIO;
		err("Can't access pcap file");
		return (NULL);
	}

	if (pkt == NULL) {
		errno = EINVAL;
		err("Can't access packet header");
		return (NULL);
	}

	if (fread((char *)&sf_hdr, 1, sizeof(sf_hdr), pcap) != sizeof(sf_hdr)) {
		if (ferror(pcap)) {
			err("Error reading dump file");
		} else if (feof(pcap)) {
			err("Reached end of file");
		} else {
			errno = EIO;
			err("Something went wrong while reading pcap");
		}

		return (NULL);
	}

	if (fread((char *)pkt, 1, sizeof(*pkt), pcap) != sizeof(*pkt)) {
		if (ferror(pcap)) {
			err("Error reading dump file");
		} else if (feof(pcap)) {
			err("Reached end of file");
		} else {
			errno = EIO;
			err("Something went wrong while reading pcap");
		}

		return (NULL);
	}

	return (pkt);
}
#endif

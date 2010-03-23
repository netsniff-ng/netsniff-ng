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
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include <netsniff-ng/pcap.h>
#include <netsniff-ng/dump.h>
#include <netsniff-ng/macros.h>

int pcap_write_header(int fd, int linktype, int thiszone, int snaplen)
{
	struct pcap_file_header hdr = { 0 };

	assert(fd != -1);

	hdr.magic = TCPDUMP_MAGIC;
	hdr.version_major = PCAP_VERSION_MAJOR;
	hdr.version_minor = PCAP_VERSION_MINOR;

	hdr.thiszone = thiszone;
	hdr.snaplen = snaplen;
	hdr.sigfigs = 0;
	hdr.linktype = linktype;

	if (write(fd, (char *)&hdr, sizeof(hdr)) != sizeof(hdr)) {
		err("Failed to write pcap header");
		return (-1);
	}

	return (0);
}

void pcap_dump(int fd, struct tpacket_hdr *tp_h, const struct ethhdr const *sp)
{
	struct pcap_sf_pkthdr sf_hdr;

	/* we don't memset() sf_hdr here because we are in a critical path */
	sf_hdr.ts.tv_sec = tp_h->tp_sec;
	sf_hdr.ts.tv_usec = tp_h->tp_usec;
	sf_hdr.caplen = tp_h->tp_snaplen;
	sf_hdr.len = tp_h->tp_len;

	/*
	 * XXX we should check the return status
	 * but then do what just inform the user
	 * or exit gracefully ?
	 */

	if (write(fd, &sf_hdr, sizeof(sf_hdr)) != sizeof(sf_hdr) || write(fd, sp, sf_hdr.len) != sf_hdr.len) {
		err("Cannot write pcap header");
		close(fd);
		exit(EXIT_FAILURE);
	}
}

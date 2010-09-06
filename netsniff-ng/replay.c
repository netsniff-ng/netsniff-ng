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
#include <fcntl.h>

#include <sys/types.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "pcap.h"
#include "replay.h"
#include "macros.h"

int pcap_has_packets(int fd)
{
	off_t pos;
	struct pcap_sf_pkthdr sf_hdr;

	if (fd < 0) {
		warn("Can't open file.\n");
		exit(EXIT_FAILURE);
	}

	if ((pos = lseek(fd, (off_t) 0, SEEK_CUR)) < 0) {
		err("Cannot seek offset of pcap file");
		close(fd);
		exit(EXIT_FAILURE);
	}

	/* Test pcap header */
	if (read(fd, (char *)&sf_hdr, sizeof(sf_hdr)) != sizeof(sf_hdr)) {
		return 0;	/* EOF */
	}

	/* Test payload */
	if (lseek(fd, pos + sf_hdr.len, SEEK_SET) < 0) {
		return 0;	/* EOF */
	}

	/* Rewind the offset */
	if (lseek(fd, pos, SEEK_SET) < 0) {
		err("Cannot rewind pcap file");
		close(fd);
		exit(EXIT_FAILURE);
	}

	return 1;
}

int pcap_validate_header(int fd)
{
	struct pcap_file_header hdr;

	if (fd < 0) {
		warn("Can't open file.\n");
		exit(EXIT_FAILURE);
	}

	if (read(fd, (char *)&hdr, sizeof(hdr)) != sizeof(hdr)) {
		err("Error reading dump file");
		return -EIO;
	}

	if (hdr.magic != TCPDUMP_MAGIC
	    || hdr.version_major != PCAP_VERSION_MAJOR
	    || hdr.version_minor != PCAP_VERSION_MINOR || hdr.linktype != LINKTYPE_EN10MB) {
		errno = EINVAL;
		err("This file is certainly not a valid pcap");
		return -EIO;
	}

	return 0;
}

size_t pcap_fetch_next_packet(int fd, struct tpacket_hdr * tp_h, struct ethhdr * sp)
{
	struct pcap_sf_pkthdr sf_hdr;

	assert(fd > 0);

	if (tp_h == NULL || sp == NULL) {
		errno = EINVAL;
		err("Can't access packet header");
		return (0);
	}

	if (read(fd, (char *)&sf_hdr, sizeof(sf_hdr)) != sizeof(sf_hdr)) {
		return (0);
	}
	//calc offset ?
	//tp_h->tp_sec = sf_hdr.ts.tv_sec;
	//tp_h->tp_usec = sf_hdr.ts.tv_usec;
	tp_h->tp_snaplen = sf_hdr.caplen;
	tp_h->tp_len = sf_hdr.len;

	if (read(fd, (char *)sp, sf_hdr.len) != sf_hdr.len) {
		return (0);
	}

	return (sf_hdr.len);
}

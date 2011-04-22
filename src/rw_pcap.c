/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Copyright 2010 Emmanuel Roullit.
 * Subject to the GPL.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "pcap.h"
#include "compiler.h"
#include "write_or_die.h"
#include "die.h"

ssize_t pcap_write_pkt(int fd, struct pcap_pkthdr *hdr,  uint8_t *packet)
{
	ssize_t ret;

	ret = write_or_die(fd, hdr, sizeof(*hdr));
	if (unlikely(ret != sizeof(*hdr))) {
		whine("Failed to write pkt header!\n");
		return -EIO;
	}

	ret = write_or_die(fd, packet, hdr->len);
	if (unlikely(ret != hdr->len)) {
		whine("Failed to write pkt payload!\n");
		return -EIO;
	}

	fsync_or_die(fd, "Syncing packet buffer");
	return (sizeof(*hdr) + hdr->len);
}

int pcap_read_still_has_packets(int fd)
{
	ssize_t ret;
	off_t pos;
	struct pcap_pkthdr hdr;

	pos = lseek(fd, (off_t) 0, SEEK_CUR);
	if (unlikely(pos < 0)) {
		whine("Cannot seek offset of pcap file!\n");
		return -EIO;
	}

	ret = read(fd, &hdr, sizeof(hdr));
	if (unlikely(ret != sizeof(hdr)))
		return 0;

	if (unlikely(lseek(fd, pos + hdr.len, SEEK_SET) < 0))
		return 0;
	if (unlikely(lseek(fd, pos, SEEK_SET) < 0)) {
		whine("Cannot rewind the pcap file!\n");
		return -EIO;
	}

	return 1;
}

ssize_t pcap_read_packet(int fd, struct pcap_pkthdr *hdr, uint8_t *packet,
			 size_t len)
{
	ssize_t ret;
	ret = read(fd, hdr, sizeof(*hdr));
	if (unlikely(ret != sizeof(*hdr)))
		return -EIO;
	if (unlikely(hdr->len > len))
		return -ENOMEM;
	ret = read(fd, packet, hdr->len);
	if (unlikely(ret != hdr->len))
		return -EIO;
	return hdr->len;
}


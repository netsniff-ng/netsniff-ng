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

#include "io.h"
#include "io_pcap.h"
#include "write_or_die.h"
#include "die.h"

__must_check int pcap_write_file_header(int fd, uint32_t linktype,
					int32_t thiszone, uint32_t snaplen)
{
	ssize_t ret;
	struct pcap_filehdr hdr;

	hdr.magic = TCPDUMP_MAGIC;
	hdr.version_major = PCAP_VERSION_MAJOR;
	hdr.version_minor = PCAP_VERSION_MINOR;
	hdr.thiszone = thiszone;
	hdr.sigfigs = 0;
	hdr.snaplen = snaplen;
	hdr.linktype = linktype;

	ret = write_or_die(fd, &hdr, sizeof(hdr));
	if (ret != sizeof(hdr)) {
		whine("Failed to write pcap header!\n");
		return -EIO;
	}

	return 0;
}

__must_check ssize_t pcap_write_pkt(int fd, struct pcap_pkthdr *hdr,
				    uint8_t *packet)
{
	ssize_t ret;

	ret = write_or_die(fd, hdr, sizeof(*hdr));
	if (ret != sizeof(*hdr)) {
		whine("Failed to write pkt header!\n");
		return -EIO;
	}

	ret = write_or_die(fd, packet, hdr->len);
	if (ret != hdr->len) {
		whine("Failed to write pkt payload!\n");
		return -EIO;
	}

	fsync_or_die(fd, "Syncing packet buffer");

	return sizeof(*hdr) + hdr->len;
}

__must_check int pcap_read_and_validate_file_header(int fd)
{
	ssize_t ret;
	struct pcap_filehdr hdr;

	ret = read(fd, &hdr, sizeof(hdr));
	if (ret != sizeof(hdr)) {
		whine("Failed to read pcap header!\n");
		return -EIO;
	}

	if (hdr.magic != TCPDUMP_MAGIC ||
	    hdr.version_major != PCAP_VERSION_MAJOR ||
	    hdr.version_minor != PCAP_VERSION_MINOR ||
	    hdr.linktype != LINKTYPE_EN10MB) {
		whine("This file has not a valid pcap header!\n");
		return -EIO;
	}

	return 0;
}

__must_check int pcap_read_still_has_packets(int fd)
{
	ssize_t ret;
	off_t pos;
	struct pcap_pkthdr hdr;

	pos = lseek(fd, (off_t) 0, SEEK_CUR);
	if (pos < 0) {
		whine("Cannot seek offset of pcap file!\n");
		return -EIO;
	}

	ret = read(fd, &hdr, sizeof(hdr));
	if (ret != sizeof(hdr))
		return 0;

	if (lseek(fd, pos + hdr.len, SEEK_SET) < 0)
		return 0;
	if (lseek(fd, pos, SEEK_SET) < 0) {
		whine("Cannot rewind the pcap file!\n");
		return -EIO;
	}

	return 1;
}

__must_check ssize_t pcap_read_packet(int fd, struct pcap_pkthdr *hdr,
				      uint8_t *packet, size_t len)
{
	ssize_t ret;

	ret = read(fd, hdr, sizeof(*hdr));
	if (ret != sizeof(*hdr))
		return -EIO;
	if (hdr->len > len)
		return -ENOMEM;
	ret = read(fd, packet, hdr->len);
	if (ret != hdr->len)
		return -EIO;

	return hdr->len;
}


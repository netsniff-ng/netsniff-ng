/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010, 2011 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "pcap.h"
#include "built_in.h"
#include "xutils.h"
#include "xio.h"
#include "die.h"

static int pcap_rw_pull_file_header(int fd, uint32_t *linktype)
{
	ssize_t ret;
	struct pcap_filehdr hdr;

	ret = read(fd, &hdr, sizeof(hdr));
	if (unlikely(ret != sizeof(hdr)))
		return -EIO;

	pcap_validate_header(&hdr);

	*linktype = hdr.linktype;

	return 0;
}

static int pcap_rw_push_file_header(int fd, uint32_t linktype)
{
	ssize_t ret;
	struct pcap_filehdr hdr;

	memset(&hdr, 0, sizeof(hdr));
	pcap_prepare_header(&hdr, linktype, 0, PCAP_DEFAULT_SNAPSHOT_LEN);

	ret = write_or_die(fd, &hdr, sizeof(hdr));
	if (unlikely(ret != sizeof(hdr))) {
		whine("Failed to write pkt file header!\n");
		return -EIO;
	}

	return 0;
}

static ssize_t pcap_rw_write_pcap_pkt(int fd, struct pcap_pkthdr *hdr,
				      uint8_t *packet, size_t len)
{
	ssize_t ret = write_or_die(fd, hdr, sizeof(*hdr));
	if (unlikely(ret != sizeof(*hdr))) {
		whine("Failed to write pkt header!\n");
		return -EIO;
	}

	if (unlikely(hdr->len != len))
		return -EINVAL;

	ret = write_or_die(fd, packet, hdr->len);
	if (unlikely(ret != hdr->len)) {
		whine("Failed to write pkt payload!\n");
		return -EIO;
	}

	return sizeof(*hdr) + hdr->len;
}

static ssize_t pcap_rw_read_pcap_pkt(int fd, struct pcap_pkthdr *hdr,
				     uint8_t *packet, size_t len)
{
	ssize_t ret = read(fd, hdr, sizeof(*hdr));
	if (unlikely(ret != sizeof(*hdr)))
		return -EIO;

	if (unlikely(hdr->caplen == 0 || hdr->caplen > len))
                return -EINVAL; /* Bogus packet */

	ret = read(fd, packet, hdr->caplen);
	if (unlikely(ret != hdr->caplen))
		return -EIO;

	return sizeof(*hdr) + hdr->caplen;
}

static void pcap_rw_fsync_pcap(int fd)
{
	fdatasync(fd);
}

static int pcap_rw_prepare_writing_pcap(int fd)
{
	set_ioprio_rt();
	return 0;
}

static int pcap_rw_prepare_reading_pcap(int fd)
{
	set_ioprio_rt();
	return 0;
}

struct pcap_file_ops pcap_rw_ops __read_mostly = {
	.name = "read-write",
	.pull_file_header = pcap_rw_pull_file_header,
	.push_file_header = pcap_rw_push_file_header,
	.write_pcap_pkt = pcap_rw_write_pcap_pkt,
	.read_pcap_pkt = pcap_rw_read_pcap_pkt,
	.fsync_pcap = pcap_rw_fsync_pcap,
	.prepare_writing_pcap = pcap_rw_prepare_writing_pcap,
	.prepare_reading_pcap = pcap_rw_prepare_reading_pcap,
};

int init_pcap_rw(int jumbo_support)
{
	return pcap_ops_group_register(&pcap_rw_ops, PCAP_OPS_RW);
}

void cleanup_pcap_rw(void)
{
	pcap_ops_group_unregister(PCAP_OPS_RW);
}

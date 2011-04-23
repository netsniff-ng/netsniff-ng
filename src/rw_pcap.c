/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010, 2011 Daniel Borkmann.
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

static int rw_pcap_pull_file_header(int fd)
{
	ssize_t ret;
	struct pcap_filehdr hdr;

	ret = read(fd, &hdr, sizeof(hdr));
	if (unlikely(ret != sizeof(hdr)))
		return -EIO;
	pcap_validate_header_maybe_die(&hdr);

	return 0;
}

static int rw_pcap_push_file_header(int fd)
{
	ssize_t ret;
	struct pcap_filehdr hdr;

	memset(&hdr, 0, sizeof(hdr));
	pcap_prepare_header(&hdr, LINKTYPE_EN10MB, 0,
			    PCAP_DEFAULT_SNAPSHOT_LEN);
	ret = write_or_die(fd, &hdr, sizeof(hdr));
	if (unlikely(ret != sizeof(hdr))) {
		whine("Failed to write pkt file header!\n");
		return -EIO;
	}

	return 0;
}

static ssize_t rw_pcap_write_pcap_pkt(int fd, struct pcap_pkthdr *hdr,
				      uint8_t *packet, size_t len)
{
	ssize_t ret;

	ret = write_or_die(fd, hdr, sizeof(*hdr));
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

static ssize_t rw_pcap_read_pcap_pkt(int fd, struct pcap_pkthdr *hdr,
				     uint8_t *packet, size_t len)
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

	return sizeof(*hdr) + hdr->len;
}

struct pcap_file_ops rw_pcap_ops __read_mostly = {
	.pull_file_header = rw_pcap_pull_file_header,
	.push_file_header = rw_pcap_push_file_header,
	.write_pcap_pkt = rw_pcap_write_pcap_pkt,
	.read_pcap_pkt = rw_pcap_read_pcap_pkt,
};

int init_rw_pcap(void)
{
	return pcap_ops_group_register(&rw_pcap_ops, PCAP_OPS_RW);
}

void cleanup_rw_pcap(void)
{
	pcap_ops_group_unregister(PCAP_OPS_RW);
}

/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009 - 2013 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "pcap_io.h"
#include "built_in.h"
#include "die.h"
#include "iosched.h"
#include "ioops.h"

static ssize_t pcap_rw_write(int fd, pcap_pkthdr_t *phdr, enum pcap_type type,
			     const uint8_t *packet, size_t len)
{
	ssize_t ret, hdrsize = pcap_get_hdr_length(phdr, type), hdrlen = 0;

	ret = write_or_die(fd, &phdr->raw, hdrsize);
	if (unlikely(ret != hdrsize))
		panic("Failed to write pkt header!\n");

	hdrlen = pcap_get_length(phdr, type);
	if (unlikely(hdrlen != (ssize_t) len))
		return -EINVAL;

	ret = write_or_die(fd, packet, hdrlen);
	if (unlikely(ret != hdrlen))
		panic("Failed to write pkt payload!\n");

	return hdrsize + hdrlen;
}

static ssize_t pcap_rw_read(int fd, pcap_pkthdr_t *phdr, enum pcap_type type,
			    uint8_t *packet, size_t len)
{
	ssize_t ret, hdrsize = pcap_get_hdr_length(phdr, type), hdrlen = 0;

	ret = read_or_die(fd, &phdr->raw, hdrsize);
	if (unlikely(ret != hdrsize))
		return -EIO;

	hdrlen = pcap_get_length(phdr, type);
	if (unlikely(hdrlen == 0 || hdrlen > (ssize_t) len))
                return -EINVAL;

	ret = read(fd, packet, hdrlen);
	if (unlikely(ret != hdrlen))
		return -EIO;

	return hdrsize + hdrlen;
}

static void pcap_rw_init_once(void)
{
	set_ioprio_rt();
}

static void pcap_rw_fsync(int fd)
{
	fdatasync(fd);
}

const struct pcap_file_ops pcap_rw_ops = {
	.init_once_pcap = pcap_rw_init_once,
	.pull_fhdr_pcap = pcap_generic_pull_fhdr,
	.push_fhdr_pcap = pcap_generic_push_fhdr,
	.read_pcap = pcap_rw_read,
	.write_pcap = pcap_rw_write,
	.fsync_pcap = pcap_rw_fsync,
};

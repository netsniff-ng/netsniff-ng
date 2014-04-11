/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2011 - 2013 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>

#include "pcap_io.h"
#include "xmalloc.h"
#include "built_in.h"
#include "iosched.h"
#include "ioops.h"

static struct iovec iov[1024] __cacheline_aligned;
static off_t iov_off_rd = 0, iov_slot = 0;

static ssize_t pcap_sg_write(int fd, pcap_pkthdr_t *phdr, enum pcap_type type,
			     const uint8_t *packet, size_t len)
{
	ssize_t ret, hdrsize = pcap_get_hdr_length(phdr, type);

	if (unlikely(iov_slot == array_size(iov))) {
		ret = writev(fd, iov, array_size(iov));
		if (ret < 0)
			panic("Writev I/O error: %s!\n", strerror(errno));

		iov_slot = 0;
	}

	fmemcpy(iov[iov_slot].iov_base, &phdr->raw, hdrsize);
	iov[iov_slot].iov_len = hdrsize;

	fmemcpy(iov[iov_slot].iov_base + iov[iov_slot].iov_len, packet, len);
	ret = (iov[iov_slot].iov_len += len);

	iov_slot++;
	return ret;
}

static ssize_t __pcap_sg_inter_iov_hdr_read(int fd, pcap_pkthdr_t *phdr,
					    size_t hdrsize)
{
	int ret;
	size_t offset = 0;
	ssize_t remainder;

	offset = iov[iov_slot].iov_len - iov_off_rd;
	remainder = hdrsize - offset;
	if (remainder < 0)
		remainder = 0;

	bug_on(offset + remainder != hdrsize);

	fmemcpy(&phdr->raw, iov[iov_slot].iov_base + iov_off_rd, offset);
	iov_off_rd = 0;
	iov_slot++;

	if (iov_slot == array_size(iov)) {
		iov_slot = 0;
		ret = readv(fd, iov, array_size(iov));
		if (unlikely(ret <= 0))
			return -EIO;
	}

	fmemcpy(&phdr->raw + offset, iov[iov_slot].iov_base + iov_off_rd, remainder);
	iov_off_rd += remainder;

	return hdrsize;
}

static ssize_t __pcap_sg_inter_iov_data_read(int fd, uint8_t *packet, size_t hdrlen)
{
	int ret;
	size_t offset = 0;
	ssize_t remainder;

	offset = iov[iov_slot].iov_len - iov_off_rd;
	remainder = hdrlen - offset;
	if (remainder < 0)
		remainder = 0;

	bug_on(offset + remainder != hdrlen);

	fmemcpy(packet, iov[iov_slot].iov_base + iov_off_rd, offset);
	iov_off_rd = 0;
	iov_slot++;

	if (iov_slot == array_size(iov)) {
		iov_slot = 0;
		ret = readv(fd, iov, array_size(iov));
		if (unlikely(ret <= 0))
			return -EIO;
	}

	fmemcpy(packet + offset, iov[iov_slot].iov_base + iov_off_rd, remainder);
	iov_off_rd += remainder;

	return hdrlen;
}

static ssize_t pcap_sg_read(int fd, pcap_pkthdr_t *phdr, enum pcap_type type,
			    uint8_t *packet, size_t len)
{
	ssize_t ret = 0;
	size_t hdrsize = pcap_get_hdr_length(phdr, type), hdrlen;

	if (likely(iov[iov_slot].iov_len - iov_off_rd >= hdrsize)) {
		fmemcpy(&phdr->raw, iov[iov_slot].iov_base + iov_off_rd, hdrsize);
		iov_off_rd += hdrsize;
	} else {
		ret = __pcap_sg_inter_iov_hdr_read(fd, phdr, hdrsize);
		if (unlikely(ret < 0))
			return ret;
	}

	hdrlen = pcap_get_length(phdr, type);
	if (unlikely(hdrlen == 0 || hdrlen > len))
		return -EINVAL;

	if (likely(iov[iov_slot].iov_len - iov_off_rd >= hdrlen)) {
		fmemcpy(packet, iov[iov_slot].iov_base + iov_off_rd, hdrlen);
		iov_off_rd += hdrlen;
	} else {
		ret = __pcap_sg_inter_iov_data_read(fd, packet, hdrlen);
		if (unlikely(ret < 0))
			return ret;
	}

	return hdrsize + hdrlen;
}

static void pcap_sg_fsync(int fd)
{
	ssize_t ret = writev(fd, iov, iov_slot);
	if (ret < 0)
		panic("Writev I/O error: %s!\n", strerror(errno));

	iov_slot = 0;
	fdatasync(fd);
}

static void pcap_sg_init_once(void)
{
	set_ioprio_rt();
}

static int pcap_sg_prepare_access(int fd, enum pcap_mode mode, bool jumbo)
{
	int ret;
	size_t i, len = 0;

	iov_slot = 0;
	len = jumbo ? (RUNTIME_PAGE_SIZE * 16) /* 64k max */ :
		      (RUNTIME_PAGE_SIZE *  3) /* 12k max */;

	for (i = 0; i < array_size(iov); ++i) {
		iov[i].iov_base = xzmalloc_aligned(len, 64);
		iov[i].iov_len = len;
	}

	if (mode == PCAP_MODE_RD) {
		ret = readv(fd, iov, array_size(iov));
		if (ret <= 0)
			return -EIO;

		iov_off_rd = 0;
		iov_slot = 0;
	}

	return 0;
}

static void pcap_sg_prepare_close(int fd __maybe_unused,
				  enum pcap_mode mode __maybe_unused)
{
	size_t i;

	for (i = 0; i < array_size(iov); ++i)
		xfree(iov[i].iov_base);
}

const struct pcap_file_ops pcap_sg_ops = {
	.init_once_pcap = pcap_sg_init_once,
	.pull_fhdr_pcap = pcap_generic_pull_fhdr,
	.push_fhdr_pcap = pcap_generic_push_fhdr,
	.prepare_access_pcap =  pcap_sg_prepare_access,
	.prepare_close_pcap = pcap_sg_prepare_close,
	.read_pcap = pcap_sg_read,
	.write_pcap = pcap_sg_write,
	.fsync_pcap = pcap_sg_fsync,
};

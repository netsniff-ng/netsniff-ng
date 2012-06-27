/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <unistd.h>

#include "pcap.h"
#include "xmalloc.h"
#include "xio.h"
#include "xutils.h"
#include "locking.h"
#include "built_in.h"

#define IOVSIZ		1000
#define ALLSIZ		(PAGE_SIZE * 3)
#define ALLSIZ_2K	(PAGE_SIZE * 3)  // 12K max
#define ALLSIZ_JUMBO	(PAGE_SIZE * 16) // 64K max

static struct iovec iov[IOVSIZ];
static unsigned long c = 0;
static struct spinlock lock;
static ssize_t iov_used;

static int pcap_sg_pull_file_header(int fd, uint32_t *linktype)
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

static int pcap_sg_push_file_header(int fd, uint32_t linktype)
{
	ssize_t ret;
	struct pcap_filehdr hdr;

	fmemset(&hdr, 0, sizeof(hdr));
	pcap_prepare_header(&hdr, linktype, 0, PCAP_DEFAULT_SNAPSHOT_LEN);

	ret = write_or_die(fd, &hdr, sizeof(hdr));
	if (unlikely(ret != sizeof(hdr))) {
		whine("Failed to write pkt file header!\n");
		return -EIO;
	}

	return 0;
}

static int pcap_sg_prepare_writing_pcap(int fd)
{
	set_ioprio_rt();
	return 0;
}

static ssize_t pcap_sg_write_pcap_pkt(int fd, struct pcap_pkthdr *hdr,
				      uint8_t *packet, size_t len)
{
	ssize_t ret;

	spinlock_lock(&lock);

	if (unlikely(c == IOVSIZ)) {
		ret = writev(fd, iov, IOVSIZ);
		if (ret < 0)
			panic("writev I/O error!\n");

		c = 0;
	}

	iov[c].iov_len = 0;
	fmemcpy(iov[c].iov_base, hdr, sizeof(*hdr));

	iov[c].iov_len += sizeof(*hdr);
	fmemcpy(iov[c].iov_base + iov[c].iov_len, packet, len);

	iov[c].iov_len += len;
	ret = iov[c].iov_len;

	c++;

	spinlock_unlock(&lock);

	return ret;
}

static int pcap_sg_prepare_reading_pcap(int fd)
{
	set_ioprio_rt();

	spinlock_lock(&lock);
	if (readv(fd, iov, IOVSIZ) <= 0)
		return -EIO;

	iov_used = 0;
	c = 0;
	spinlock_unlock(&lock);

	return 0;
}

static ssize_t pcap_sg_read_pcap_pkt(int fd, struct pcap_pkthdr *hdr,
				     uint8_t *packet, size_t len)
{
	ssize_t ret = 0;

	/* In contrast to writing, reading gets really ugly ... */
	spinlock_lock(&lock);

	if (likely(iov[c].iov_len - iov_used >= sizeof(*hdr))) {
		fmemcpy(hdr, iov[c].iov_base + iov_used, sizeof(*hdr));
		iov_used += sizeof(*hdr);
	} else {
		size_t offset = 0;
		ssize_t remainder;

		offset = iov[c].iov_len - iov_used;
		remainder = sizeof(*hdr) - offset;
		if (remainder < 0)
			remainder = 0;

		bug_on(offset + remainder != sizeof(*hdr));

		fmemcpy(hdr, iov[c].iov_base + iov_used, offset);

		iov_used = 0;
		c++;

		if (c == IOVSIZ) {
			/* We need to refetch! */
			c = 0;
			if (readv(fd, iov, IOVSIZ) <= 0) {
				ret = -EIO;
				goto out_err;
			}
		}

		/* Now we copy the remainder and go on with business ... */
		fmemcpy((uint8_t *) hdr + offset,
			iov[c].iov_base + iov_used, remainder);
		iov_used += remainder;
	}

	/* header read completed */

	if (unlikely(hdr->caplen == 0 || hdr->caplen > len)) {
		ret = -EINVAL; /* Bogus packet */
		goto out_err;
	}

	/* now we read data ... */

	if (likely(iov[c].iov_len - iov_used >= hdr->caplen)) {
		fmemcpy(packet, iov[c].iov_base + iov_used, hdr->caplen);
		iov_used += hdr->caplen;
	} else {
		size_t offset = 0;
		ssize_t remainder;

		offset = iov[c].iov_len - iov_used;
		remainder = hdr->caplen - offset;
		if (remainder < 0)
			remainder = 0;

		bug_on(offset + remainder != hdr->caplen);

		fmemcpy(packet, iov[c].iov_base + iov_used, offset);

		iov_used = 0;
		c++;

		if (c == IOVSIZ) {
			/* We need to refetch! */
			c = 0;
			if (readv(fd, iov, IOVSIZ) <= 0) {
				ret = -EIO;
				goto out_err;
			}
		}

		/* Now we copy the remainder and go on with business ... */
		fmemcpy(packet + offset, iov[c].iov_base + iov_used, remainder);
		iov_used += remainder;
	}

	spinlock_unlock(&lock);

	return sizeof(*hdr) + hdr->caplen;

out_err:
	spinlock_unlock(&lock);
	return ret;
}

static void pcap_sg_fsync_pcap(int fd)
{
	ssize_t ret;

	spinlock_lock(&lock);
	ret = writev(fd, iov, c);
	if (ret < 0)
		panic("writev I/O error!\n");

	c = 0;

	fdatasync(fd);
	spinlock_unlock(&lock);
}

struct pcap_file_ops pcap_sg_ops __read_mostly = {
	.name = "scatter-gather",
	.pull_file_header = pcap_sg_pull_file_header,
	.push_file_header = pcap_sg_push_file_header,
	.write_pcap_pkt = pcap_sg_write_pcap_pkt,
	.prepare_reading_pcap =  pcap_sg_prepare_reading_pcap,
	.prepare_writing_pcap =  pcap_sg_prepare_writing_pcap,
	.read_pcap_pkt = pcap_sg_read_pcap_pkt,
	.fsync_pcap = pcap_sg_fsync_pcap,
};

int init_pcap_sg(int jumbo_support)
{
	unsigned long i;
	size_t allocsz = 0;

	c = 0;

	fmemset(iov, 0, sizeof(iov));

	if (jumbo_support)
		allocsz = ALLSIZ_JUMBO; 
	else
		allocsz = ALLSIZ_2K;

	for (i = 0; i < IOVSIZ; ++i) {
		iov[i].iov_base = xzmalloc_aligned(allocsz, 64);
		iov[i].iov_len = allocsz;
	}

	spinlock_init(&lock);

	return pcap_ops_group_register(&pcap_sg_ops, PCAP_OPS_SG);
}

void cleanup_pcap_sg(void)
{
	unsigned long i;

	spinlock_destroy(&lock);

	for (i = 0; i < IOVSIZ; ++i)
		xfree(iov[i].iov_base);

	pcap_ops_group_unregister(PCAP_OPS_SG);
}

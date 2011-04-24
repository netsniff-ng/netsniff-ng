/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/uio.h>

#include "pcap.h"
#include "tlsf.h"
#include "write_or_die.h"
#include "opt_memcpy.h"
#include "locking.h"

#define IOVSIZ 100000
#define ALLSIZ   9100

static struct iovec iov[IOVSIZ];
static unsigned long c = 0;
static struct spinlock lock;

static int sg_pcap_pull_file_header(int fd)
{
	ssize_t ret;
	struct pcap_filehdr hdr;

	ret = read(fd, &hdr, sizeof(hdr));
	if (unlikely(ret != sizeof(hdr)))
		return -EIO;
	pcap_validate_header_maybe_die(&hdr);

	return 0;
}

static int sg_pcap_push_file_header(int fd)
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


static ssize_t sg_pcap_write_pcap_pkt(int fd, struct pcap_pkthdr *hdr,
				      uint8_t *packet, size_t len)
{
	ssize_t ret;
	spinlock_lock(&lock);
	if (c == IOVSIZ) {
		ret = writev(fd, iov, IOVSIZ);
		if (ret < 0)
			panic("writev I/O error!\n");
		c = 0;
	}
	iov[c].iov_len = 0;
	__memcpy_small(iov[c].iov_base, hdr, sizeof(*hdr));
	iov[c].iov_len += sizeof(*hdr);
	__memcpy(iov[c].iov_base + iov[c].iov_len, packet, len);
	iov[c].iov_len += len;
	ret = iov[c].iov_len;
	c++;
	spinlock_unlock(&lock);
	return ret;
}

static ssize_t sg_pcap_read_pcap_pkt(int fd, struct pcap_pkthdr *hdr,
				     uint8_t *packet, size_t len)
{
	spinlock_lock(&lock);
	/* blubber */
	spinlock_unlock(&lock);
	return 0;
}

static void sg_pcap_fsync_pcap(int fd)
{
	ssize_t ret;
	spinlock_lock(&lock);
	ret = writev(fd, iov, c);
	if (ret < 0)
		panic("writev I/O error!\n");
	c = 0;
	spinlock_unlock(&lock);
}

struct pcap_file_ops sg_pcap_ops __read_mostly = {
	.pull_file_header = sg_pcap_pull_file_header,
	.push_file_header = sg_pcap_push_file_header,
	.write_pcap_pkt = sg_pcap_write_pcap_pkt,
	.read_pcap_pkt = sg_pcap_read_pcap_pkt,
	.fsync_pcap = sg_pcap_fsync_pcap,
};

int init_sg_pcap(void)
{
	unsigned long i;
	c = 0;
	memset(iov, 0, sizeof(iov));
	for (i = 0; i < IOVSIZ; ++i)
		iov[i].iov_base = xtlsf_malloc(ALLSIZ);
	spinlock_init(&lock);
	return pcap_ops_group_register(&sg_pcap_ops, PCAP_OPS_SG);
}

void cleanup_sg_pcap(void)
{
	unsigned long i;
	spinlock_destroy(&lock);
	for (i = 0; i < IOVSIZ; ++i)
		xtlsf_free(iov[i].iov_base);
	pcap_ops_group_unregister(PCAP_OPS_SG);
}


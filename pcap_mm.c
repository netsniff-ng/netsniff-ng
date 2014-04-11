/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2011 - 2013 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#define _GNU_SOURCE 
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/mman.h>

#include "pcap_io.h"
#include "built_in.h"
#include "ioops.h"
#include "iosched.h"

static size_t map_size = 0;
static char *ptr_va_start, *ptr_va_curr;

static void __pcap_mmap_write_need_remap(int fd)
{
	int ret;
	off_t pos, map_size_old = map_size;
	off_t offset = ptr_va_curr - ptr_va_start;

	map_size = PAGE_ALIGN(map_size_old * 10 / 8);

	pos = lseek(fd, map_size, SEEK_SET);
	if (pos < 0)
		panic("Cannot lseek pcap file!\n");

	ret = write_or_die(fd, "", 1);
	if (ret != 1)
		panic("Cannot write file!\n");

	ptr_va_start = mremap(ptr_va_start, map_size_old, map_size, MREMAP_MAYMOVE);
	if (ptr_va_start == MAP_FAILED)
		panic("mmap of file failed!");

	ret = madvise(ptr_va_start, map_size, MADV_SEQUENTIAL);
	if (ret < 0)
		panic("Failed to give kernel mmap advise!\n");

	ptr_va_curr = ptr_va_start + offset;
}

static ssize_t pcap_mm_write(int fd, pcap_pkthdr_t *phdr, enum pcap_type type,
			     const uint8_t *packet, size_t len)
{
	size_t hdrsize = pcap_get_hdr_length(phdr, type);

	if ((off_t) (ptr_va_curr - ptr_va_start) + hdrsize + len > map_size)
		__pcap_mmap_write_need_remap(fd);

	fmemcpy(ptr_va_curr, &phdr->raw, hdrsize);
	ptr_va_curr += hdrsize;
	fmemcpy(ptr_va_curr, packet, len);
	ptr_va_curr += len;

	return hdrsize + len;
}

static ssize_t pcap_mm_read(int fd __maybe_unused, pcap_pkthdr_t *phdr,
			    enum pcap_type type, uint8_t *packet, size_t len)
{
	size_t hdrsize = pcap_get_hdr_length(phdr, type), hdrlen;

	if (unlikely((off_t) (ptr_va_curr + hdrsize - ptr_va_start) > (off_t) map_size))
		return -EIO;

	fmemcpy(&phdr->raw, ptr_va_curr, hdrsize);
	ptr_va_curr += hdrsize;
	hdrlen = pcap_get_length(phdr, type);

	if (unlikely((off_t) (ptr_va_curr + hdrlen - ptr_va_start) > (off_t) map_size))
		return -EIO;
	if (unlikely(hdrlen == 0 || hdrlen > len))
		return -EINVAL;

	fmemcpy(packet, ptr_va_curr, hdrlen);
	ptr_va_curr += hdrlen;

	return hdrsize + hdrlen;
}

static inline off_t ____get_map_size(bool jumbo)
{
	int allocsz = jumbo ? 16 : 3;

	return PAGE_ALIGN(sizeof(struct pcap_filehdr) + (RUNTIME_PAGE_SIZE * allocsz) * 1024);
}

static void __pcap_mm_prepare_access_wr(int fd, bool jumbo)
{
	int ret;
	off_t pos;
	struct stat sb;

	map_size = ____get_map_size(jumbo);

	ret = fstat(fd, &sb);
	if (ret < 0)
		panic("Cannot fstat pcap file!\n");
	if (!S_ISREG (sb.st_mode))
		panic("pcap dump file is not a regular file!\n");

	pos = lseek(fd, map_size, SEEK_SET);
	if (pos < 0)
		panic("Cannot lseek pcap file!\n");

	ret = write_or_die(fd, "", 1);
	if (ret != 1)
		panic("Cannot write file!\n");

	ptr_va_start = mmap(NULL, map_size, PROT_WRITE, MAP_SHARED, fd, 0);
	if (ptr_va_start == MAP_FAILED)
		panic("mmap of file failed!");
	ret = madvise(ptr_va_start, map_size, MADV_SEQUENTIAL);
	if (ret < 0)
		panic("Failed to give kernel mmap advise!\n");

	ptr_va_curr = ptr_va_start + sizeof(struct pcap_filehdr);
}

static void __pcap_mm_prepare_access_rd(int fd)
{
	int ret;
	struct stat sb;

	ret = fstat(fd, &sb);
	if (ret < 0)
		panic("Cannot fstat pcap file!\n");
	if (!S_ISREG (sb.st_mode))
		panic("pcap dump file is not a regular file!\n");

	map_size = sb.st_size;
	ptr_va_start = mmap(NULL, map_size, PROT_READ, MAP_SHARED | MAP_LOCKED, fd, 0);
	if (ptr_va_start == MAP_FAILED)
		panic("mmap of file failed!");
	ret = madvise(ptr_va_start, map_size, MADV_SEQUENTIAL);
	if (ret < 0)
		panic("Failed to give kernel mmap advise!\n");

	ptr_va_curr = ptr_va_start + sizeof(struct pcap_filehdr);
}

static void pcap_mm_init_once(void)
{
	set_ioprio_be();
}

static int pcap_mm_prepare_access(int fd, enum pcap_mode mode, bool jumbo)
{
	switch (mode) {
	case PCAP_MODE_RD:
		__pcap_mm_prepare_access_rd(fd);
		break;
	case PCAP_MODE_WR:
		__pcap_mm_prepare_access_wr(fd, jumbo);
		break;
	default:
		bug();
	}

	return 0;
}

static void pcap_mm_fsync(int fd __maybe_unused)
{
	msync(ptr_va_start, (off_t) (ptr_va_curr - ptr_va_start), MS_ASYNC);
}

static void pcap_mm_prepare_close(int fd, enum pcap_mode mode)
{
	int ret;

	ret = munmap(ptr_va_start, map_size);
	if (ret < 0)
		panic("Cannot unmap the pcap file!\n");

	if (mode == PCAP_MODE_WR) {
		ret = ftruncate(fd, (off_t) (ptr_va_curr - ptr_va_start));
		if (ret)
			panic("Cannot truncate the pcap file!\n");
	}
}

const struct pcap_file_ops pcap_mm_ops = {
	.init_once_pcap = pcap_mm_init_once,
	.pull_fhdr_pcap = pcap_generic_pull_fhdr,
	.push_fhdr_pcap = pcap_generic_push_fhdr,
	.prepare_access_pcap = pcap_mm_prepare_access,
	.prepare_close_pcap = pcap_mm_prepare_close,
	.read_pcap = pcap_mm_read,
	.write_pcap = pcap_mm_write,
	.fsync_pcap = pcap_mm_fsync,
};

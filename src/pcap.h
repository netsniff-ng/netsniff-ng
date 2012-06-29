/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Copyright 2010 Emmanuel Roullit.
 * Subject to the GPL, version 2.
 */

#ifndef PCAP_H
#define PCAP_H

#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <sys/time.h>
#include <linux/if_packet.h>

#include "built_in.h"
#include "die.h"

#define TCPDUMP_MAGIC              0xa1b2c3d4
#define PCAP_VERSION_MAJOR         2
#define PCAP_VERSION_MINOR         4
#define PCAP_DEFAULT_SNAPSHOT_LEN  65535

#define LINKTYPE_NULL              0   /* BSD loopback encapsulation */
#define LINKTYPE_EN10MB            1   /* Ethernet (10Mb) */
#define LINKTYPE_EN3MB             2   /* Experimental Ethernet (3Mb) */
#define LINKTYPE_AX25              3   /* Amateur Radio AX.25 */
#define LINKTYPE_PRONET            4   /* Proteon ProNET Token Ring */
#define LINKTYPE_CHAOS             5   /* Chaos */
#define LINKTYPE_IEEE802           6   /* 802.5 Token Ring */
#define LINKTYPE_ARCNET            7   /* ARCNET, with BSD-style header */
#define LINKTYPE_SLIP              8   /* Serial Line IP */
#define LINKTYPE_PPP               9   /* Point-to-point Protocol */
#define LINKTYPE_FDDI              10  /* FDDI */
#define LINKTYPE_IEEE802_11	   105	/* IEEE 802.11 wireless */

struct pcap_filehdr {
	uint32_t magic;
	uint16_t version_major;
	uint16_t version_minor;
	int32_t thiszone;
	uint32_t sigfigs;
	uint32_t snaplen;
	uint32_t linktype;
};

struct pcap_timeval {
	int32_t tv_sec;
	int32_t tv_usec;
};

struct pcap_nsf_pkthdr {
	struct timeval ts;
	uint32_t caplen;
	uint32_t len;
};

struct pcap_pkthdr {
	struct pcap_timeval ts;
	uint32_t caplen;
	uint32_t len;
};

static inline void tpacket_hdr_to_pcap_pkthdr(struct tpacket_hdr *thdr,
					      struct pcap_pkthdr *phdr)
{
	phdr->ts.tv_sec = thdr->tp_sec;
	phdr->ts.tv_usec = thdr->tp_usec;
	phdr->caplen = thdr->tp_snaplen;
/* FIXME */
/*	phdr->len = thdr->tp_len; */
	phdr->len = thdr->tp_snaplen;
}

static inline void pcap_pkthdr_to_tpacket_hdr(struct pcap_pkthdr *phdr,
					      struct tpacket_hdr *thdr)
{
	thdr->tp_sec = phdr->ts.tv_sec;
	thdr->tp_usec = phdr->ts.tv_usec;
	thdr->tp_snaplen = phdr->caplen;
	thdr->tp_len = phdr->len;
}

enum pcap_ops_groups {
	PCAP_OPS_RW = 0,
#define PCAP_OPS_RW PCAP_OPS_RW
	PCAP_OPS_SG,
#define PCAP_OPS_SG PCAP_OPS_SG
	PCAP_OPS_MMAP,
#define PCAP_OPS_MMAP PCAP_OPS_MMAP
	__PCAP_OPS_MAX,
};
#define PCAP_OPS_MAX (__PCAP_OPS_MAX - 1)
#define PCAP_OPS_SIZ (__PCAP_OPS_MAX)

enum pcap_mode {
	PCAP_MODE_READ = 0,
	PCAP_MODE_WRITE,
};

struct pcap_file_ops {
	const char *name;
	int (*pull_file_header)(int fd, uint32_t *linktype);
	int (*push_file_header)(int fd, uint32_t linktype);
	int (*prepare_writing_pcap)(int fd);
	ssize_t (*write_pcap_pkt)(int fd, struct pcap_pkthdr *hdr,
				  uint8_t *packet, size_t len);
	void (*fsync_pcap)(int fd);
	int (*prepare_reading_pcap)(int fd);
	ssize_t (*read_pcap_pkt)(int fd, struct pcap_pkthdr *hdr,
				 uint8_t *packet, size_t len);
	void (*prepare_close_pcap)(int fd, enum pcap_mode mode);
};

extern struct pcap_file_ops *pcap_ops[PCAP_OPS_SIZ];

extern int pcap_ops_group_register(struct pcap_file_ops *ops,
				   enum pcap_ops_groups group);
extern void pcap_ops_group_unregister(enum pcap_ops_groups group);

static inline struct pcap_file_ops *
pcap_ops_group_get(enum pcap_ops_groups group)
{
	return pcap_ops[group];
}

static inline void pcap_prepare_header(struct pcap_filehdr *hdr,
				       uint32_t linktype,
				       int32_t thiszone, uint32_t snaplen)
{
	hdr->magic = TCPDUMP_MAGIC;
	hdr->version_major = PCAP_VERSION_MAJOR;
	hdr->version_minor = PCAP_VERSION_MINOR;
	hdr->thiszone = thiszone;
	hdr->sigfigs = 0;
	hdr->snaplen = snaplen;
	hdr->linktype = linktype;
}

static inline void pcap_validate_header(struct pcap_filehdr *hdr)
{
	if (unlikely(hdr->magic != TCPDUMP_MAGIC ||
		     hdr->version_major != PCAP_VERSION_MAJOR ||
		     hdr->version_minor != PCAP_VERSION_MINOR ||
 		     (hdr->linktype != LINKTYPE_EN10MB &&
 		     hdr->linktype != LINKTYPE_IEEE802_11)))
		panic("This file has not a valid pcap header\n");
}

extern int init_pcap_mmap(int jumbo_support);
extern int init_pcap_rw(int jumbo_support);
extern int init_pcap_sg(int jumbo_support);

extern void cleanup_pcap_mmap(void);
extern void cleanup_pcap_rw(void);
extern void cleanup_pcap_sg(void);

static inline int init_pcap(int jumbo_support)
{
	init_pcap_rw(jumbo_support);
	init_pcap_sg(jumbo_support);
	init_pcap_mmap(jumbo_support);

	return 0;
}

static inline void cleanup_pcap(void)
{
	cleanup_pcap_rw();
	cleanup_pcap_sg();
	cleanup_pcap_mmap();
}

#endif /* PCAP_H */

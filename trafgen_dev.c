/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2011 - 2013 Daniel Borkmann <dborkma@tik.ee.ethz.ch>,
 * Swiss federal institute of technology (ETH Zurich)
 * Subject to the GPL, version 2.
 */

#define _GNU_SOURCE

#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <net/ethernet.h>

#include "sock.h"
#include "xmalloc.h"
#include "pcap_io.h"
#include "built_in.h"
#include "mac80211.h"
#include "linktype.h"
#include "trafgen_dev.h"
#include "trafgen_conf.h"
#include "trafgen_dump.h"

static int dev_pcap_open(struct dev_io *dev, const char *name, enum dev_io_mode_t mode)
{
	dev->pcap_magic = ORIGINAL_TCPDUMP_MAGIC;
	dev->pcap_ops = pcap_ops[PCAP_OPS_SG];

	if (mode == DEV_IO_IN) {
		if (!strncmp("-", name, strlen("-"))) {
			dev->fd = dup_or_die(fileno(stdin));
			close(fileno(stdin));
		} else {
			dev->fd = open(name, O_RDONLY | O_LARGEFILE | O_NOATIME);
			if (dev->fd < 0 && errno == EPERM)
				dev->fd = open_or_die(name, O_RDONLY | O_LARGEFILE);
		}

		dev->pcap_mode = PCAP_MODE_RD;
		dev->buf_len = round_up(1024 * 1024, RUNTIME_PAGE_SIZE);
		dev->buf = xmalloc_aligned(dev->buf_len, CO_CACHE_LINE_SIZE);
	} else if (mode & DEV_IO_OUT) {
		if (!strncmp("-", name, strlen("-"))) {
			dev->fd = dup_or_die(fileno(stdout));
			close(fileno(stdout));
		} else {
			dev->fd = open_or_die_m(name, O_RDWR | O_CREAT | O_TRUNC |
					        O_LARGEFILE, DEFFILEMODE);
		}

		dev->pcap_mode = PCAP_MODE_WR;
	} else {
		bug();
	}

	if (dev->fd < 0)
		panic("pcap_dev: Cannot open file %s! %s.\n", name, strerror(errno));

	if (dev->pcap_ops->init_once_pcap)
		dev->pcap_ops->init_once_pcap(false);

	if (mode == DEV_IO_IN) {
		if (dev->pcap_ops->pull_fhdr_pcap(dev->fd, &dev->pcap_magic, &dev->link_type))
			panic("Error reading pcap header!\n");
	}

	if (dev->pcap_ops->prepare_access_pcap) {
		if (dev->pcap_ops->prepare_access_pcap(dev->fd, dev->pcap_mode, false))
			panic("Error prepare reading pcap!\n");
	}

	return 0;
}

static struct packet *dev_pcap_read(struct dev_io *dev)
{
	size_t len = dev->buf_len;
	uint8_t *buf = dev->buf;
	pcap_pkthdr_t phdr;
	struct packet *pkt;
	size_t pkt_len;

	if (dev->pcap_ops->read_pcap(dev->fd, &phdr, dev->pcap_magic, buf, len) <= 0)
		return NULL;

	pkt_len = pcap_get_length(&phdr, dev->pcap_magic);
	if (!pkt_len)
		return NULL;

	pkt = realloc_packet();

	pkt->len = pkt_len;
	pkt->is_created = true;
	pkt->payload = xzmalloc(pkt_len);
	memcpy(pkt->payload, buf, pkt_len);
	pcap_get_tstamp(&phdr, dev->pcap_magic, &pkt->tstamp);

	return pkt;
}

static int dev_pcap_write(struct dev_io *dev, struct packet *pkt)
{
	uint8_t *buf = pkt->payload;
	size_t len = pkt->len;
	struct timeval time;
	pcap_pkthdr_t phdr;
	int ret;

	/* Write PCAP file header only once */
	if (!dev->is_initialized) {
		if (dev->pcap_ops->push_fhdr_pcap(dev->fd, dev->pcap_magic, dev->link_type)) {
			fprintf(stderr, "Error writing pcap header!\n");
			return -1;
		}

		if (dev->pcap_ops->prepare_access_pcap) {
			if (dev->pcap_ops->prepare_access_pcap(dev->fd, PCAP_MODE_WR, true)) {
				fprintf(stderr, "Error prepare writing pcap!\n");
				return -1;
			}
		}

		dev->is_initialized = true;
	}

	bug_on(gettimeofday(&time, NULL));

	phdr.ppo.ts.tv_sec = time.tv_sec;
	phdr.ppo.ts.tv_usec = time.tv_usec;
	phdr.ppo.caplen = len;
	phdr.ppo.len = len;

	ret = dev->pcap_ops->write_pcap(dev->fd, &phdr, dev->pcap_magic,
					buf, pcap_get_length(&phdr, dev->pcap_magic));

	if (unlikely(ret != (int) pcap_get_total_length(&phdr, dev->pcap_magic))) {
		fprintf(stderr, "Write error to pcap!\n");
		return -1;
	}

	return ret;
}

static void dev_pcap_close(struct dev_io *dev)
{
	if (dev->pcap_mode == PCAP_MODE_WR) {
		dev->pcap_ops->fsync_pcap(dev->fd);
	} else if (dev->pcap_mode == PCAP_MODE_RD) {
		free(dev->buf);
		dev->buf_len = 0;
		dev->buf = NULL;
	}

	if (dev->pcap_ops->prepare_close_pcap)
		dev->pcap_ops->prepare_close_pcap(dev->fd, dev->pcap_mode);

	close(dev->fd);
}

static const struct dev_io_ops dev_pcap_ops = {
	.open = dev_pcap_open,
	.read = dev_pcap_read,
	.write = dev_pcap_write,
	.close = dev_pcap_close,
};

static int dev_net_open(struct dev_io *dev, const char *name, enum dev_io_mode_t mode)
{
	dev->ifindex = __device_ifindex(name);
	dev->dev_type = device_type(name);
	dev->fd = pf_socket();

	return 0;
}

static int dev_net_write(struct dev_io *dev, struct packet *pkt)
{
	struct sockaddr_ll saddr = {
		.sll_family = PF_PACKET,
		.sll_halen = ETH_ALEN,
		.sll_ifindex = dev->ifindex,
	};
	uint8_t *buf = pkt->payload;
	size_t len = pkt->len;

	return sendto(dev->fd, buf, len, 0, (struct sockaddr *) &saddr, sizeof(saddr));
}

static int dev_net_set_link_type(struct dev_io *dev, int link_type)
{
	if (link_type != LINKTYPE_IEEE802_11 && link_type != LINKTYPE_IEEE802_11_RADIOTAP)
		return 0;

	dev->trans = xstrdup(dev->name);
	xfree(dev->name);

	enter_rfmon_mac80211(dev->trans, &dev->name);
	dev->ifindex = __device_ifindex(dev->name);
	dev->dev_type = device_type(dev->name);

	return 0;
}

static void dev_net_close(struct dev_io *dev)
{
	if (dev->link_type == LINKTYPE_IEEE802_11 || dev->link_type == LINKTYPE_IEEE802_11_RADIOTAP)
		leave_rfmon_mac80211(dev->name);

	free(dev->trans);
}

static const struct dev_io_ops dev_net_ops = {
	.open = dev_net_open,
	.write = dev_net_write,
	.set_link_type = dev_net_set_link_type,
	.close = dev_net_close,
};

static int dev_cfg_open(struct dev_io *dev, const char *name, enum dev_io_mode_t mode)
{
	dev->fd = open_or_die_m(name, O_RDWR | O_CREAT | O_TRUNC | O_LARGEFILE, DEFFILEMODE);
	return 0;
}

static int dev_cfg_write(struct dev_io *dev, struct packet *pkt)
{
	if (packet_dump_fd(pkt, dev->fd))
		return -1;

	return pkt->len;
}

static void dev_cfg_close(struct dev_io *dev)
{
	close(dev->fd);
}

static const struct dev_io_ops dev_cfg_ops = {
	.open = dev_cfg_open,
	.write = dev_cfg_write,
	.close = dev_cfg_close,
};

struct dev_io *dev_io_create(const char *name, enum dev_io_mode_t mode)
{
	struct dev_io *dev = xzmalloc(sizeof(struct dev_io));

	dev->mode = mode;
	if (strstr(name, ".pcap")) {
		dev->name = xstrdup(name);
		dev->ops = &dev_pcap_ops;
	} else if (strstr(name, ".cfg")) {
		dev->name = xstrdup(name);
		dev->ops = &dev_cfg_ops;
	} else if (device_mtu(name) > 0) {
		dev->name = xstrndup(name, IFNAMSIZ);
		dev->ops = &dev_net_ops;
	} else {
		free(dev);
		fprintf(stderr, "No networking device or pcap file: %s\n", name);
		return NULL;
	}

	return dev;
};

extern void dev_io_open(struct dev_io *dev)
{
	bug_on(!dev);
	bug_on(!dev->ops);

	if (dev->ops->open)
		if (dev->ops->open(dev, dev->name, dev->mode))
			panic("Cannot open io %s mode %d\n", dev->name,
			      dev->mode);
}

int dev_io_write(struct dev_io *dev, struct packet *pkt)
{
	bug_on(!dev);
	bug_on(!dev->ops);

	if (dev->ops->write)
		return dev->ops->write(dev, pkt);

	return 0;
}

struct packet *dev_io_read(struct dev_io *dev)
{
	bug_on(!dev);
	bug_on(!dev->ops);

	if (dev->ops->read)
		return dev->ops->read(dev);

	return NULL;
}

const char *dev_io_name_get(struct dev_io *dev)
{
	return dev->name;
}

bool dev_io_is_netdev(struct dev_io *dev)
{
	return dev->ops == &dev_net_ops;
}

bool dev_io_is_pcap(struct dev_io *dev)
{
	return dev->ops == &dev_pcap_ops;
}

int dev_io_link_type_set(struct dev_io *dev, int link_type)
{
	if (dev->ops->set_link_type) {
		if (dev->ops->set_link_type(dev, link_type))
			return -1;
	}

	dev->link_type = link_type;
	return 0;
}

int dev_io_ifindex_get(struct dev_io *dev)
{
	return dev->ifindex;
}

int dev_io_fd_get(struct dev_io *dev)
{
	return dev->fd;
}

void dev_io_close(struct dev_io *dev)
{
	if (dev) {
		if (dev->ops->close)
			dev->ops->close(dev);

		free(dev->name);
		free(dev);
	}
}

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
#include "trafgen_dev.h"

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

static int dev_pcap_read(struct dev_io *dev, uint8_t *buf, size_t len,
			 struct timespec *tstamp)
{
	pcap_pkthdr_t phdr;
	size_t pkt_len;

	if (dev->pcap_ops->read_pcap(dev->fd, &phdr, dev->pcap_magic, buf, len) <= 0)
		return -1;

	pkt_len = pcap_get_length(&phdr, dev->pcap_magic);
	if (!pkt_len)
		return -1;

	pcap_get_tstamp(&phdr, dev->pcap_magic, tstamp);

	return pkt_len;
}

static int dev_pcap_write(struct dev_io *dev, const uint8_t *buf, size_t len)
{
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
	if (dev->pcap_mode == PCAP_MODE_WR)
		dev->pcap_ops->fsync_pcap(dev->fd);

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

static int dev_net_write(struct dev_io *dev, const uint8_t *buf, size_t len)
{
	struct sockaddr_ll saddr = {
		.sll_family = PF_PACKET,
		.sll_halen = ETH_ALEN,
		.sll_ifindex = dev->ifindex,
	};

	return sendto(dev->fd, buf, len, 0, (struct sockaddr *) &saddr, sizeof(saddr));
}

static const struct dev_io_ops dev_net_ops = {
	.open = dev_net_open,
	.write = dev_net_write,
};

struct dev_io *dev_io_open(const char *name, enum dev_io_mode_t mode)
{
	struct dev_io *dev = xzmalloc(sizeof(struct dev_io));

	if (strstr(name, ".pcap")) {
		dev->ops = &dev_pcap_ops;
	} else if (device_mtu(name) > 0) {
		dev->ops = &dev_net_ops;
	} else {
		fprintf(stderr, "No networking device or pcap file: %s\n", name);
		return NULL;
	}

	if (dev->ops->open) {
		if (dev->ops->open(dev, name, mode)) {
			xfree(dev);
			return NULL;
		}
	}

	dev->name = xstrdup(name);
	return dev;
};

int dev_io_write(struct dev_io *dev, const uint8_t *buf, size_t len)
{
	bug_on(!dev);
	bug_on(!dev->ops);

	if (dev->ops->write)
		return dev->ops->write(dev, buf, len);

	return 0;
}

int dev_io_read(struct dev_io *dev, uint8_t *buf, size_t len,
		struct timespec *tstamp)
{
	bug_on(!dev);
	bug_on(!dev->ops);

	if (dev->ops->read)
		return dev->ops->read(dev, buf, len, tstamp);

	return 0;
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

void dev_io_link_type_set(struct dev_io *dev, int link_type)
{
	dev->link_type = link_type;
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

#ifndef TRAFGEN_DEV_H
#define TRAFGEN_DEV_H

#include <stdbool.h>
#include <inttypes.h>

#include "pcap_io.h"

enum dev_io_mode_t {
	DEV_IO_IN	= 1 << 0,
	DEV_IO_OUT	= 1 << 1,
};

struct dev_io_ops;

struct dev_io {
	int fd;
	char *name;
	char *trans;
	int ifindex;
	int dev_type;
	uint32_t link_type;
	uint32_t pcap_magic;
	bool is_initialized;
	enum pcap_mode pcap_mode;

	const struct pcap_file_ops *pcap_ops;
	const struct dev_io_ops *ops;
};

struct dev_io_ops {
	int(*open) (struct dev_io *dev, const char *name, enum dev_io_mode_t mode);
	int(*write) (struct dev_io *dev, const uint8_t *buf, size_t len);
	int(*read) (struct dev_io *dev, uint8_t *buf, size_t len, struct timespec *tstamp);
	int(*set_link_type) (struct dev_io *dev, int link_type);
	void(*close) (struct dev_io *dev);
};

extern struct dev_io *dev_io_open(const char *name, enum dev_io_mode_t mode);
extern int dev_io_write(struct dev_io *dev, const uint8_t *buf, size_t len);
extern int dev_io_read(struct dev_io *dev, uint8_t *buf, size_t len,
		       struct timespec *tstamp);
extern int dev_io_ifindex_get(struct dev_io *dev);
extern int dev_io_fd_get(struct dev_io *dev);
extern const char *dev_io_name_get(struct dev_io *dev);
extern int dev_io_link_type_set(struct dev_io *dev, int link_type);
extern bool dev_io_is_netdev(struct dev_io *dev);
extern bool dev_io_is_pcap(struct dev_io *dev);
extern void dev_io_close(struct dev_io *dev);

#endif /* TRAFGEN_DEV_H */

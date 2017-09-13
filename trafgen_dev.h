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
struct packet;

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
	enum dev_io_mode_t mode;
	size_t buf_len;
	uint8_t *buf;

	const struct pcap_file_ops *pcap_ops;
	const struct dev_io_ops *ops;
};

struct dev_io_ops {
	int(*open) (struct dev_io *dev, const char *name, enum dev_io_mode_t mode);
	int(*write) (struct dev_io *dev, struct packet *pkt);
	struct packet *(*read) (struct dev_io *dev);
	int(*set_link_type) (struct dev_io *dev, int link_type);
	void(*close) (struct dev_io *dev);
};

extern struct dev_io *dev_io_create(const char *name, enum dev_io_mode_t mode);
extern void dev_io_open(struct dev_io *dev);
extern int dev_io_write(struct dev_io *dev, struct packet *pkt);
extern struct packet *dev_io_read(struct dev_io *dev);
extern int dev_io_ifindex_get(struct dev_io *dev);
extern int dev_io_fd_get(struct dev_io *dev);
extern const char *dev_io_name_get(struct dev_io *dev);
extern int dev_io_link_type_set(struct dev_io *dev, int link_type);
extern bool dev_io_is_netdev(struct dev_io *dev);
extern bool dev_io_is_pcap(struct dev_io *dev);
extern void dev_io_close(struct dev_io *dev);

#endif /* TRAFGEN_DEV_H */

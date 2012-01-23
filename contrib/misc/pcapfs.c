/*
 * A read/write filesystem for (large) Pcap files
 * By Daniel Borkmann, <daniel.borkmann@tik.ee.ethz.ch>
 * GPL, version 2.0
 *
 * gcc -Wall `pkg-config fuse --cflags --libs` pcapfs.c -o pcapfs
 *
 * Usage:
 *  pcapfs <mntpoint> <trace.pcap>
 *  hexdump -C <mntpoint>/0.hex
 *  ls -la <mntpoint>/0.hex
 *  vim <mntpoint>/0.hex
 *    hit escape and type:
 *     :%!xxd to switch into hex mode
 *    when done hit escape and type:
 *     :%!xxd -r to exit from hex mode
 *  fusermount -u <mntpoint>
 */

#define _FILE_OFFSET_BITS 64
#define FUSE_USE_VERSION 26
#include <fuse.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/sendfile.h>

#define TCPDUMP_MAGIC		0xa1b2c3d4
#define PCAP_VERSION_MAJOR	2
#define PCAP_VERSION_MINOR	4

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

struct pcap_pkthdr {
	struct pcap_timeval ts;
	uint32_t caplen;
	uint32_t len;
};

enum {
	PCAP_NONE,
	PCAP_ROOT,
	PCAP_FILE,
};

struct pcap_fnode {
	struct pcap_pkthdr meta;
	off_t data;
	int dirty;
	uint8_t *cowbuff;
	size_t cowlen;
};

static int pcap_fd;

static char *pcap_disc = NULL;

static struct pcap_fnode *table = NULL;

static size_t table_len = 0, table_next = 0;

static sig_atomic_t flushing = 0, rwing = 0;

static void pcapfs_flush_dirty_nodes_to_disc(void);

static void *xmalloc(size_t len)
{
	void *ptr = malloc(len);
	if (!ptr) {
		syslog(LOG_ERR, "no mem left! panic!\n");
		exit(1);
	}
	return ptr;
}

static void *xrealloc(void *ptr, size_t nlen)
{
	void *nptr = realloc(ptr, nlen);
	if (!nptr) {
		syslog(LOG_ERR, "no mem left! panic!\n");
		exit(1);
	}
	return nptr;
}

static int pcapfs_file_type(const char *path, size_t *node)
{
	int ret;
	if (strcmp(path, "/") == 0)
		return PCAP_ROOT;
	ret = sscanf(path, "/%zu.hex", node);
	if (ret <= 0)
		return PCAP_NONE;
	if (*node >= table_next)
		return PCAP_NONE;
	return PCAP_FILE;
}

static int pcapfs_getattr(const char *path, struct stat *stbuf)
{
	size_t node;
	stbuf->st_uid = getuid();
	stbuf->st_gid = getgid();
	switch (pcapfs_file_type(path, &node)) {
	case PCAP_ROOT:
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		stbuf->st_atime = stbuf->st_mtime = time(NULL);
		break;
	case PCAP_FILE:
		stbuf->st_mode = S_IFREG | 0644;
		stbuf->st_nlink = 1;
		if (table[node].dirty)
			stbuf->st_size = table[node].cowlen;
		else
			stbuf->st_size = table[node].meta.caplen;
		stbuf->st_atime = stbuf->st_mtime = table[node].meta.ts.tv_sec;
		break;
	case PCAP_NONE:
	default:
		return -ENOENT;
	}
	return 0;
}

static int pcapfs_open(const char *path, struct fuse_file_info *fi)
{
	size_t node;
	(void) fi;
	if (pcapfs_file_type(path, &node) != PCAP_NONE)
		return 0;
	return -ENOENT;
}

static int pcapfs_read(const char *path, char *buff, size_t size,
		       off_t offset, struct fuse_file_info *fi)
{
	size_t node;
	ssize_t ret = 0;
	(void) fi;
	if (pcapfs_file_type(path, &node) != PCAP_FILE)
		return -EINVAL;
	while (flushing)
		sleep(0);
	rwing = 1;
	if (!table[node].dirty) {
		if (offset >= table[node].meta.caplen)
			goto out;
		if (size > table[node].meta.caplen - offset)
			size = table[node].meta.caplen - offset;
		lseek(pcap_fd, table[node].data + offset, SEEK_SET);
		ret = read(pcap_fd, buff, size);
	} else {
		if (offset >= table[node].cowlen)
			goto out;
		if (size > table[node].cowlen - offset)
			size = table[node].cowlen - offset;
		memcpy(buff, table[node].cowbuff + offset, size);
		ret = size;
	}
out:
	rwing = 0;
	return ret;
}

static int pcapfs_truncate(const char *path, off_t size)
{
	size_t node;
	if (pcapfs_file_type(path, &node) != PCAP_FILE)
		return -EINVAL;
	return size;
}

static int pcapfs_write(const char *path, const char *buff, size_t size,
			off_t offset, struct fuse_file_info *fi)
{
	size_t node;
	ssize_t ret;
	(void) fi;
	if (pcapfs_file_type(path, &node) != PCAP_FILE)
		return -EINVAL;
	while (flushing)
		sleep(0);
	rwing = 1;
	if (!table[node].dirty) {
		table[node].dirty = 1;
		table[node].cowlen = table[node].meta.caplen;
		table[node].cowbuff = xmalloc(table[node].cowlen);
		lseek(pcap_fd, table[node].data, SEEK_SET);
		ret = read(pcap_fd, table[node].cowbuff, table[node].cowlen);
		if (ret != table[node].cowlen) {
			syslog(LOG_ERR, "error writing into cow buff of"
			       " %s!\n", path);
			table[node].dirty = 0;
			table[node].cowlen = 0;
			free(table[node].cowbuff);
			table[node].cowbuff = NULL;
			rwing = 0;
			return -EIO;
		}
	}
	if (table[node].cowlen < size + offset) {
		table[node].cowlen = size + offset;
		table[node].cowbuff = xrealloc(table[node].cowbuff,
					       table[node].cowlen);
		memset(table[node].cowbuff + table[node].meta.caplen,
		       0, table[node].cowlen - table[node].meta.caplen);
	}
	if (table[node].cowlen > size + offset) {
		table[node].cowlen = size + offset;
		table[node].cowbuff = xrealloc(table[node].cowbuff,
					       table[node].cowlen);
	}
	memcpy(table[node].cowbuff + offset, buff, size);
	rwing = 0;
	return size;
}

static int pcapfs_readdir(const char *path, void *buff,
			  fuse_fill_dir_t filler,
			  off_t offset, struct fuse_file_info *fi)
{
	size_t i;
	size_t node;
	char tmp[256];
	(void) fi;
	(void) offset;
	if (pcapfs_file_type(path, &node) != PCAP_ROOT)
		return -ENOENT;
	filler(buff, ".", NULL, 0);
	filler(buff, "..", NULL, 0);
	for (i = 0; i < table_next; ++i) {
		memset(tmp, 0, sizeof(tmp));
		snprintf(tmp, sizeof(tmp), "%zu.hex", i);
		tmp[sizeof(tmp) - 1] = 0;
		filler(buff, tmp, NULL, 0);
	}
	return 0;
}

static struct fuse_operations pcapfs_ops = {
	.open		= pcapfs_open,
	.read		= pcapfs_read,
	.write		= pcapfs_write,
	.getattr	= pcapfs_getattr,
	.readdir	= pcapfs_readdir,
	.truncate	= pcapfs_truncate,
};

static void pcapfs_build_cache(void)
{
	ssize_t ret;
#define INIT_SLOTS	1024
	table = xmalloc(sizeof(*table) * INIT_SLOTS);
	table_len = INIT_SLOTS;
	table_next = 0;
	posix_fadvise(pcap_fd, 0, 0, POSIX_FADV_SEQUENTIAL);
	while (1) {
		ret = read(pcap_fd, &table[table_next].meta,
			   sizeof(table[table_next].meta));
		if (ret == 0)
			break;
		if (ret != sizeof(table[table_next].meta))
			goto die;
		if (table[table_next].meta.caplen == 0 ||
		    table[table_next].meta.len == 0)
			goto die;
		table[table_next].data = lseek(pcap_fd, 0, SEEK_CUR);
		table[table_next].dirty = 0;
		table[table_next].cowbuff = NULL;
		table[table_next].cowlen = 0;
		ret = lseek(pcap_fd, table[table_next].meta.caplen, SEEK_CUR);
		if (ret < 0)
			goto die;
		table_next++;
		if (table_next == table_len) {
			table_len = (size_t) table_len * 3 / 2;
			table = xrealloc(table, table_len);
		}
	}
	lseek(pcap_fd, 0, SEEK_SET);
	posix_fadvise(pcap_fd, 0, 0, POSIX_FADV_RANDOM);
	return;
die:
	syslog(LOG_ERR, "error parsing the pcap file! corrupted?!\n");
	exit(1);
}

static inline void pcapfs_destroy_cache(void)
{
	free(table);
	table = NULL;
	table_len = 0;
	table_next = 0;
}

static void ____pcapfs_flush_dirty_nodes_to_disc_dirty(size_t i)
{
	ssize_t ret;
	if ((table[i].meta.caplen == table[i].meta.len) ||
	    (table[i].meta.caplen < table[i].meta.len &&
	     table[i].cowlen > table[i].meta.len))
		table[i].meta.len = table[i].cowlen;
	table[i].meta.caplen = table[i].cowlen;
	ret = write(pcap_fd, &table[i].meta, sizeof(table[i].meta));
	if (ret != sizeof(table[i].meta))
		syslog(LOG_ERR, "disc flush meta error at node %zu,"
		       "continuing\n", i + 1);
	ret = write(pcap_fd, table[i].cowbuff, table[i].cowlen);
	if (ret != table[i].cowlen)
		syslog(LOG_ERR, "disc flush error at dirty node %zu,"
		       "continuing\n", i);
	table[i].cowlen = 0;
	free(table[i].cowbuff);
	table[i].cowbuff = NULL;
	table[i].dirty = 0;
	table[i].data = lseek(pcap_fd, 0, SEEK_CUR) - table[i].meta.caplen;
}

static void
____pcapfs_flush_dirty_nodes_to_disc_clean(size_t i, int pcap_fd2,
					   off_t offshift)
{
	ssize_t ret;
	uint8_t *tmp;
	lseek(pcap_fd2, table[i].data - offshift, SEEK_SET);
	ret = write(pcap_fd, &table[i].meta, sizeof(table[i].meta));
	if (ret != sizeof(table[i].meta))
		syslog(LOG_ERR, "disc flush meta error at node %zu,"
		       "continuing\n", i + 1);
	/* we cannot do a sendfile backwards :-( but chunks here are smaller */
	tmp = xmalloc(table[i].meta.caplen);
	ret = read(pcap_fd2, tmp, table[i].meta.caplen);
	if (ret != table[i].meta.caplen)
		syslog(LOG_ERR, "disc flush error (%s) at clean node %zu read,"
		       "continuing\n", strerror(errno), i);
	ret = write(pcap_fd, tmp, table[i].meta.caplen);
	if (ret != table[i].meta.caplen)
		syslog(LOG_ERR, "disc flush error (%s) at clean node %zu write,"
		       "continuing\n", strerror(errno), i);
	table[i].data = lseek(pcap_fd, 0, SEEK_CUR) - table[i].meta.caplen;
	free(tmp);
}

static void __pcapfs_flush_dirty_nodes_to_disc(size_t i_dirty, int pcap_fd2,
					       size_t *count, off_t offshift)
{
	size_t i;
	for (i = i_dirty; i < table_next; ++i) {
		if (table[i].dirty) {
			____pcapfs_flush_dirty_nodes_to_disc_dirty(i);
			(*count)++;
		} else {
			____pcapfs_flush_dirty_nodes_to_disc_clean(i, pcap_fd2,
								   offshift);
		}
	}
}

static void pcapfs_flush_dirty_nodes_to_disc(void)
{
	size_t i, count = 0;
	ssize_t ret;
	while (rwing)
		sleep(0);
	flushing = 1;
	posix_fadvise(pcap_fd, 0, 0, POSIX_FADV_SEQUENTIAL);
	for (i = 0; i < table_next; ++i) {
		if (!table[i].dirty)
			continue;
		if (table[i].dirty &&
		    table[i].cowlen == table[i].meta.caplen) {
			lseek(pcap_fd, table[i].data, SEEK_SET);
			ret = write(pcap_fd, table[i].cowbuff,
				    table[i].cowlen);
			if (ret != table[i].cowlen)
				syslog(LOG_ERR, "disc flush error at node "
				       "%zu, continuing\n", i);
			table[i].dirty = 0;
			table[i].cowlen = 0;
			free(table[i].cowbuff);
			table[i].cowbuff = NULL;
			count++;
		} else if (table[i].dirty) {
			int pcap_fd2;
			size_t ii;
			char *tmpfile = "/tmp/pcapfs.fubar";
			off_t offshift = table[i].data;
			size_t to_copy, chunk_size, chunk_blocks, chunk_rest;
			struct stat ost;
			fstat(pcap_fd, &ost);
			pcap_fd2 = open(tmpfile, O_RDWR | O_CREAT | O_TRUNC,
					S_IRUSR | S_IWUSR);
			if (pcap_fd2 < 0) {
				syslog(LOG_ERR, "error creating temp file!\n");
				break;
			}
			posix_fadvise(pcap_fd2, 0, 0, POSIX_FADV_SEQUENTIAL);
			to_copy = ost.st_size - table[i].data;
			chunk_size = ost.st_blksize;
			chunk_blocks = (size_t) (to_copy / chunk_size);
			chunk_rest = to_copy % chunk_size;
			lseek(pcap_fd, table[i].data, SEEK_SET);
			for (ii = 0; ii < chunk_blocks; ++ii) {
				ret = sendfile(pcap_fd2, pcap_fd, NULL,
					       chunk_size);
				if (ret != chunk_size)
					syslog(LOG_ERR, "error (%s) while "
					       "splicing!\n", strerror(errno));
			}
			ret = sendfile(pcap_fd2, pcap_fd, NULL, chunk_rest);
			if (ret != chunk_rest)
				syslog(LOG_ERR, "error while tee'ing!\n");
			lseek(pcap_fd2, 0, SEEK_SET);
			lseek(pcap_fd, table[i].data -
			      sizeof(struct pcap_pkthdr), SEEK_SET);
			ftruncate(pcap_fd, table[i].data -
				  sizeof(struct pcap_pkthdr));
			__pcapfs_flush_dirty_nodes_to_disc(i, pcap_fd2, &count,
							   offshift);
			close(pcap_fd2);
			unlink(tmpfile);
			break;
		}
	}
	fsync(pcap_fd);
	posix_fadvise(pcap_fd, 0, 0, POSIX_FADV_RANDOM);
	flushing = 0;
	syslog(LOG_INFO, "%zu dirty marked node(s) flushed\n", count);
}

static void pcapfs_check_superblock(void)
{
	ssize_t ret;
	struct pcap_filehdr hdr;
	ret = read(pcap_fd, &hdr, sizeof(hdr));
	if (ret != sizeof(hdr))
		goto die;
	if (hdr.magic != TCPDUMP_MAGIC)
		goto die;
	if (hdr.version_major != PCAP_VERSION_MAJOR)
		goto die;
	if (hdr.version_minor != PCAP_VERSION_MINOR)
		goto die;
	return;
die:
	fprintf(stderr, "this isn't a pcap file!\n");
	exit(1);
}

static inline void pcapfs_lock_disc(void)
{
	int ret = flock(pcap_fd, LOCK_EX);
	if (ret < 0) {
		syslog(LOG_ERR, "cannot lock pcap disc!\n");
		exit(1);
	}
}

static inline void pcapfs_unlock_disc(void)
{
	flock(pcap_fd, LOCK_UN);
}

static inline void pcapfs_init_disc(void)
{
	pcap_fd = open(pcap_disc, O_RDWR | O_APPEND);
	if (pcap_fd < 0) {
		syslog(LOG_ERR, "cannot open pcap disc!\n");
		exit(1);
	}
}

static inline void pcapfs_halt_disc(void)
{
	close(pcap_fd);
}

static void pcapfs_cleanup(void)
{
	pcapfs_flush_dirty_nodes_to_disc();
	pcapfs_destroy_cache();
	pcapfs_unlock_disc();
	pcapfs_halt_disc();
	syslog(LOG_INFO, "unmounted\n");
	closelog();
}

static void pcapfs_init(void)
{
	openlog("pcapfs", LOG_PID | LOG_CONS | LOG_NDELAY, LOG_DAEMON);
	pcapfs_init_disc();
	pcapfs_lock_disc();
	pcapfs_check_superblock();
	pcapfs_build_cache();
	syslog(LOG_INFO, "mounted\n");
}

int main(int argc, char **argv)
{
	int i, ret;
	struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
	if (argc < 3) {
		fprintf(stderr, "usage: pcapfs <mntpoint> <pcap>\n");
		exit(1);
	}
	for (i = 0; i < argc - 1; i++)
		fuse_opt_add_arg(&args, argv[i]);
	pcap_disc = argv[argc - 1];
	pcapfs_init();
	ret = fuse_main(args.argc, args.argv, &pcapfs_ops, NULL);
	pcapfs_cleanup();
	return ret;
}

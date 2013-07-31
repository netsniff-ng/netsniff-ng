#ifndef IOOPS_H
#define IOOPS_H

#include <sys/types.h>

extern int open_or_die(const char *file, int flags);
extern int open_or_die_m(const char *file, int flags, mode_t mode);
extern int dup_or_die(int oldfd);
extern void dup2_or_die(int oldfd, int newfd);
extern void create_or_die(const char *file, mode_t mode);
extern int tun_open_or_die(const char *name, int type);
extern void pipe_or_die(int pipefd[2], int flags);
extern ssize_t read_or_die(int fd, void *buf, size_t count);
extern ssize_t write_or_die(int fd, const void *buf, size_t count);
extern int read_blob_or_die(const char *file, void *blob, size_t count);
extern int write_blob_or_die(const char *file, const void *blob, size_t count);

#endif /* IOOPS_H */

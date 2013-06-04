#ifndef IOEXACT_H
#define IOEXACT_H

extern ssize_t read_exact(int fd, void *buf, size_t len, int mayexit);
extern ssize_t write_exact(int fd, void *buf, size_t len, int mayexit);

#endif /* IOEXACT_H */

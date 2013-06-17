#ifndef IOEXACT_H
#define IOEXACT_H

#include <stdbool.h>

extern ssize_t read_exact(int fd, void *buf, size_t len, bool mayexit);
extern ssize_t write_exact(int fd, void *buf, size_t len, bool mayexit);

#endif /* IOEXACT_H */

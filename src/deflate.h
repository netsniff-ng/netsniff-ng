/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef DEFLATE_H
#define DEFLATE_H

extern int z_alloc_or_maybe_die(int z_level);
extern ssize_t z_deflate(char *src, size_t size, char **dst);
extern ssize_t z_inflate(char *src, size_t size, char **dst);
extern void z_free(void);
extern char *z_get_version(void);

#endif /* DEFLATE_H */

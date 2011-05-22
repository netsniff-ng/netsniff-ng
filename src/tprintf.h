/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef TPRINTF_H
#define TPRINTF_H

extern void tprintf_init(void);
extern void tprintf(char *msg, ...);
extern void tprintf_flush(void);
extern void tprintf_cleanup(void);
extern size_t tprintf_get_free_count(void);

#endif /* TPRINTF_H */

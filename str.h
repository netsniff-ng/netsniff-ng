#ifndef STR_H
#define STR_H

#include <stdlib.h>

#include "built_in.h"

extern size_t strlcpy(char *dest, const char *src, size_t size);
extern int slprintf(char *dst, size_t size, const char *fmt, ...)  __check_format_printf(3, 4);
extern int slprintf_nocheck(char *dst, size_t size, const char *fmt, ...);
extern char *strtrim_right(char *p, char c);
extern noinline void *xmemset(void *s, int c, size_t n);
extern char *argv2str(int startind, int argc, char **argv);
extern char **argv_insert(char **argv, size_t *count, const char *str);
extern void argv_free(char **argv);
extern int str2mac(const char *str, uint8_t *mac, size_t len);

#endif /* STR_H */

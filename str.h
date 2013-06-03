#ifndef STR_H
#define STR_H

#include "built_in.h"

extern size_t strlcpy(char *dest, const char *src, size_t size);
extern int slprintf(char *dst, size_t size, const char *fmt, ...)  __check_format_printf(3, 4);
extern int slprintf_nocheck(char *dst, size_t size, const char *fmt, ...);
extern char *strtrim_right(char *p, char c);
extern noinline void *xmemset(void *s, int c, size_t n);

#endif /* STR_H */

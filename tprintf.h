#ifndef TPRINTF_H
#define TPRINTF_H

#include "built_in.h"
#include "colors.h"
#include "colorize.h"

extern void tprintf_init(void);
extern void tprintf(char *msg, ...) __check_format_printf(1, 2);
extern void tprintf_flush(void);
extern void tprintf_cleanup(void);

extern void tputchar_safe(int c);
extern void tputs_safe(const char *str, size_t len);

#define DEFAULT_TTY_SIZE	80

#endif /* TPRINTF_H */

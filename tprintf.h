/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef TPRINTF_H
#define TPRINTF_H

#include "built_in.h"
#include "colors.h"

extern void tprintf_init(void);
extern void tprintf(char *msg, ...) __check_format_printf(1, 2);
extern void tprintf_flush(void);
extern void tprintf_cleanup(void);

extern void tputchar_safe(int c);
extern void tputs_safe(const char *str, size_t len);

#define colorize_start(fore)			"\033[" __##fore "m"
#define colorize_start_full(fore, back)		"\033[" __##fore ";" __on_##back "m"
#define colorize_end()				"\033[" __reset "m"

#define DEFAULT_TTY_SIZE	80

#endif /* TPRINTF_H */

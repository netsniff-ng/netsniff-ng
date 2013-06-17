#ifndef DIE_H
#define DIE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>

#include "built_in.h"

static inline void panic(const char *format, ...)  __check_format_printf(1, 2);
static inline void syslog_panic(const char *format,
				...) __check_format_printf(1, 2);
static inline void syslog_maybe(bool cond, int priority,
				const char *format, ...) __check_format_printf(3, 4);

static inline void __noreturn __die_hard(void)
{
	exit(EXIT_FAILURE);
}

static inline void __noreturn __die_harder(void)
{
	_exit(EXIT_FAILURE);
}

static inline void __noreturn die(void)
{
	__die_hard();
}

static inline void __noreturn _die(void)
{
	__die_harder();
}

static inline void __noreturn panic(const char *format, ...)
{
	va_list vl;

	va_start(vl, format);
	vfprintf(stderr, format, vl);
	va_end(vl);

	die();
}

static inline void __noreturn syslog_panic(const char *format, ...)
{
	va_list vl;

	va_start(vl, format);
	vsyslog(LOG_ERR, format, vl);
	va_end(vl);

	die();
}

static inline void syslog_maybe(bool cond, int priority,
				const char *format, ...)
{
	if (cond) {
		va_list vl;

		va_start(vl, format);
		vsyslog(priority, format, vl);
		va_end(vl);
	}
}

#endif /* DIE_H */

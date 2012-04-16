/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef DIE_H 
#define DIE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <syslog.h>

static inline void die(void)
{
	exit(EXIT_FAILURE);
}

static inline void _die(void)
{
	_exit(EXIT_FAILURE);
}

static inline void panic(char *format, ...)
{
	va_list vl;
	va_start(vl, format);
	vfprintf(stderr, format, vl);
	va_end(vl);
	die();
}

static inline void syslog_panic(const char *format, ...)
{
	va_list vl;
	va_start(vl, format);
	vsyslog(LOG_ERR, format, vl);
	va_end(vl);
	die();
}

static inline void syslog_maybe(int may, int priority, const char *format, ...)
{
	if (may) {	
		va_list vl;
		va_start(vl, format);
		vsyslog(priority, format, vl);
		va_end(vl);
	}
}

static inline void whine(char *format, ...)
{
	va_list vl;
	va_start(vl, format);
	vfprintf(stderr, format, vl);
	va_end(vl);
}

#endif /* DIE_H */

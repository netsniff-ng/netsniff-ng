/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef DIE_H 
#define DIE_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "compiler.h"
#include "tty.h"
#include "xmalloc.h"

static inline void error_and_die(int status, char *msg, ...)
{
	va_list vl;
	va_start(vl, msg);
	vfprintf(stderr, msg, vl);
	va_end(vl);

	exit(status);
}

static inline void die(void)
{
	exit(EXIT_FAILURE);
}

static inline void _die(void)
{
	_exit(EXIT_FAILURE);
}

static inline void panic(char *msg, ...)
{
	va_list vl;
	va_start(vl, msg);
	vfprintf(stderr, msg, vl);
	va_end(vl);

	die();
}

static inline void panic_trace(char *msg, ...)
{
	va_list vl;
	va_start(vl, msg);
	vfprintf(stderr, msg, vl);
	va_end(vl);

	stacktrace();
	die();
}

static inline void whine(char *msg, ...)
{
	va_list vl;
	va_start(vl, msg);
	vfprintf(stderr, msg, vl);
	va_end(vl);
}

static inline void BUG(char *msg, ...)
{
	va_list vl;

	whine("BUG: ");
	va_start(vl, msg);
	vfprintf(stderr, msg, vl);
	va_end(vl);

	stacktrace();
	die();
}

static inline void BUG_ON(int cond, char *msg, ...)
{
	va_list vl;

	if (unlikely(cond)) {
		whine("BUG: ");
		va_start(vl, msg);
		vfprintf(stderr, msg, vl);
		va_end(vl);

		stacktrace();
		die();
	}
}

static inline void info(char *msg, ...)
{
	va_list vl;
	va_start(vl, msg);
	vfprintf(stdout, msg, vl);
	va_end(vl);
}

#ifdef _DEBUG_
static inline void debug(char *msg, ...)
{
	va_list vl;
	va_start(vl, msg);
	vfprintf(stderr, msg, vl);
	va_end(vl);

	fflush(stderr);
}

static inline void debug_blue(char *msg, ...)
{
	va_list vl;

	fprintf(stderr, "%s", colorize_start_full(white, blue));
	va_start(vl, msg);
	vfprintf(stderr, msg, vl);
	va_end(vl);
	fprintf(stderr, "%s\n", colorize_end());

	fflush(stderr);
}

static inline void debug_red(char *msg, ...)
{
	va_list vl;

	fprintf(stderr, "%s", colorize_start_full(white, red));
	va_start(vl, msg);
	vfprintf(stderr, msg, vl);
	va_end(vl);
	fprintf(stderr, "%s\n", colorize_end());

	fflush(stderr);
}

static inline void debug_green(char *msg, ...)
{
	va_list vl;

	fprintf(stderr, "%s", colorize_start_full(white, green));
	va_start(vl, msg);
	vfprintf(stderr, msg, vl);
	va_end(vl);
	fprintf(stderr, "%s\n", colorize_end());

	fflush(stderr);
}
#else
static inline void debug(char *msg, ...)
{
	/* NOP */
}

static inline void debug_blue(char *msg, ...)
{
	/* NOP */
}

static inline void debug_red(char *msg, ...)
{
	/* NOP */
}

static inline void debug_green(char *msg, ...)
{
	/* NOP */
}
#endif /* _DEBUG_ */

static inline void print_blue(char *msg, ...)
{
	va_list vl;

	fprintf(stdout, "%s", colorize_start_full(white, blue));
	va_start(vl, msg);
	vfprintf(stdout, msg, vl);
	va_end(vl);
	fprintf(stdout, "%s\n", colorize_end());

	fflush(stdout);
}

static inline void print_red(char *msg, ...)
{
	va_list vl;

	fprintf(stdout, "%s", colorize_start_full(white, red));
	va_start(vl, msg);
	vfprintf(stdout, msg, vl);
	va_end(vl);
	fprintf(stdout, "%s\n", colorize_end());

	fflush(stdout);
}

static inline void print_green(char *msg, ...)
{
	va_list vl;

	fprintf(stdout, "%s", colorize_start_full(white, green));
	va_start(vl, msg);
	vfprintf(stdout, msg, vl);
	va_end(vl);
	fprintf(stdout, "%s\n", colorize_end());

	fflush(stdout);
}

static inline void puke_and_die_num(int status, int num, char *msg, ...)
{
	va_list vl;
	va_start(vl, msg);
	vfprintf(stderr, msg, vl);
	va_end(vl);

	fprintf(stderr, ": %s\n", strerror(num));

	exit(status);
}

static inline void puke_and_die(int status, char *msg, ...)
{
	va_list vl;
	va_start(vl, msg);
	vfprintf(stderr, msg, vl);
	va_end(vl);

	fprintf(stderr, ": %s\n", strerror(errno));

	exit(status);
}

#endif /* DIE_H */

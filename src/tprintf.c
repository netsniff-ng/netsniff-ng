/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#define _BSD_SOURCE
#include <stdio.h>
#include <stdarg.h>

#include "xutils.h"
#include "tprintf.h"
#include "die.h"
#include "locking.h"
#include "built_in.h"

#define term_trailing_size	5
#define term_starting_size	3
#define term_curr_size		(get_tty_size() - term_trailing_size)

static char buffer[1024];
static volatile size_t buffer_use = 0;
static struct spinlock buffer_lock;

static inline void __tprintf_flush_newline(void)
{
	int i;
	fputc('\n', stdout);
	for (i = 0; i < term_starting_size; ++i)
		fputc(' ', stdout);
}

static inline int __tprintf_flush_skip(char *buffer, int i, size_t max)
{
	int val = buffer[i];
	if (val == ' ' || val == ',')
		return 1;
	return 0;
}

static void __tprintf_flush(void)
{
	int i;
	static ssize_t line_count = 0;
	size_t term_len = term_curr_size;

	for (i = 0; i < buffer_use; ++i) {
		if (buffer[i] == '\n') {
			term_len = term_curr_size;
			line_count = -1;
		}
		if (line_count == term_len) {
			__tprintf_flush_newline();
			line_count = term_starting_size;
			while (i < buffer_use &&
			       __tprintf_flush_skip(buffer, i, buffer_use))
				i++;
		}

		fputc(buffer[i], stdout);
		line_count++;
	}

	fflush(stdout);
	access_once(buffer_use) = 0;
}

void tprintf_flush(void)
{
	spinlock_lock(&buffer_lock);
	__tprintf_flush();
	spinlock_unlock(&buffer_lock);
}

void tprintf_init(void)
{
	spinlock_init(&buffer_lock);
}

void tprintf_cleanup(void)
{
	tprintf_flush();
	spinlock_destroy(&buffer_lock);
}

void tprintf(char *msg, ...)
{
	ssize_t ret;
	ssize_t avail;
	va_list vl;

	spinlock_lock(&buffer_lock);

	avail = sizeof(buffer) - buffer_use;
	bug_on(avail < 0);

	va_start(vl, msg);
	ret = vsnprintf(buffer + buffer_use, avail, msg, vl);
	va_end(vl);

	if (ret < 0)
		panic("vsnprintf screwed up in tprintf!\n");
	if (ret > sizeof(buffer))
		panic("No mem in tprintf left!\n");
	if (ret >= avail) {
		__tprintf_flush();

		avail = sizeof(buffer) - buffer_use;
		bug_on(avail < 0);

		va_start(vl, msg);
		ret = vsnprintf(buffer + buffer_use, avail, msg, vl);
		va_end(vl);

		if (ret < 0)
			panic("vsnprintf screwed up in tprintf!\n");
	}

	buffer_use += ret;

	spinlock_unlock(&buffer_lock);
}

/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL.
 */

/*
 * Copyright (C) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland, 
 *                    All rights reserved
 * Copyright (c) 1998 Bjorn Reese <breese@mail1.stofanet.dk>,
 *                    Stacktrace routine
 * Copyright (C) 2010, 2011 Daniel Borkmann <daniel@netsniff-ng.org>,
 *                    Ported from SSH and added several other functions and
 *                    heap consistency checks, added & heavily cleaned up
 *                    stacktrace routine
 *
 * Versions of malloc and friends that check their results, and never return
 * failure (they call fatal if they encounter an error).
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * You must compile with -DTARGETNAME="\"<target>\""
 */

#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mcheck.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <sys/types.h>

#ifndef SIZE_T_MAX
# define SIZE_T_MAX  ((size_t) ~0)
#endif
#define SYMNAMSIZ        512
#define TMPBUFSIZ        512
#define ADDRESSLISTSIZ    20

#include "xmalloc.h"
#include "compiler.h"
#include "strlcpy.h"
#include "tty.h"
#include "die.h"

struct faddress {
	unsigned long real_addr;
	unsigned long closest_addr;
	char name[SYMNAMSIZ];
	char type;
};

static void kill_pipe(int fd, int pid)
{
	close(fd);
	kill(pid, SIGTERM);
}

static int spawn_pipe(const char *cmd, pid_t *pid)
{
	int ret, pipefd[2];

	ret = pipe(pipefd);
	if (ret < 0)
		return ret;

	*pid = fork();
	switch (*pid) {
	case -1:
		close(pipefd[0]);
		close(pipefd[1]);
		ret = -EIO;
		break;
	case 0:
		close(pipefd[0]);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);

		dup2(pipefd[1], STDOUT_FILENO);
		dup2(pipefd[1], STDERR_FILENO);

		/*
		 * The System() call assumes that /bin/sh is
		 * always available, and so will we.
		 */
		execl("/bin/sh", "/bin/sh", "-c", cmd, NULL);
		_die();
		break;
	default:
		close(pipefd[1]);
		ret = pipefd[0];
		break;
	}

	return ret;
}

static int pull_from_pipe(int fd, char *buffer, int max)
{
	char c;
	int i = 0;

	do {
		if (read(fd, &c, 1) < 1)
			return 0;
		if (i < max)
			buffer[i++] = c;
	} while (c != '\n');
	buffer[i] = 0;

	return i;
}

void stacktrace(void)
{
	void *p;
	int i, fd, ret;
	char buffer[TMPBUFSIZ], type;
	char name[TMPBUFSIZ];
	struct faddress syms[ADDRESSLISTSIZ + 1];
	unsigned long addr, hi_addr, lo_addr;
	pid_t pid = 0;

	for (i = 0, p = &p; p; ++i) {
		/*
		 * This is based on code by Steve Coleman
		 * <steve.colemanjhuapl.edu> __builtin_return_address()
		 * only accepts a constant as argument.
		 */
		switch (i) {
		case 0:
			if (__builtin_frame_address(0))
				p = __builtin_return_address(0);
			else	p = NULL;
			break;
		case 1:
			if (__builtin_frame_address(1))
				p = __builtin_return_address(1);
			else	p = NULL;
			break;
		case 2:
			if (__builtin_frame_address(2))
				p = __builtin_return_address(2);
			else	p = NULL;
			break;
		case 3:
			if (__builtin_frame_address(3))
				p = __builtin_return_address(3);
			else	p = NULL;
			break;
		case 4:
			if (__builtin_frame_address(4))
				p = __builtin_return_address(4);
			else	p = NULL;
			break;
		case 5:
			if (__builtin_frame_address(5))
				p = __builtin_return_address(5);
			else	p = NULL;
			break;
		case 6:
			if (__builtin_frame_address(6))
				p = __builtin_return_address(6);
			else	p = NULL;
			break;
		case 7:
			if (__builtin_frame_address(7))
				p = __builtin_return_address(7);
			else	p = NULL;
			break;
		case 8:
			if (__builtin_frame_address(8))
				p = __builtin_return_address(8);
			else	p = NULL;
			break;
		case 9:
			if (__builtin_frame_address(9))
				p = __builtin_return_address(9);
			else	p = NULL;
			break;
		case 10:
			if (__builtin_frame_address(10))
				p = __builtin_return_address(10);
			else	p = NULL;
			break;
		case 11:
			if (__builtin_frame_address(11))
				p = __builtin_return_address(11);
			else	p = NULL;
			break;
		case 12:
			if (__builtin_frame_address(12))
				p = __builtin_return_address(12);
			else	p = NULL;
			break;
		case 13:
			if (__builtin_frame_address(13))
				p = __builtin_return_address(13);
			else	p = NULL;
			break;
		case 14:
			if (__builtin_frame_address(14))
				p = __builtin_return_address(14);
			else	p = NULL;
			break;
		case 15:
			if (__builtin_frame_address(15))
				p = __builtin_return_address(15);
			else	p = NULL;
			break;
		case 16:
			if (__builtin_frame_address(16))
				p = __builtin_return_address(16);
			else	p = NULL;
			break;
		case 17:
			if (__builtin_frame_address(17))
				p = __builtin_return_address(17);
			else	p = NULL;
			break;
		case 18:
			if (__builtin_frame_address(18))
				p = __builtin_return_address(18);
			else	p = NULL;
			break;
		case 19:
			if (__builtin_frame_address(19))
				p = __builtin_return_address(19);
			else	p = NULL;
			break;
		default:
			p = NULL;
			break;
		}

		if (p && i < ADDRESSLISTSIZ) {
			syms[i].real_addr = (unsigned long) p;
			syms[i].closest_addr = 0;
			syms[i].name[0] = 0;
			syms[i].type = ' ';
		} else {
			syms[i].real_addr = 0;
			break;
		}
	}

	strcpy(buffer, "nm -B ");
	strcat(buffer, TARGETNAME);

	lo_addr = ULONG_MAX;
	hi_addr = 0;

	fd = spawn_pipe(buffer, &pid);
	if (fd < 0)
		panic("Cannot spawn pipe to shell!\n");

	while (pull_from_pipe(fd, buffer, sizeof(buffer))) {
		if (buffer[0] == '\n')
			continue;
		ret = sscanf(buffer, "%lx %c %s", &addr, &type, name);
		if (ret != 3)
			continue;
		if (type != 't' && type != 'T')
			continue;
		if (addr == 0)
			continue;
		if (addr < lo_addr)
			lo_addr = addr;
		if (addr > hi_addr)
			hi_addr = addr;
		for (i = 0; syms[i].real_addr != 0; ++i) {
			if (addr <= syms[i].real_addr &&
			    addr > syms[i].closest_addr) {
				syms[i].closest_addr = addr;
				strlcpy(syms[i].name, name, SYMNAMSIZ);
				syms[i].type = type;
			}
		}
	}

	kill_pipe(fd, pid);

	for (i = 0; syms[i].real_addr != 0; ++i) {
		if (syms[i].name[0] == 0 ||
		    syms[i].real_addr <= lo_addr ||
		    syms[i].real_addr >= hi_addr)
			sprintf(buffer, "[%d] 0x%08lx ???\n",
				i, syms[i].real_addr);
		else
			sprintf(buffer, "[%d] 0x%08lx <%s+0x%lx> %c\n",
				i, syms[i].real_addr, syms[i].name,
				syms[i].real_addr - syms[i].closest_addr,
				syms[i].type);
		info(buffer);
	}
}

void mcheck_abort(enum mcheck_status stat)
{
	if (unlikely(stat != MCHECK_OK))
		panic("mcheck: mem inconsistency detected: %d\n", stat);
}

static void xmalloc_mcheck_init(void)
{
	int ret = mcheck_pedantic(mcheck_abort);
	if (ret < 0)
		panic("xmalloc: cannot init mcheck! bug\n");
	mtrace();
}

static void xmalloc_init_hook(void)
{
	xmalloc_mcheck_init();
}

void (*__malloc_initialize_hook)(void) = xmalloc_init_hook;

void muntrace_handler(int signal)
{
	if (signal != SIGSEGV) {
		muntrace();
		return;
	}

	info("Oops, SIGSEGV received!\n");
	info("Stacktrace:\n");
	stacktrace();
	info("@('_')@ __.-<^*Panic!*^>\n");
	muntrace();
	abort();
}

__hidden void *xmalloc(size_t size)
{
	void *ptr;
	enum mcheck_status stat;

	if (size == 0)
		panic("xmalloc: zero size\n");

	ptr = malloc(size);
	if (ptr == NULL)
		panic("xmalloc: out of memory (allocating %lu bytes)\n",
		      (u_long) size);
	stat = mprobe(ptr);
	if (stat > MCHECK_OK)
		panic("xmalloc: mem inconsistency detected: %d\n", stat);

	debug_blue("%p: %zu", ptr, size);
	return ptr;
}

__hidden void *xzmalloc(size_t size)
{
	void *ptr;
	enum mcheck_status stat;

	if (size == 0)
		panic("xzmalloc: zero size\n");

	ptr = malloc(size);
	if (ptr == NULL)
		panic("xzmalloc: out of memory (allocating %lu bytes)\n",
		      (u_long) size);

	stat = mprobe(ptr);
	if (stat > MCHECK_OK)
		panic("xzmalloc: mem inconsistency detected: %d\n", stat);

	memset(ptr, 0, size);

	debug_blue("%p: %zu", ptr, size);
	return ptr;
}

__hidden void *xmalloc_aligned(size_t size, size_t alignment)
{
	int ret;
	void *ptr;
	enum mcheck_status stat;

	if (size == 0)
		panic("xmalloc_aligned: zero size\n");

	ret = posix_memalign(&ptr, alignment, size);
	if (ret != 0)
		panic("xmalloc_aligned: out of memory (allocating %lu "
		      "bytes)\n", (u_long) size);
	stat = mprobe(ptr);
	if (stat > MCHECK_OK)
		panic("xmalloc_aligned: mem inconsistency detected: %d\n",
		      stat);

	debug_blue("%p: %zu", ptr, size);
	return ptr;
}

__hidden void *xvalloc(size_t size)
{
	void *ptr;
	enum mcheck_status stat;

	if (size == 0)
		panic("xvalloc: zero size\n");

	ptr = valloc(size);
	if (ptr == NULL)
		panic("xvalloc: out of memory (allocating %lu bytes)\n",
		      (u_long) size);
	stat = mprobe(ptr);
	if (stat > MCHECK_OK)
		panic("xvalloc: mem inconsistency detected: %d\n", stat);

	debug_blue("%p: %zu", ptr, size);
	return ptr;
}

__hidden void *xmallocz(size_t size)
{
	void *ptr;

	if (size + 1 < size)
		panic("xmallocz: data too large to fit into virtual "
		      "memory space\n");

	ptr = xmalloc(size + 1);
	((char*) ptr)[size] = 0;

	return ptr;
}

__hidden void *xmemdupz(const void *data, size_t len)
{
	return memcpy(xmallocz(len), data, len);
}

__hidden void *xcalloc(size_t nmemb, size_t size)
{
	void *ptr;
	enum mcheck_status stat;

	if (size == 0 || nmemb == 0)
		panic("xcalloc: zero size\n");
	if (SIZE_T_MAX / nmemb < size)
		panic("xcalloc: nmemb * size > SIZE_T_MAX\n");

	ptr = calloc(nmemb, size);
	if (ptr == NULL)
		panic("xcalloc: out of memory (allocating %lu bytes)\n",
		      (u_long) (size * nmemb));

	stat = mprobe(ptr);
	if (stat > MCHECK_OK)
		panic("xcalloc: mem inconsistency detected: %d\n", stat);

	debug_blue("%p: %zu", ptr, size);
	return ptr;
}

__hidden void *xrealloc(void *ptr, size_t nmemb, size_t size)
{
	void *new_ptr;
	size_t new_size = nmemb * size;
	enum mcheck_status stat;

	if (new_size == 0)
		panic("xrealloc: zero size\n");
	if (SIZE_T_MAX / nmemb < size)
		panic("xrealloc: nmemb * size > SIZE_T_MAX\n");

	if (ptr == NULL)
		new_ptr = malloc(new_size);
	else
		new_ptr = realloc(ptr, new_size);

	if (new_ptr == NULL)
		panic("xrealloc: out of memory (new_size %lu bytes)\n",
		      (u_long) new_size);

	stat = mprobe(new_ptr);
	if (stat > MCHECK_OK)
		panic("xrealloc: mem inconsistency detected: %d\n", stat);

	debug_blue("%p: %zu => %p: %zu", ptr, size, new_ptr, new_size);
	return new_ptr;
}

__hidden void xfree(void *ptr)
{
	enum mcheck_status stat;

	if (ptr == NULL)
		panic("xfree: NULL pointer given as argument\n");

	stat = mprobe(ptr);
	if (stat > MCHECK_OK)
		panic("xfree: mem inconsistency detected: %d\n", stat);
	debug_blue("%p => 0", ptr);

	free(ptr);
}

__hidden char *xstrdup(const char *str)
{
	size_t len;
	char *cp;

	len = strlen(str) + 1;
	cp = xmalloc(len);
	strlcpy(cp, str, len);

	return cp;
}

__hidden char *xstrndup(const char *str, size_t size)
{
	size_t len;
	char *cp;

	len = strlen(str) + 1;
	if (size < len)
		len = size;

	cp = xmalloc(len);
	strlcpy(cp, str, len);

	return cp;
}

__hidden int xdup(int fd)
{
	int ret = dup(fd);
	if (ret < 0)
		panic("xdup: dup failed\n");

	return ret;
}


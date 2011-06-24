/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

#define _GNU_SOURCE
#include <search.h>
#include <limits.h>
#include <errno.h>
#include <string.h>

#include "locking.h"
#include "cpusched.h"
#include "xmalloc.h"
#include "hash.h"

/* Flow to CPU mapper / scheduler to keep connection CPU-local */
struct map_entry {
	int fd;
	unsigned int cpu;
	struct map_entry *next;
};

static struct hash_table mapper;

static unsigned int *cpu_assigned = NULL;

static unsigned int cpu_len = 0;

static struct rwlock map_lock;

void init_cpusched(unsigned int cpus, size_t num)
{
	rwlock_init(&map_lock);
	rwlock_wr_lock(&map_lock);
	cpu_len = cpus;
	cpu_assigned = xzmalloc(cpus * sizeof(*cpu_assigned));
	memset(&mapper, 0, sizeof(mapper));
	init_hash(&mapper);
	rwlock_unlock(&map_lock);
}

static int get_appropriate_cpu(void)
{
	int i, cpu = 0;
	int work = INT_MAX;
	for (i = 0; i < cpu_len; ++i) {
		if (cpu_assigned[i] < work) {
			work = cpu_assigned[i];
			cpu = i;
		}
	}
	return cpu;
}

unsigned int socket_to_cpu(int fd)
{
	int cpu = 0;
	struct map_entry *entry;
	errno = 0;
	rwlock_rd_lock(&map_lock);
	entry = lookup_hash(fd, &mapper);
	while (entry && fd != entry->fd)
		entry = entry->next;
	if (entry && fd == entry->fd)
		cpu = entry->cpu;
	else
		errno = ENOENT;
	rwlock_unlock(&map_lock);
	return cpu;
}

unsigned int register_socket(int fd)
{
	void **pos;
	struct map_entry *entry;

	rwlock_wr_lock(&map_lock);
	entry = lookup_hash(fd, &mapper);
	while (entry && fd != entry->fd)
		entry = entry->next;
	if (entry && fd == entry->fd) {
		entry->cpu = get_appropriate_cpu();
		cpu_assigned[entry->cpu]++;
		rwlock_unlock(&map_lock);
		return entry->cpu;
	} else {
		entry = xzmalloc(sizeof(*entry));
		entry->fd = fd;
		entry->cpu = get_appropriate_cpu();
		cpu_assigned[entry->cpu]++;
	}
	pos = insert_hash(entry->fd, entry, &mapper);
	if (pos) {
		entry->next = *pos;
		*pos = &entry;
	}
	rwlock_unlock(&map_lock);

	return entry->cpu;
}

void unregister_socket(int fd)
{
	unsigned int ncpu = socket_to_cpu(fd);
	if (ncpu == 0 && errno == ENOENT)
		return;
	rwlock_wr_lock(&map_lock);
	cpu_assigned[ncpu]--;
	rwlock_unlock(&map_lock);
}

static int cleanup_batch(void *ptr)
{
	struct map_entry *tmp, *e = ptr;
	if (!ptr)
		return 0;
	while ((tmp = e->next)) {
		xfree(e);
		e = tmp;
	}
	xfree(e);
	return 0;
}

void destroy_cpusched(void)
{
	rwlock_destroy(&map_lock);
	xfree(cpu_assigned);
	cpu_len = 0;
	for_each_hash(&mapper, cleanup_batch);
	free_hash(&mapper);
}


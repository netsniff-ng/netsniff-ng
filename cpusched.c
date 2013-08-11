#define _GNU_SOURCE
#include <search.h>
#include <limits.h>
#include <errno.h>
#include <string.h>

#include "locking.h"
#include "cpusched.h"
#include "xmalloc.h"
#include "hash.h"

struct map_entry {
	int fd;
	unsigned int cpu;
	struct map_entry *next;
};

static struct hash_table mapper;
static unsigned int *cpu_work_map = NULL;
static unsigned int cpu_len = 0;
static struct rwlock map_lock;

static unsigned int get_appropriate_cpu(void)
{
	unsigned int i, cpu = 0;
	unsigned int work = UINT_MAX;

	for (i = 0; i < cpu_len; ++i) {
		if (cpu_work_map[i] < work) {
			work = cpu_work_map[i];
			cpu = i;
		}
	}

	return cpu;
}

unsigned int socket_to_cpu(int fd)
{
	int cpu = 0;
	struct map_entry *entry;

	rwlock_rd_lock(&map_lock);

	entry = lookup_hash(fd, &mapper);
	while (entry && fd != entry->fd)
		entry = entry->next;

	if (entry && fd == entry->fd)
		cpu = entry->cpu;

	rwlock_unlock(&map_lock);
	return cpu;
}

unsigned int register_socket(int fd)
{
	void **pos;
	struct map_entry *entry;

	rwlock_wr_lock(&map_lock);

	entry = xzmalloc(sizeof(*entry));
	entry->fd = fd;
	entry->cpu = get_appropriate_cpu();

	cpu_work_map[entry->cpu]++;

	pos = insert_hash(entry->fd, entry, &mapper);
	if (pos) {
		entry->next = (*pos);
		(*pos) = entry;
	}

	rwlock_unlock(&map_lock);
	return entry->cpu;
}

static struct map_entry *socket_to_map_entry(int fd)
{
	struct map_entry *entry, *ret = NULL;

	rwlock_rd_lock(&map_lock);

	entry = lookup_hash(fd, &mapper);
	while (entry && fd != entry->fd)
		entry = entry->next;

	if (entry && fd == entry->fd)
		ret = entry;

	rwlock_unlock(&map_lock);
	return ret;
}

void unregister_socket(int fd)
{
	struct map_entry *pos;
	struct map_entry *entry = socket_to_map_entry(fd);

	if (entry == NULL)
		return;

	rwlock_wr_lock(&map_lock);

	cpu_work_map[entry->cpu]--;

	pos = remove_hash(entry->fd, entry, entry->next, &mapper);
	while (pos && pos->next && pos->next != entry)
		pos = pos->next;

	if (pos && pos->next && pos->next == entry)
		pos->next = entry->next;

	entry->next = NULL;
	xfree(entry);

	rwlock_unlock(&map_lock);
}

static int cleanup_cpusched_batch(void *ptr)
{
	struct map_entry *next;
	struct map_entry *entry = ptr;

	if (!entry)
		return 0;

	while ((next = entry->next)) {
		entry->next = NULL;

		xfree(entry);
		entry = next;
	}

	xfree(entry);
	return 0;
}

void init_cpusched(unsigned int cpus)
{
	rwlock_init(&map_lock);
	cpu_work_map = xzmalloc((cpu_len = cpus) * sizeof(*cpu_work_map));
	init_hash(&mapper);
}

void destroy_cpusched(void)
{
	xfree(cpu_work_map);
	for_each_hash(&mapper, cleanup_cpusched_batch);
	free_hash(&mapper);
	rwlock_destroy(&map_lock);
}

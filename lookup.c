/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010 Daniel Borkmann.
 * Copyright 2014, 2015 Tobias Klauser
 * Subject to the GPL, version 2.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "hash.h"
#include "str.h"
#include "lookup.h"
#include "xmalloc.h"

static struct hash_table lookup_port_tables[LT_MAX];
static const char * const lookup_port_files[] = {
	[LT_PORTS_UDP]	= ETCDIRE_STRING "/udp.conf",
	[LT_PORTS_TCP]	= ETCDIRE_STRING "/tcp.conf",
	[LT_ETHERTYPES]	= ETCDIRE_STRING "/ether.conf",
};

struct lookup_entry {
	unsigned int id;
	char *str;
	struct lookup_entry *next;
};

void lookup_init(enum lookup_type which)
{
	FILE *fp;
	char buff[128], *ptr, *end;
	const char *file;
	struct hash_table *table;
	struct lookup_entry *p;
	void **pos;

	bug_on(which >= LT_MAX);
	table = &lookup_port_tables[which];
	file = lookup_port_files[which];

	fp = fopen(file, "r");
	if (!fp) {
		fprintf(stderr, "Cannot open %s: %s."
				"Port name resolution won't be available.\n",
				file, strerror(errno));
		return;
	}

	memset(buff, 0, sizeof(buff));

	while (fgets(buff, sizeof(buff), fp) != NULL) {
		buff[sizeof(buff) - 1] = 0;
		ptr = buff;

		p = xmalloc(sizeof(*p));
		p->id = strtol(ptr, &end, 0);
		/* not a valid line, skip */
		if (p->id == 0 && end == ptr) {
			xfree(p);
			continue;
		}

		ptr = strstr(buff, ", ");
		/* likewise */
		if (!ptr) {
			xfree(p);
			continue;
		}

		ptr += strlen(", ");
		ptr = strtrim_right(ptr, '\n');
		ptr = strtrim_right(ptr, ' ');

		p->str = xstrdup(ptr);
		p->next = NULL;

		pos = insert_hash(p->id, p, table);
		if (pos) {
			p->next = *pos;
			*pos = p;
		}

		memset(buff, 0, sizeof(buff));
	}

	fclose(fp);
}

static int __lookup_cleanup_single(void *ptr)
{
	struct lookup_entry *tmp, *p = ptr;

	if (!ptr)
		return 0;

	while ((tmp = p->next)) {
		xfree(p->str);
		xfree(p);
		p = tmp;
	}

	xfree(p->str);
	xfree(p);

	return 0;
}

void lookup_cleanup(enum lookup_type which)
{
	struct hash_table *table;

	bug_on(which >= LT_MAX);
	table = &lookup_port_tables[which];

	for_each_hash(table, __lookup_cleanup_single);
	free_hash(table);
}

#define __do_lookup_inline(id, hash_ptr)	\
	({								\
		struct lookup_entry *entry = lookup_hash(id, hash_ptr);	\
									\
		while (entry && id != entry->id)			\
			entry = entry->next;				\
									\
		(entry && id == entry->id ? entry->str : NULL); \
	})

char *lookup_ether_type(unsigned int id)
{
	return __do_lookup_inline(id, &lookup_port_tables[LT_ETHERTYPES]);
}

char *lookup_port_udp(unsigned int id)
{
	return __do_lookup_inline(id, &lookup_port_tables[LT_PORTS_UDP]);
}

char *lookup_port_tcp(unsigned int id)
{
	return __do_lookup_inline(id, &lookup_port_tables[LT_PORTS_TCP]);
}

/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010 Daniel Borkmann.
 * Copyright 2014 Tobias Klauser
 * Subject to the GPL, version 2.
 */

#include <string.h>

#include "hash.h"
#include "str.h"
#include "lookup.h"
#include "xmalloc.h"

static struct hash_table lookup_port_tables[PORTS_MAX];
static const char * const lookup_port_files[] = {
	[PORTS_UDP]	= ETCDIRE_STRING "/udp.conf",
	[PORTS_TCP]	= ETCDIRE_STRING "/tcp.conf",
	[PORTS_ETHER]	= ETCDIRE_STRING "/ether.conf",
};

struct port {
	unsigned int id;
	char *port;
	struct port *next;
};

void lookup_init_ports(enum ports which)
{
	FILE *fp;
	char buff[128], *ptr, *end;
	const char *file;
	struct hash_table *table;
	struct port *p;
	void **pos;

	bug_on(which >= PORTS_MAX);
	table = &lookup_port_tables[which];
	file = lookup_port_files[which];

	fp = fopen(file, "r");
	if (!fp)
		panic("No %s found!\n", file);

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

		p->port = xstrdup(ptr);
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
	struct port *tmp, *p = ptr;

	if (!ptr)
		return 0;

	while ((tmp = p->next)) {
		xfree(p->port);
		xfree(p);
		p = tmp;
	}

	xfree(p->port);
	xfree(p);

	return 0;
}

void lookup_cleanup_ports(enum ports which)
{
	struct hash_table *table;

	bug_on(which >= PORTS_MAX);
	table = &lookup_port_tables[which];

	for_each_hash(table, __lookup_cleanup_single);
	free_hash(table);
}

#define __do_lookup_inline(id, struct_name, hash_ptr, struct_member)	\
	({								\
		struct struct_name *entry = lookup_hash(id, hash_ptr);	\
									\
		while (entry && id != entry->id)			\
			entry = entry->next;				\
									\
		(entry && id == entry->id ? entry->struct_member : NULL); \
	})

char *lookup_ether_type(unsigned int id)
{
	return __do_lookup_inline(id, port, &lookup_port_tables[PORTS_ETHER], port);
}

char *lookup_port_udp(unsigned int id)
{
	return __do_lookup_inline(id, port, &lookup_port_tables[PORTS_UDP], port);
}

char *lookup_port_tcp(unsigned int id)
{
	return __do_lookup_inline(id, port, &lookup_port_tables[PORTS_TCP], port);
}

/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009 - 2013 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdint.h>
#include <stdbool.h>

#include "hash.h"
#include "xmalloc.h"
#include "oui.h"
#include "str.h"

static struct hash_table oui;

static bool initialized = false;

struct vendor_id {
	unsigned int id;
	char *vendor;
	struct vendor_id *next;
};

const char *lookup_vendor(unsigned int id)
{
	struct vendor_id *v;

	v = lookup_hash(id, &oui);
	while (v && id != v->id)
		v = v->next;

	return (v && id == v->id ? v->vendor : NULL);
}

void dissector_init_oui(void)
{
	FILE *fp;
	char buff[128], *ptr, *end;
	struct vendor_id *v;
	void **pos;

	if (initialized)
		return;

	fp = fopen(ETCDIRE_STRING "/oui.conf", "r");
	if (!fp)
		panic("No oui.conf found!\n");

	memset(buff, 0, sizeof(buff));

	while (fgets(buff, sizeof(buff), fp) != NULL) {
		buff[sizeof(buff) - 1] = 0;
		ptr = buff;

		v = xmalloc(sizeof(*v));
		v->id = strtol(ptr, &end, 0);
		/* not a valid line, skip */
		if (v->id == 0 && end == ptr) {
			xfree(v);
			continue;
		}

		ptr = strstr(buff, ", ");
		/* likewise */
		if (!ptr) {
			xfree(v);
			continue;
		}

		ptr += strlen(", ");
		ptr = strtrim_right(ptr, '\n');
		ptr = strtrim_right(ptr, ' ');

		v->vendor = xstrdup(ptr);
		v->next = NULL;

		pos = insert_hash(v->id, v, &oui);
		if (pos) {
			v->next = *pos;
			*pos = v;
		}

		memset(buff, 0, sizeof(buff));
	}

	fclose(fp);
	initialized = true;
}

static int dissector_cleanup_oui_hash(void *ptr)
{
	struct vendor_id *tmp, *v = ptr;

	if (!ptr)
		return 0;

	while ((tmp = v->next)) {
		xfree(v->vendor);
		xfree(v);
		v = tmp;
	}

	xfree(v->vendor);
	xfree(v);

	return 0;
}

void dissector_cleanup_oui(void)
{
	if (!initialized)
		return;

	for_each_hash(&oui, dissector_cleanup_oui_hash);
	free_hash(&oui);
	initialized = false;
}

/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdint.h>

#include "hash.h"
#include "xmalloc.h"
#include "xutils.h"
#include "oui.h"

static struct hash_table oui;
static int initialized = 0;

struct vendor_id {
	unsigned int id;
	char *vendor;
	struct vendor_id *next;
};

/* Note: this macro only applies to the lookup_* functions here in this file,
 * mainly to remove redundand code. */
#define __do_lookup_inline(id, struct_name, hash_ptr, struct_member)	      \
	({								      \
		struct struct_name *entry = lookup_hash(id, hash_ptr);	      \
		while (entry && id != entry->id)			      \
			entry = entry->next;				      \
		(entry && id == entry->id ? entry->struct_member : "Unknown");\
	})

char *lookup_vendor(unsigned int id)
{
	return __do_lookup_inline(id, vendor_id, &oui, vendor);
}

void dissector_init_oui(void)
{
	FILE *fp;
	char buff[512], *ptr;
	struct vendor_id *ven;
	void **pos;

	if (initialized)
		return;

	fp = fopen("/etc/netsniff-ng/oui.conf", "r");
	if (!fp)
		panic("No /etc/netsniff-ng/oui.conf found!\n");

	memset(buff, 0, sizeof(buff));
	while (fgets(buff, sizeof(buff), fp) != NULL) {
		buff[sizeof(buff) - 1] = 0;

		ven = xmalloc(sizeof(*ven));
		ptr = buff;
		ptr = skips(ptr);
		ptr = getuint(ptr, &ven->id);
		ptr = skips(ptr);
		ptr = skipchar(ptr, ',');
		ptr = skips(ptr);
		ptr = strtrim_right(ptr, '\n');
		ptr = strtrim_right(ptr, ' ');
		ven->vendor = xstrdup(ptr);
		ven->next = NULL;
		pos = insert_hash(ven->id, ven, &oui);
		if (pos) {
			ven->next = *pos;
			*pos = ven;
		}
		memset(buff, 0, sizeof(buff));
	}
	fclose(fp);

	initialized = 1;
}

static int __dissector_cleanup_oui(void *ptr)
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
	for_each_hash(&oui, __dissector_cleanup_oui);
	free_hash(&oui);

	initialized = 0;
}

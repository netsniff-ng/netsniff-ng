#ifndef HASH_H
#define HASH_H

/* Hash table implementation from the GIT project. */
/* Copyright 2008 (C) Linus Torvalds, GPL version 2 */
/*
 * These are some simple generic hash table helper functions.
 * Not necessarily suitable for all users, but good for things
 * where you want to just keep track of a list of things, and
 * have a good hash to use on them.
 *
 * It keeps the hash table at roughly 50-75% free, so the memory
 * cost of the hash table itself is roughly
 *
 *	3 * 2*sizeof(void *) * nr_of_objects
 *
 * bytes.
 *
 * FIXME: on 64-bit architectures, we waste memory. It would be
 * good to have just 32-bit pointers, requiring a special allocator
 * for hashed entries or something.
 */

#include <stdio.h>

#define alloc_nr(x) (((x) + 16) * 3 / 2)
#define INSERT_HASH_PROTOS(ops, table)					\
	do {								\
		void **pos = insert_hash((ops).key, &(ops), &(table));	\
		/* We already had an entry there? */			\
		if (pos) {						\
			(ops).next = *pos;				\
			*pos = &(ops);					\
		}							\
	} while (0)

struct hash_table_entry {
	unsigned int hash;
	void *ptr;
};

struct hash_table {
	unsigned int size, nr;
	struct hash_table_entry *array;
};

extern void *lookup_hash(unsigned int hash, const struct hash_table *table);
extern void **insert_hash(unsigned int hash, void *ptr,
			  struct hash_table *table);
extern void *remove_hash(unsigned int hash, void *ptr, void *ptr_next,
			 struct hash_table *table);
extern int for_each_hash(const struct hash_table *table, int (*fn)(void *));
extern int for_each_hash_int(const struct hash_table *table,
			     int (*fn)(void *, int), int arg);
extern void free_hash(struct hash_table *table);

static inline void init_hash(struct hash_table *table)
{
	table->size = 0;
	table->nr = 0;
	table->array = NULL;
}

static inline unsigned char icase_hash(unsigned char c)
{
	return c & ~((c & 0x40) >> 1);
}

static inline unsigned int hash_name(const char *name, int namelen)
{
	unsigned int hash = 0x123;
	do {
		unsigned char c = *name++;
		c = icase_hash(c);
		hash = hash * 101 + c;
	} while (--namelen);
	return hash;
}

#endif /* HASH_H */

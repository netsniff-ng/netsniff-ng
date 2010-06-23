/*
 * Copyright (C) 2009, 2010  Daniel Borkmann <daniel@netsniff-ng.org> and 
 *                           Emmanuel Roullit <emmanuel@netsniff-ng.org>
 *
 * This program is free software; you can redistribute it and/or modify 
 * it under the terms of the GNU General Public License as published by 
 * the Free Software Foundation; either version 2 of the License, or (at 
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License 
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 51 Franklin St, Fifth Floor, Boston, MA 02110, USA
 */

#ifndef _NET_HASH_H_
#define _NET_HASH_H_

/*
 * Internal data structures
 */

#include <stdint.h>
#include <unistd.h>

struct hashtable_bucket {
	void *key;
	void *data;
	struct hashtable_bucket *next;
};

struct hashtable_callbacks {
	void *(*key_copy) (void *k);
	void (*key_free) (void *k);
	 uintptr_t(*key_to_hash) (void *k);
	int (*key_equal) (void *k1, void *k2);
};

struct hashtable {
	size_t size;
	uint32_t elems;
	struct hashtable_callbacks *f;
	struct hashtable_bucket **table;
};

/*
 * Functions, generic
 */

extern int hashtable_init(struct hashtable **ht, size_t size, struct hashtable_callbacks *f);
extern void hashtable_destroy(struct hashtable *ht);
extern void *hashtable_insert(struct hashtable *ht, void *key, void *data);
extern void *hashtable_find(struct hashtable *ht, void *key);
extern void *hashtable_delete(struct hashtable *ht, void *key);
extern int hashtable_foreach(struct hashtable *ht, void (*callback) (void *key, void *data));

/*
 * Functions, specific hashtables
 */

extern int ieee_vendors_init(void);
extern void ieee_vendors_destroy(void);
extern const char *ieee_vendors_find(const uint8_t * mac_addr);

extern int ports_udp_init(void);
extern void ports_udp_destroy(void);
extern const char *ports_udp_find(uint16_t port);

extern int ports_tcp_init(void);
extern void ports_tcp_destroy(void);
extern const char *ports_tcp_find(uint16_t port);

extern int ether_types_init(void);
extern void ether_types_destroy(void);
extern const char *ether_types_find(uint16_t type);
extern const char *ether_types_find_less(uint16_t type);

#endif				/* _NET_HASH_H_ */

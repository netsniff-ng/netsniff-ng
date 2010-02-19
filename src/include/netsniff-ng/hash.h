/* XXX: Coding Style - use the tool indent with the following (Linux kernel
 *                     code indents)
 *
 * indent -nbad -bap -nbc -bbo -hnl -br -brs -c33 -cd33 -ncdb -ce -ci4   \
 *        -cli0 -d0 -di1 -nfc1 -i8 -ip0 -l120 -lp -npcs -nprs -npsl -sai \
 *        -saf -saw -ncs -nsc -sob -nfca -cp33 -ss -ts8 -il1
 *
 *
 * netsniff-ng
 *
 * High performance network sniffer for packet inspection
 *
 * Copyright (C) 2009, 2010  Daniel Borkmann <danborkmann@googlemail.com> and 
 *                           Emmanuel Roullit <emmanuel.roullit@googlemail.com>
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
 *
 * Note: Your kernel has to be compiled with CONFIG_PACKET_MMAP=y option in 
 *       order to use this.
 */

/*
 * Contains: 
 *    Bucket hash related stuff
 */

#ifndef _NET_HASH_H_
#define _NET_HASH_H_

/*
 * Internal data structures
 */

#include <stdint.h>
#include <unistd.h>

typedef struct bucket {
	void *key;
	void *data;
	struct bucket *next;
} hashtable_bucket_t;
typedef struct callbacks {
	void *(*key_copy) (void *k);
	void (*key_free) (void *k);
	uintptr_t (*key_to_hash) (void *k);
	int (*key_equal) (void *k1, void *k2);
} hashtable_callbacks_t;
typedef struct hashtable {
	size_t size;
	uint32_t elems;
	hashtable_callbacks_t *f;
	hashtable_bucket_t **table;
} hashtable_t;

/*
 * Functions, generic
 */

extern int hashtable_init(hashtable_t ** ht, size_t size, hashtable_callbacks_t * f);
extern void hashtable_destroy(hashtable_t * ht);
extern void *hashtable_insert(hashtable_t * ht, void *key, void *data);
extern void *hashtable_find(hashtable_t * ht, void *key);
extern void *hashtable_delete(hashtable_t * ht, void *key);
extern int hashtable_foreach(hashtable_t * ht, void (*callback) (void *data));

/*
 * Functions, specific hashtables
 */

extern int ieee_vendors_init(void);
extern void ieee_vendors_destroy(void);
extern char *ieee_vendors_find(uint8_t mac_addr[6]);

#endif				/* _NET_HASH_H_ */

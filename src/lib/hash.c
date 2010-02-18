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

#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <arpa/inet.h>

#include <netsniff-ng/macros.h>
#include <netsniff-ng/oui.h>
#include <netsniff-ng/hash.h>

/*
 * Hash function API
 */

int hashtable_init(hashtable_t ** ht, size_t size, hashtable_callbacks_t * f)
{
	int i;

	if(!ht || !f || size <= 0)
		return -EINVAL;
	if(!f->key_copy || !f->key_to_hash || !f->key_equal)
		return -EINVAL;

	*ht = malloc(sizeof(**ht));
	if(!(*ht))
		return -ENOMEM;

	(*ht)->size = size;
	(*ht)->elems = 0;
	(*ht)->f = f;

	(*ht)->table = malloc(sizeof(*(*ht)->table) * size);
	if(!(*ht)->table) {
		free(*ht);
		return -ENOMEM;
	}

	for(i = 0; i < size; ++i)
		(*ht)->table[i] = NULL;

	return 0;
}

void hashtable_destroy(hashtable_t * ht)
{
	int i;
	hashtable_bucket_t *hb, *hb_prev;

	if(!ht)
		return;

	for(i = 0; i < ht->size; ++i) {
		for(hb = ht->table[i]; hb != NULL;) {
			hb_prev = hb;
			ht->f->key_free(hb->key);
			hb = hb->next;
			free(hb_prev);
		}
	}

	free(ht->table);
	free(ht);
}

void *hashtable_insert(hashtable_t * ht, void *key, void *data)
{
	unsigned int val;
	hashtable_bucket_t *hb;

	if(!ht)
		return NULL;

	val = ht->f->key_to_hash(key) % ht->size;

	for(hb = ht->table[val]; hb; hb = hb->next)
		if(ht->f->key_equal(key, hb->key))
			return hb->data;

	hb = malloc(sizeof(*hb));
	if(!hb)
		return NULL;

	hb->next = ht->table[val];
	hb->data = data;
	hb->key = ht->f->key_copy(key);
	ht->table[val] = hb;

	ht->elems++;

	return data;
}

void *hashtable_find(hashtable_t * ht, void *key)
{
	unsigned int val;
	hashtable_bucket_t *hb;

	if(!ht)
		return NULL;

	val = ht->f->key_to_hash(key) % ht->size;

	for(hb = ht->table[val]; hb; hb = hb->next)
		if(ht->f->key_equal(key, hb->key))
			return hb->data;
	return NULL;
}

void *hashtable_delete(hashtable_t * ht, void *key)
{
	unsigned int val;
	void *data = NULL;
	hashtable_bucket_t *hb, *hb_prev;

	if(!ht)
		return NULL;

	val = ht->f->key_to_hash(key) % ht->size;

	for(hb_prev = NULL, hb = ht->table[val]; hb; hb_prev = hb, hb = hb->next) {
		if(ht->f->key_equal(key, hb->key)) {
			data = hb->data;

			if(hb_prev)
				hb_prev->next = hb->next;
			else
				ht->table[val] = hb->next;

			ht->f->key_free(hb->key);
			free(hb);
			ht->elems--;
		}
	}

	return data;
}

int hashtable_foreach(hashtable_t * ht, void (*callback) (void *data))
{
	int i;
	hashtable_bucket_t *hb;

	if(!ht || !callback)
		return -EINVAL;

	for(i = 0; i < ht->size; ++i)
		for(hb = ht->table[i]; hb; hb = hb->next)
			callback(hb->data);

	return 0;
}

/*
 * Some callback implementations
 */

void *no_copy(void *key)
{
	return key;
}

void no_free(void *key)
{
	return;
}

unsigned int raw_key_to_hash(void *key)
{
	return (unsigned int) key;
}

int raw_key_equal(void *key1, void *key2)
{
	return (key1 == key2);
}

/*
 * Specific hash function implementations
 */

static hashtable_t *ieee_vendor_db;
static hashtable_callbacks_t ieee_vendor_cbs = {
	.key_copy = no_copy,
	.key_free = no_free,
	.key_to_hash = raw_key_to_hash,
	.key_equal = raw_key_equal,
};

int ieee_vendors_init(void)
{
	int i, ret;
	size_t len;

	ret = hashtable_init(&ieee_vendor_db, 14000, &ieee_vendor_cbs);
	if(ret < 0) {
		warn("Could not create vendor hashtable! No mem left.\n");
		return ret;
	}

	len = sizeof(vendor_db) / sizeof(vendor_id_t);
	for(i = 0; i < len; ++i) {
		hashtable_insert(ieee_vendor_db, (void *) vendor_db[i].id, vendor_db[i].vendor);
	}
	
	return 0;
}

void ieee_vendors_destroy(void)
{
	hashtable_destroy(ieee_vendor_db);
}

char *ieee_vendors_find(uint8_t mac_addr[6])
{
	char *vendor;
	uint32_t key = 0;
	uint8_t *keyp = (uint8_t *) &key;

	keyp[1] = mac_addr[0];
	keyp[2] = mac_addr[1];
	keyp[3] = mac_addr[2];

	vendor = hashtable_find(ieee_vendor_db, (void *) ntohl(key));
	if(!vendor)
		vendor = vendor_unknown;

	return vendor;
}


/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann, rewritten
 * Copyright 1991-2007 Kawahara Lab., Kyoto University
 * Copyright 2000-2005 Shikano Lab., Nara Institute of Science and Technology
 * Copyright 2005-2007 Julius project team, Nagoya Institute of Technology
 * All rights reserved
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "patricia.h"
#include "built_in.h"
#include "xmalloc.h"

static unsigned char mbit[] = {0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01};

static inline int testbit(char *str, size_t slen, int bitplace)
{
	int maskptr;
	if ((maskptr = bitplace >> 3) > slen)
		return 0;
	return (str[maskptr] & mbit[bitplace & 7]);
}

static inline int testbit_max(char *str, int bitplace, int maxbitplace)
{
	if (bitplace >= maxbitplace)
		return 0;
	return (str[bitplace >> 3] & mbit[bitplace & 7]);
}

static int where_the_bit_differ(char *str1, size_t l1, char *str2, size_t l2)
{
	int p = 0, bitloc;
	while (str1[p] == str2[p])
		p++;
	bitloc = p * 8;
	while (testbit(str1, l1, bitloc) ==
	       testbit(str2, l2, bitloc))
		bitloc++;
	return bitloc;
}

static struct patricia_node *new_node(void)
{
	struct patricia_node *n = xzmalloc(sizeof(*n));
	n->l = n->r = NULL;
	return n;
}

static void free_node(struct patricia_node *n)
{
	if (n->key)
		xfree(n->key);
	if (n->addr)
		xfree(n->addr);
	xfree(n);
}

void ptree_display(struct patricia_node *node, int level)
{
	int i;
	for (i = 0; i < level; ++i)
		printf("-");
	if (node->l == NULL && node->r == NULL)
		printf("leaf: (%s -> %d)\n", (char *) node->key, node->value.data);
	else {
		printf("thres: %d\n", node->value.thres_bit);
		if (node->l != NULL)
			ptree_display(node->l, level + 1);
		if (node->r != NULL)
			ptree_display(node->r, level + 1);
	}
}

void ptree_get_key(int data, struct patricia_node *node,
		   struct patricia_node **wanted)
{
	if (!node)
		return;
	if (node->l == NULL && node->r == NULL) {
		if (node->value.data == data)
			(*wanted) = node;
	} else {
		if (node->l != NULL)
			ptree_get_key(data, node->l, wanted);
		if (node->r != NULL)
			ptree_get_key(data, node->r, wanted);
	}
}

void ptree_get_key_addr(struct sockaddr_storage *addr, size_t alen,
			struct patricia_node *node, struct patricia_node **wanted)
{
	if (!node)
		return;
	if (node->l == NULL && node->r == NULL) {
		if (!memcmp(node->addr, addr, node->alen))
			(*wanted) = node;
	} else {
		if (node->l != NULL)
			ptree_get_key_addr(addr, alen, node->l, wanted);
		if (node->r != NULL)
			ptree_get_key_addr(addr, alen, node->r, wanted);
	}
}

static int ptree_search_data_r(struct patricia_node *node, char *str,
			       size_t slen, struct sockaddr_storage *addr,
			       size_t *alen, int maxbitplace)
{
	if (node->l == NULL && node->r == NULL) {
		if (node->addr && addr)
			memcpy(addr, node->addr, node->alen);
		(*alen) = node->alen;
		return node->value.data;
	}
	if (testbit_max(str, node->value.thres_bit, maxbitplace) != 0)
		return ptree_search_data_r(node->r, str, slen, addr,
					   alen, maxbitplace);
	else
		return ptree_search_data_r(node->l, str, slen, addr,
					   alen, maxbitplace);
}

static int *ptree_search_data_r_p(struct patricia_node *node, char *str,
				  size_t slen, int maxbitplace)
{
	if (node->l == NULL && node->r == NULL)
		return &(node->value.data);
	if (testbit_max(str, node->value.thres_bit, maxbitplace) != 0)
		return ptree_search_data_r_p(node->r, str, slen, maxbitplace);
	else
		return ptree_search_data_r_p(node->l, str, slen, maxbitplace);
}

static int ptree_search_data_r_x(struct patricia_node *node, char *str,
				 size_t slen, struct sockaddr_storage *addr,
				 size_t *alen, int maxbitplace)
{
	if (node->l == NULL && node->r == NULL) {
		if (node->klen == slen && !memcmp(str, node->key, node->klen)) {
			if (node->addr && addr)
				memcpy(addr, node->addr, node->alen);
			(*alen) = node->alen;
			return node->value.data;
		} else
			return -ENOENT;
	}
	if (testbit_max(str, node->value.thres_bit, maxbitplace) != 0)
		return ptree_search_data_r_x(node->r, str, slen, addr,
					     alen, maxbitplace);
	else
		return ptree_search_data_r_x(node->l, str, slen, addr,
					     alen, maxbitplace);
}

int ptree_search_data_nearest(void *str, size_t sstr, struct sockaddr_storage *addr,
			      size_t *alen, struct patricia_node *root)
{
	if (!root)
		return -ENOENT;
	return ptree_search_data_r(root, str, sstr, addr, alen, sstr * 8);
}

static int *ptree_search_data_nearest_ptr(char *str, size_t sstr,
					  struct patricia_node *root)
{
	return ptree_search_data_r_p(root, str, sstr, sstr * 8);
}

int ptree_search_data_exact(void *str, size_t sstr, struct sockaddr_storage *addr,
			    size_t *alen, struct patricia_node *root)
{
	if (!root)
		return -ENOENT;
	return ptree_search_data_r_x(root, str, sstr, addr, alen, sstr * 8);
}

static struct patricia_node *ptree_make_root_node(char *str, size_t sstr,
						  int data, struct sockaddr_storage *addr,
						  size_t alen)
{
	struct patricia_node *n = new_node();
	n->value.data = data;
	n->key = xmemdupz(str, sstr);
	n->klen = sstr;
	if (addr)
		n->addr = xmemdupz(addr, alen);
	else
		n->addr = NULL;
	n->alen = alen;
	return n;
}

static void ptree_add_entry_at(char *str, size_t slen, int bitloc, int data,
			       struct sockaddr_storage *addr, size_t alen,
			       struct patricia_node **parentlink)
{
	struct patricia_node *node = (*parentlink);
	if (node->value.thres_bit > bitloc ||
	    (node->l == NULL && node->r == NULL)) {
		struct patricia_node *newleaf, *newbranch;

		newleaf = new_node();
		newleaf->value.data = data;
		newleaf->key = xmemdupz(str, slen);
		newleaf->klen = slen;
		if (addr)
			newleaf->addr = xmemdupz(addr, alen);
		else
			newleaf->addr = NULL;
		newleaf->alen = alen;

		newbranch = new_node();
		newbranch->value.thres_bit = bitloc;
		(*parentlink) = newbranch;
		if (testbit(str, slen, bitloc) ==0) {
			newbranch->l = newleaf;
			newbranch->r = node;
		} else {
			newbranch->l = node;
			newbranch->r = newleaf;
		}
		return;
	} else {
		if (testbit(str, slen, node->value.thres_bit) != 0)
			ptree_add_entry_at(str, slen, bitloc, data,
					   addr, alen, &(node->r));
		else
			ptree_add_entry_at(str, slen, bitloc, data,
					   addr, alen, &(node->l));
	}
}

int ptree_add_entry(void *str, size_t sstr, int data, struct sockaddr_storage *addr,
		    size_t alen, struct patricia_node **root)
{
	int *ptr, bitloc, malicious = 0;
	struct patricia_node *n;

	if (!(*root))
		(*root) = ptree_make_root_node(str, sstr, data, addr, alen);
	else {
		ptr = ptree_search_data_nearest_ptr(str, sstr, (*root));
		n = container_of(ptr, struct patricia_node, value.data);
		if (n->klen == sstr && !memcmp(str, n->key, n->klen)) {
			/* Make sure if entry exists, that we also have the
			 * same data, otherwise, we drop the packet */
			if (n->value.data != data)
				malicious = 1;
			else if (n->alen != alen)
				malicious = 1;
			else if ((n->addr && !addr) || (!n->addr && addr))
				malicious = 1;
			else if (n->alen == alen && n->addr && addr) {
				if (memcmp(n->addr, addr, alen))
					malicious = 1;
			}
			return malicious;
		}
		bitloc = where_the_bit_differ(str, sstr, n->key, n->klen);
		ptree_add_entry_at(str, sstr, bitloc, data, addr, alen, root);
	}

	return malicious;
}

static void ptree_remove_entry_r(struct patricia_node *now,
				 struct patricia_node *up,
				 struct patricia_node *up2,
				 char *str, size_t slen, int maxbitplace,
				 struct patricia_node **root)
{
	struct patricia_node *b;

	if (now->l == NULL && now->r == NULL) {
		if (now->klen != slen)
			return;
		if (memcmp(now->key, str, slen))
			return;
		if (up == NULL) {
			*root = NULL;
			free_node(now);
			return;
		}
		b = (up->r == now) ? up->l : up->r;
		if (up2 == NULL) {
			*root = b;
			free_node(now);
			free_node(up);
			return;
		}
		if (up2->l == up)
			up2->l = b;
		else
			up2->r = b;
		free_node(now);
		free_node(up);
		return;
	} else {
		if (testbit_max(str, now->value.thres_bit, maxbitplace) != 0)
			ptree_remove_entry_r(now->r, now, up, str, slen,
					     maxbitplace, root);
		else
			ptree_remove_entry_r(now->l, now, up, str, slen,
					     maxbitplace, root);
	}
}

void ptree_del_entry(void *str, size_t sstr, struct patricia_node **root)
{
	if (!(*root))
		return;
	ptree_remove_entry_r(*root, NULL, NULL, str, sstr, sstr * 8, root);
}

void ptree_free(struct patricia_node *node)
{
	if (!node)
		return;
	if (node->l)
		ptree_free(node->l);
	if (node->r)
		ptree_free(node->r);
	free_node(node);
}


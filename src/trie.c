/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <asm/byteorder.h>

#include "patricia.h"
#include "locking.h"
#include "trie.h"

struct ipv4hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__extension__ uint8_t h_ihl:4,
			      h_version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__extension__ uint8_t h_version:4,
			      h_ihl:4;
#else
# error "Please fix <asm/byteorder.h>"
#endif
	uint8_t h_tos;
	uint16_t h_tot_len;
	uint16_t h_id;
	uint16_t h_frag_off;
	uint8_t h_ttl;
	uint8_t h_protocol;
	uint16_t h_check;
	uint32_t h_saddr;
	uint32_t h_daddr;
} __attribute__((packed));

struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__extension__ uint8_t priority:4,
			      version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__extension__ uint8_t version:4,
			      priority:4;
#else
# error "Please fix <asm/byteorder.h>"
#endif
	uint8_t flow_lbl[3];
	uint16_t payload_len;
	uint8_t nexthdr;
	uint8_t hop_limit;
	struct in6_addr saddr;
	struct in6_addr daddr;
} __attribute__((packed));

static struct patricia_node *tree = NULL;

static struct rwlock tree_lock;

void trie_addr_lookup(char *buff, size_t len, int ipv4, int *fd,
		      struct sockaddr_storage *addr, size_t *alen)
{
	void *data;
	size_t dlen;
	struct ipv4hdr *hdr4 = (void *) buff;
	struct ipv6hdr *hdr6 = (void *) buff;

	data = ipv4 ? (void *) &hdr4->h_daddr : (void *) &hdr6->daddr;
	dlen = ipv4 ? sizeof(hdr4->h_daddr) : sizeof(hdr6->daddr);

	if (unlikely((ipv4 && ((struct ipv4hdr *) buff)->h_version != 4) ||
		     (!ipv4 && ((struct ipv6hdr *) buff)->version  != 6))) {
		memset(addr, 0, sizeof(*addr));
		(*alen) = 0;
		(*fd) = -1;
		return;
	}

	/* Always happens on the dst address */
	rwlock_rd_lock(&tree_lock);
	(*fd) = ptree_search_data_exact(data, dlen, addr, alen, tree);
	rwlock_unlock(&tree_lock);
}

int trie_addr_maybe_update(char *buff, size_t len, int ipv4, int fd,
			   struct sockaddr_storage *addr, size_t alen)
{
	int ret;
	void *data;
	size_t dlen;
	struct ipv4hdr *hdr4 = (void *) buff;
	struct ipv6hdr *hdr6 = (void *) buff;

	data = ipv4 ? (void *) &hdr4->h_saddr : (void *) &hdr6->saddr;
	dlen = ipv4 ? sizeof(hdr4->h_saddr) : sizeof(hdr6->saddr);

	if (unlikely((ipv4 && ((struct ipv4hdr *) buff)->h_version != 4) ||
		     (!ipv4 && ((struct ipv6hdr *) buff)->version  != 6)))
		return -1;

	/* Always happens on the src address */
	rwlock_wr_lock(&tree_lock);
	ret = ptree_maybe_add_entry(data, dlen, fd, addr, alen, &tree);
	rwlock_unlock(&tree_lock);

	return ret;
}

void trie_addr_remove(int fd)
{
	int found = 1;
	struct patricia_node *n = NULL;

	rwlock_wr_lock(&tree_lock);

	while (found) {
		ptree_get_key(fd, tree, &n);
		if (n) {
			ptree_del_entry(n->key, n->klen, &tree);
			n = NULL;
		} else
			found = 0;
	}

	rwlock_unlock(&tree_lock);
}

void trie_addr_remove_addr(struct sockaddr_storage *addr, size_t alen)
{
	int found = 1;
	struct patricia_node *n = NULL;

	rwlock_wr_lock(&tree_lock);

	while (found) {
		ptree_get_key_addr(addr, alen, tree, &n);
		if (n) {
			ptree_del_entry(n->key, n->klen, &tree);
			n = NULL;
		} else
			found = 0;
	}

	rwlock_unlock(&tree_lock);
}

void trie_init(void)
{
	rwlock_init(&tree_lock);
}

void trie_cleanup(void)
{
	rwlock_wr_lock(&tree_lock);
	ptree_free(tree);
	rwlock_unlock(&tree_lock);

	rwlock_destroy(&tree_lock);
}

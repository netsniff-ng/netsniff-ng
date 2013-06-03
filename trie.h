#ifndef TRIE_H
#define TRIE_H

#include <netinet/in.h>

extern void trie_addr_lookup(char *buff, size_t len, int ipv4, int *fd,
			     struct sockaddr_storage *addr, size_t *alen);
extern int trie_addr_maybe_update(char *buff, size_t len, int ipv4, int fd,
				  struct sockaddr_storage *addr, size_t alen);
extern void trie_addr_remove(int fd);
extern void trie_addr_remove_addr(struct sockaddr_storage *addr, size_t alen);
extern void trie_init(void);
extern void trie_cleanup(void);

#endif /* TRIE_H */

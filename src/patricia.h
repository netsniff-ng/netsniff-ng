/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann
 * Copyright 1991-2007 Kawahara Lab., Kyoto University
 * Copyright 2000-2005 Shikano Lab., Nara Institute of Science and Technology
 * Copyright 2005-2007 Julius project team, Nagoya Institute of Technology
 * All rights reserved
 * Subject to the GPL.
 */

#ifndef PATRICIA_H
#define PATRICIA_H

struct patricia_node {
	union {
		int data;
		int thres_bit;
	} value;
	char *key; //TODO save exact key to check lookup string against it
	struct patricia_node *l, *r;
};

//TODO: add remove node
extern int ptree_search_data(char *str, struct patricia_node *root);
extern void ptree_add_entry(char *str, int data, char *matchstr,
			    struct patricia_node **root);
extern void ptree_display(struct patricia_node *node, int level);
extern void ptree_free(struct patricia_node *root);

#endif /* PATRICIA_H */

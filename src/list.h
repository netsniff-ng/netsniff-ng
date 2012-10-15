/*
 * netsniff-ng - the packet sniffing beast
 * list.c - Doubly linked list implementation
 * Copyright (C) 2011 Jiri Pirko <jpirko@redhat.com>
 * Subject to the GPL, version 2.
 */

#ifndef LIST_H
#define LIST_H

#include <stdbool.h>

struct list_item {
	struct list_item *prev;
	struct list_item *next;
};

static inline void list_init(struct list_item *head)
{
	head->prev = head;
	head->next = head;
}

static inline bool list_empty(struct list_item *head)
{
	return head->next == head;
}

static inline void __list_add(struct list_item *new_node,
			      struct list_item *prev_node,
			      struct list_item *next_node)
{
	new_node->prev = prev_node;
	new_node->next = next_node;
	prev_node->next = new_node;
	next_node->prev = new_node;
}

static inline void list_add(struct list_item *head, struct list_item *node)
{
	__list_add(node, head, head->next);
}

static inline void list_add_tail(struct list_item *head, struct list_item *node)
{
	__list_add(node, head->prev, head);
}

static inline void list_del(struct list_item *node)
{
	node->prev->next = node->next;
	node->next->prev = node->prev;
}

static inline void list_move_nodes(struct list_item *dst_head,
				   struct list_item *src_head)
{
	if (list_empty(src_head))
		return;
	dst_head->prev->next = src_head->next;
	src_head->next->prev = dst_head->prev;
	dst_head->prev = src_head->prev;
	src_head->prev->next = dst_head;
	list_init(src_head);
}

static inline struct list_item *list_get_next_node(struct list_item *head,
						   struct list_item *node)
{
	if (node->next == head)
		return NULL;
	return node->next;
}

#define list_for_each_node(node, head)			\
	for (node = list_get_next_node(head, head);	\
	     node;					\
	     node = list_get_next_node(head, node))

#define in_struct_offset(struct_type, struct_member) \
	((size_t) (&((struct_type *) 0)->struct_member))

#define get_container(ptr, struct_type, struct_member)		\
	((struct_type *) (					\
		((size_t) ptr) -				\
		in_struct_offset(struct_type, struct_member)))

#define list_get_node_entry(node, struct_type, struct_member)		\
	get_container(node, struct_type, struct_member)

#define list_for_each_node_entry(entry, head, struct_member)			\
	for (entry = list_get_node_entry((head)->next, typeof(*entry),		\
					 struct_member);			\
	     &entry->struct_member != (head);					\
	     entry = list_get_node_entry(entry->struct_member.next,		\
					 typeof(*entry), struct_member))

#define list_for_each_node_entry_continue_reverse(entry, head, struct_member)	\
	for (entry = list_get_node_entry(entry->struct_member.prev,		\
					 typeof(*entry), struct_member);	\
	     &entry->struct_member != (head);					\
	     entry = list_get_node_entry(entry->struct_member.prev,		\
					 typeof(*entry), struct_member))

#define list_for_each_node_entry_safe(entry, tmp, head, struct_member)		\
	for (entry = list_get_node_entry((head)->next,				\
					 typeof(*entry), struct_member),	\
	     tmp = list_get_node_entry(entry->struct_member.next,		\
				       typeof(*entry), struct_member);		\
	     &entry->struct_member != (head);					\
	     entry = tmp,							\
	     tmp = list_get_node_entry(entry->struct_member.next,		\
				       typeof(*entry), struct_member))

#define list_get_next_node_entry(head, entry, struct_member) ({			\
	struct list_item *next = (entry ? &entry->struct_member : (head))->next;\
	(next == (head)) ? NULL : list_get_node_entry(next, typeof(*entry),	\
						      struct_member);})

#endif /* LIST_H */

#ifndef LIST_I_H
#define LIST_I_H

#include <urcu/list.h>
#include <urcu/rculist.h>

#define list_head	cds_list_head

#define LIST_HEAD	CDS_LIST_HEAD
#define INIT_LIST_HEAD	CDS_INIT_LIST_HEAD
#define LIST_HEAD_INIT	CDS_LIST_HEAD_INIT

#define list_add			cds_list_add
#define list_add_tail			cds_list_add_tail
#define list_del			cds_list_del
#define list_del_init			cds_list_del_init
#define list_move			cds_list_move
#define list_replace			cds_list_replace
#define list_splice			cds_list_splice
#define list_entry			cds_list_entry
#define list_first_entry		cds_list_first_entry
#define list_for_each			cds_list_for_each
#define list_for_each_safe		cds_list_for_each_safe
#define list_for_each_prev		cds_list_for_each_prev
#define list_for_each_prev_safe		cds_list_for_each_prev_safe
#define list_for_each_entry		cds_list_for_each_entry
#define list_for_each_entry_safe	cds_list_for_each_entry_safe
#define list_for_each_entry_reverse	cds_list_for_each_entry_reverse
#define list_empty			cds_list_empty
#define list_replace_init		cds_list_replace_init

#define list_add_rcu			cds_list_add_rcu
#define list_add_tail_rcu		cds_list_add_tail_rcu
#define list_replace_rcu		cds_list_replace_rcu
#define list_del_rcu			cds_list_del_rcu
#define list_for_each_rcu		cds_list_for_each_rcu
#define list_for_each_entry_rcu		cds_list_for_each_entry_rcu

#endif /* LIST_I_H */

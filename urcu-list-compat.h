#ifndef URCU_LIST_COMPAT_H
#define URCU_LIST_COMPAT_H

#include <urcu/list.h>

#ifndef cds_list_last_entry
#define cds_list_last_entry(ptr, type, member) \
	cds_list_entry((ptr)->prev, type, member)
#endif

#ifndef cds_list_next_entry
#define cds_list_next_entry(pos, member) \
	cds_list_entry((pos)->member.next, typeof(*(pos)), member)
#endif

#ifndef cds_list_prev_entry
#define cds_list_prev_entry(pos, member) \
	cds_list_entry((pos)->member.prev, typeof(*(pos)), member)
#endif

#endif /* URCU_LIST_COMPAT_H */

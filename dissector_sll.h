/*
 * netsniff-ng - the packet sniffing beast
 * Subject to the GPL, version 2.
 */

#ifndef DISSECTOR_SLL_H
#define DISSECTOR_SLL_H

#include "hash.h"
#include "proto.h"

extern void dissector_init_sll(int fnttype);
extern void dissector_cleanup_sll(void);

extern struct protocol *dissector_get_sll_entry_point(void);
extern struct protocol *dissector_get_sll_exit_point(void);

#endif /* DISSECTOR_SLL_H */

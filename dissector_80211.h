/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef DISSECTOR_80211_H
#define DISSECTOR_80211_H

#include "hash.h"
#include "proto.h"
#include "protos.h"
#include "tprintf.h"
#include "xutils.h"
#include "oui.h"

extern struct hash_table ieee80211_lay2;

extern void dissector_init_ieee80211(int fnttype);
extern void dissector_cleanup_ieee80211(void);

#ifdef __WITH_PROTOS
static inline struct protocol *dissector_get_ieee80211_entry_point(void)
{
	return &ieee80211_ops;
}

static inline struct protocol *dissector_get_ieee80211_exit_point(void)
{
	return &none_ops;
}
#else
static inline struct protocol *dissector_get_ieee80211_entry_point(void)
{
	return NULL;
}

static inline struct protocol *dissector_get_ieee80211_exit_point(void)
{
	return NULL;
}
#endif /* __WITH_PROTOS */
#endif /* DISSECTOR_80211_H */

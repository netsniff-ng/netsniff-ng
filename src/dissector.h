/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef DISSECTOR_H
#define DISSECTOR_H

#include <stdlib.h>
#include <stdint.h>

#define LINKTYPE_NULL       0	/* BSD loopback encapsulation */
#define LINKTYPE_EN10MB     1	/* Ethernet (10Mb) */
#define LINKTYPE_EN3MB      2	/* Experimental Ethernet (3Mb) */
#define LINKTYPE_AX25       3	/* Amateur Radio AX.25 */
#define LINKTYPE_PRONET     4	/* Proteon ProNET Token Ring */
#define LINKTYPE_CHAOS      5	/* Chaos */
#define LINKTYPE_IEEE802    6	/* 802.5 Token Ring */
#define LINKTYPE_ARCNET     7	/* ARCNET, with BSD-style header */
#define LINKTYPE_SLIP       8	/* Serial Line IP */
#define LINKTYPE_PPP        9	/* Point-to-point Protocol */
#define LINKTYPE_FDDI      10	/* FDDI */

#define FNTTYPE_PRINT_NORM  0	/* Normal printing */
#define FNTTYPE_PRINT_LESS  1	/* Less verbose printing */
#define FNTTYPE_PRINT_NONE  2	/* No printing at all */
#define FNTTYPE_PRINT_HEX1  3	/* Only payload as hex */
#define FNTTYPE_PRINT_HEX2  4	/* The whole packet as hex */
#define FNTTYPE_PRINT_CHR1  5	/* Only payload as char */
#define FNTTYPE_PRINT_NOPA  6	/* No payload at all, only header */
#define FNTTYPE_PRINT_PAAC  7	/* Payload as copy-and-paste C */

extern void dissector_init_all(int fnttype);
extern void dissector_entry_point(uint8_t *packet, size_t len, int linktype);
extern void dissector_cleanup_all(void);

extern int dissector_set_print_norm(void *ptr);
extern int dissector_set_print_less(void *ptr);
extern int dissector_set_print_none(void *ptr);
extern int dissector_set_print_payload(void *ptr);
extern int dissector_set_print_payload_hex(void *ptr);
extern int dissector_set_print_c_style(void *ptr);
extern int dissector_set_print_all_hex(void *ptr);
extern int dissector_set_print_no_payload(void *ptr);

#endif /* DISSECTOR_H */

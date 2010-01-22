#ifndef	__PRINT_VLAN_H__
#define	__PRINT_VLAN_H__

#include <stdint.h>
#include <assert.h>
#include <netsniff-ng/macros.h>
#include <netsniff-ng/protocols/l2/vlan.h>

/*
 * print_vlan - Just plain dumb formatting
 * @header:            Vlan header
 */

static inline void print_vlan(const struct vlan_hdr * header)
{
	info(" [ VLAN tag : %u ]", get_vlan_tag(header));
	info("\n");
}

#endif	/* __PRINT_VLAN_H__ */

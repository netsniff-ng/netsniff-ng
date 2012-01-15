/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#ifndef IPV4_H
#define IPV4_H

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */
#include <arpa/inet.h>     /* for inet_ntop() */
#include <asm/byteorder.h>

#include "csum.h"
#include "proto_struct.h"
#include "dissector_eth.h"

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

#define	FRAG_OFF_RESERVED_FLAG(x)      ((x) & 0x8000)
#define	FRAG_OFF_NO_FRAGMENT_FLAG(x)   ((x) & 0x4000)
#define	FRAG_OFF_MORE_FRAGMENT_FLAG(x) ((x) & 0x2000)
#define	FRAG_OFF_FRAGMENT_OFFSET(x)    ((x) & 0x1fff)

static inline void ipv4(uint8_t *packet, size_t len)
{
	uint16_t csum, frag_off;
	char src_ip[INET_ADDRSTRLEN];
	char dst_ip[INET_ADDRSTRLEN];
	struct ipv4hdr *ip = (struct ipv4hdr *) packet;

	if (len < sizeof(struct ipv4hdr))
		return;

	frag_off = ntohs(ip->h_frag_off);
	csum = calc_csum(ip, ip->h_ihl * 4, 0);

	inet_ntop(AF_INET, &ip->h_saddr, src_ip, sizeof(src_ip));
	inet_ntop(AF_INET, &ip->h_daddr, dst_ip, sizeof(dst_ip));

	tprintf(" [ IPv4 ");
	tprintf("Addr (%s => %s), ", src_ip, dst_ip);
	tprintf("Proto (%u), ", ip->h_protocol);
	tprintf("TTL (%u), ", ip->h_ttl);
	tprintf("TOS (%u), ", ip->h_tos);
	tprintf("Ver (%u), ", ip->h_version);
	tprintf("IHL (%u), ", ip->h_ihl);
	tprintf("Tlen (%u), ", ntohs(ip->h_tot_len));
	tprintf("ID (%u), ", ntohs(ip->h_id));
	tprintf("Res (%u), NoFrag (%u), MoreFrag (%u), FragOff (%u), ",
		FRAG_OFF_RESERVED_FLAG(frag_off) ? 1 : 0,
		FRAG_OFF_NO_FRAGMENT_FLAG(frag_off) ? 1 : 0,
		FRAG_OFF_MORE_FRAGMENT_FLAG(frag_off) ? 1 : 0,
		FRAG_OFF_FRAGMENT_OFFSET(frag_off));
	tprintf("CSum (0x%x) is %s", ntohs(ip->h_check), 
		csum ? colorize_start_full(black, red) "bogus (!)" 
		       colorize_end() : "ok");
	if (csum)
		tprintf("%s should be %x%s", colorize_start_full(black, red),
			csum_expected(ip->h_check, csum), colorize_end());
	tprintf(" ]\n");
}

static inline void ipv4_less(uint8_t *packet, size_t len)
{
	uint16_t csum, frag_off;
	char src_ip[INET_ADDRSTRLEN];
	char dst_ip[INET_ADDRSTRLEN];
	struct ipv4hdr *ip = (struct ipv4hdr *) packet;

	if (len < sizeof(struct ipv4hdr))
		return;

	frag_off = ntohs(ip->h_frag_off);
	csum = calc_csum(ip, ip->h_ihl * 4, 0);

	inet_ntop(AF_INET, &ip->h_saddr, src_ip, sizeof(src_ip));
	inet_ntop(AF_INET, &ip->h_daddr, dst_ip, sizeof(dst_ip));

	tprintf(" %s/%s Len %u", src_ip, dst_ip,
		ntohs(ip->h_tot_len));
}

static inline void ipv4_next(uint8_t *packet, size_t len,
			     struct hash_table **table,
			     unsigned int *key, size_t *off)
{
	struct ipv4hdr *ip = (struct ipv4hdr *) packet;

	if (len < sizeof(struct ipv4hdr))
		goto invalid;

	(*off) = sizeof(struct ipv4hdr);
	(*key) = ip->h_protocol;
	(*table) = &eth_lay3;

	return;
invalid:
	(*off) = 0;
	(*key) = 0;
	(*table) = NULL;
}

struct protocol ipv4_ops = {
	.key = 0x0800,
	.offset = sizeof(struct ipv4hdr),
	.print_full = ipv4,
	.print_less = ipv4_less,
	.print_pay_ascii = empty,
	.print_pay_hex = empty,
	.print_pay_none = ipv4,
	.print_all_cstyle = __hex2,
	.print_all_hex = __hex,
	.proto_next = ipv4_next,
};

#endif /* IPV4_H */

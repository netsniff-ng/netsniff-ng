/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>.
 * Copyright (C) 2009, 2010 Daniel Borkmann
 * Copyright (C) 2012 Christoph Jaeger <christoph@netsniff-ng.org>
 * Subject to the GPL, version 2.
 */

#ifndef IPV4_H
#define IPV4_H

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */
#include <arpa/inet.h>     /* for inet_ntop() */
#include <asm/byteorder.h>
#include <assert.h>

#include "csum.h"
#include "proto_struct.h"
#include "dissector_eth.h"
#include "pkt_buff.h"

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
	uint8_t h_opts[0];
} __attribute__((packed));

#define	FRAG_OFF_RESERVED_FLAG(x)      ((x) & 0x8000)
#define	FRAG_OFF_NO_FRAGMENT_FLAG(x)   ((x) & 0x4000)
#define	FRAG_OFF_MORE_FRAGMENT_FLAG(x) ((x) & 0x2000)
#define	FRAG_OFF_FRAGMENT_OFFSET(x)    ((x) & 0x1fff)

static inline void ipv4(struct pkt_buff *pkt)
{
	uint16_t csum, frag_off;
	char src_ip[INET_ADDRSTRLEN];
	char dst_ip[INET_ADDRSTRLEN];
	struct ipv4hdr *ip = (struct ipv4hdr *) pkt_pull_head(pkt, sizeof(*ip));
	uint8_t *opts;
	size_t opts_len;

	if (ip == NULL)
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

	/* TODO: do/print something more usefull (dissect options, ...) */
	opts_len = ip->h_ihl * 4 - 20;

	assert(opts_len <= 40);
	opts = (uint8_t *) pkt_pull_head(pkt, opts_len);

	if (opts_len && opts) {
		tprintf("   [ Options hex ");
		for (; opts_len-- > 0; opts++)
		       tprintf("%.2x ", *opts);
		tprintf("]\n");
	}

	/*
	 * Cut off everything that is not part of IPv4 payload (ethernet
	 * trailer, padding... whatever).
	 */
	pkt_pull_tail(pkt, pkt_len(pkt) + ip->h_ihl * 4 - ntohs(ip->h_tot_len));
	pkt_set_proto(pkt, &eth_lay3, ip->h_protocol);
}

static inline void ipv4_less(struct pkt_buff *pkt)
{
	char src_ip[INET_ADDRSTRLEN];
	char dst_ip[INET_ADDRSTRLEN];
	struct ipv4hdr *ip = (struct ipv4hdr *) pkt_pull_head(pkt, sizeof(*ip));

	if (ip == NULL)
		return;

	inet_ntop(AF_INET, &ip->h_saddr, src_ip, sizeof(src_ip));
	inet_ntop(AF_INET, &ip->h_daddr, dst_ip, sizeof(dst_ip));

	tprintf(" %s/%s Len %u", src_ip, dst_ip,
		ntohs(ip->h_tot_len));

	/*
	 * Cut off everything that is not part of IPv4 payload (IPv4 options,
	 * ethernet trailer, padding... whatever).
	 */
	pkt_pull_head(pkt, ip->h_ihl * 4 - 20);
	pkt_pull_tail(pkt, pkt_len(pkt) + ip->h_ihl * 4 - ntohs(ip->h_tot_len));
	pkt_set_proto(pkt, &eth_lay3, ip->h_protocol);
}

struct protocol ipv4_ops = {
	.key = 0x0800,
	.print_full = ipv4,
	.print_less = ipv4_less,
};

#endif /* IPV4_H */

/*
 * netsniff-ng - the packet sniffing beast
 * Copyright (C) 2009, 2010 Daniel Borkmann
 * Copyright (C) 2012 Christoph Jaeger <christoph@netsniff-ng.org>
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */
#include <arpa/inet.h>     /* for inet_ntop() */

#include "proto.h"
#include "protos.h"
#include "csum.h"
#include "dissector_eth.h"
#include "ipv4.h"
#include "geoip.h"
#include "pkt_buff.h"
#include "built_in.h"

#define FRAG_OFF_RESERVED_FLAG(x)      ((x) & 0x8000)
#define FRAG_OFF_NO_FRAGMENT_FLAG(x)   ((x) & 0x4000)
#define FRAG_OFF_MORE_FRAGMENT_FLAG(x) ((x) & 0x2000)
#define FRAG_OFF_FRAGMENT_OFFSET(x)    ((x) & 0x1fff)

/* IP Option Numbers (http://www.iana.org/assignments/ip-parameters) */
#define IP_OPT_EOOL 0x00
#define IP_OPT_NOP  0x01

#define IP_OPT_COPIED_FLAG(x)  ((x) & 0x80)
#define IP_OPT_CLASS(x)       (((x) & 0x60) >> 5)
#define IP_OPT_NUMBER(x)       ((x) & 0x1F)

static void ipv4(struct pkt_buff *pkt)
{
	uint16_t csum, frag_off, h_tot_len;
	char src_ip[INET_ADDRSTRLEN];
	char dst_ip[INET_ADDRSTRLEN];
	struct ipv4hdr *ip = (struct ipv4hdr *) pkt_pull(pkt, sizeof(*ip));
	uint8_t *opt, *trailer;
	unsigned int trailer_len = 0;
	ssize_t opts_len, opt_len;
	struct sockaddr_in sas, sad;
	const char *city, *region, *country;

	if (!ip)
		return;

	frag_off = ntohs(ip->h_frag_off);
	h_tot_len = ntohs(ip->h_tot_len);
	csum = calc_csum(ip, ip->h_ihl * 4, 0);

	inet_ntop(AF_INET, &ip->h_saddr, src_ip, sizeof(src_ip));
	inet_ntop(AF_INET, &ip->h_daddr, dst_ip, sizeof(dst_ip));

	if ((pkt_len(pkt) + sizeof(*ip)) > h_tot_len) {
		trailer_len = pkt_len(pkt) + sizeof(*ip) - h_tot_len;
		trailer = pkt->data + h_tot_len + trailer_len;
	}

	if (trailer_len) {
		 tprintf(" [ Eth trailer ");
		 while (trailer_len--) {
			tprintf("%x", *(trailer - trailer_len));
		 }
		 tprintf(" ]\n");
	}

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
	tprintf("CSum (0x%.4x) is %s", ntohs(ip->h_check),
		csum ? colorize_start_full(black, red) "bogus (!)"
		       colorize_end() : "ok");
	if (csum)
		tprintf("%s should be 0x%.4x%s", colorize_start_full(black, red),
			csum_expected(ip->h_check, csum), colorize_end());
	tprintf(" ]\n");

	memset(&sas, 0, sizeof(sas));
	sas.sin_family = PF_INET;
	sas.sin_addr.s_addr = ip->h_saddr;

	memset(&sad, 0, sizeof(sad));
	sad.sin_family = PF_INET;
	sad.sin_addr.s_addr = ip->h_daddr;

	if (geoip_working()) {
		tprintf("\t[ Geo (");
		if ((country = geoip4_country_name(sas))) {
			tprintf("%s", country);
			if ((region = geoip4_region_name(sas)))
				tprintf(" / %s", region);
			if ((city = geoip4_city_name(sas)))
				tprintf(" / %s", city);
		} else {
			tprintf("local");
		}
		tprintf(" => ");
		if ((country = geoip4_country_name(sad))) {
			tprintf("%s", country);
			if ((region = geoip4_region_name(sad)))
				tprintf(" / %s", region);
			if ((city = geoip4_city_name(sad)))
				tprintf(" / %s", city);
		} else {
			tprintf("local");
		}
		tprintf(") ]\n");
	}

	opts_len = max_t(uint8_t, ip->h_ihl, sizeof(*ip) / sizeof(uint32_t)) *
		   sizeof(uint32_t) - sizeof(*ip);

	for (opt = pkt_pull(pkt, opts_len); opt && opts_len > 0; opt++) {
		tprintf("   [ Option  Copied (%u), Class (%u), Number (%u)",
			IP_OPT_COPIED_FLAG(*opt) ? 1 : 0, IP_OPT_CLASS(*opt),
			IP_OPT_NUMBER(*opt));

		switch (*opt) {
		case IP_OPT_EOOL:
		case IP_OPT_NOP:
			tprintf(" ]\n");
			opts_len--;
			break;
		default:
			/*
			 * Assuming that EOOL and NOP are the only single-byte
			 * options, treat all other options as variable in
			 * length with a minimum of 2.
			 *
			 * TODO: option length might be incorrect in malformed packets,
			 *       check and handle that
			 */
			opt_len = *(++opt);
			if (opt_len > opts_len) {
				tprintf(", Len (%zd, invalid) ]\n", opt_len);
				goto out;
			} else
				tprintf(", Len (%zd) ]\n", opt_len);
			opts_len -= opt_len;
			tprintf("     [ Data hex ");
			for (opt_len -= 2; opt_len > 0; opt_len--)
				tprintf(" %.2x", *(++opt));
			tprintf(" ]\n");
			break;
		}
	}
out:
	/* cut off everything that is not part of IPv4 payload */
	/* XXX there could still be an Ethernet trailer included or others */

	pkt_trim(pkt, pkt_len(pkt) - min(pkt_len(pkt),
		 (ntohs(ip->h_tot_len) - ip->h_ihl * sizeof(uint32_t))));

	pkt_set_proto(pkt, &eth_lay3, ip->h_protocol);
}

static void ipv4_less(struct pkt_buff *pkt)
{
	char src_ip[INET_ADDRSTRLEN];
	char dst_ip[INET_ADDRSTRLEN];
	struct ipv4hdr *ip = (struct ipv4hdr *) pkt_pull(pkt, sizeof(*ip));

	if (!ip)
		return;

	inet_ntop(AF_INET, &ip->h_saddr, src_ip, sizeof(src_ip));
	inet_ntop(AF_INET, &ip->h_daddr, dst_ip, sizeof(dst_ip));

	tprintf(" %s/%s Len %u", src_ip, dst_ip,
		ntohs(ip->h_tot_len));

	/* cut off IP options and everything that is not part of IPv4 payload */
	pkt_pull(pkt, max_t(uint8_t, ip->h_ihl, sizeof(*ip) / sizeof(uint32_t))
		* sizeof(uint32_t) - sizeof(*ip));
	/* XXX there coul still be an Ethernet trailer included or others */
#if 0
	pkt_trim(pkt, pkt_len(pkt) - min(pkt_len(pkt),
		 (ntohs(ip->h_tot_len) - ip->h_ihl * sizeof(uint32_t))));
#endif
	pkt_set_proto(pkt, &eth_lay3, ip->h_protocol);
}

struct protocol ipv4_ops = {
	.key = 0x0800,
	.print_full = ipv4,
	.print_less = ipv4_less,
};

#ifndef	__PRINT_IP_H__
#define	__PRINT_IP_H__

#include <stdint.h>
#include <assert.h>
#include <netsniff-ng/macros.h>
#include <netsniff-ng/protocols/l3/ip.h>

/*
 * print_iphdr - Just plain dumb formatting
 * @ip:            ip header
 */

void print_iphdr(struct iphdr *ip)
{
	/* XXX Version check */
	assert(ip);
	char src_ip[INET_ADDRSTRLEN] = { 0 };
	char dst_ip[INET_ADDRSTRLEN] = { 0 };
	
	uint16_t printable_frag_off;

	inet_ntop(AF_INET, &ip->saddr, src_ip, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ip->daddr, dst_ip, INET_ADDRSTRLEN);
	printable_frag_off = ntohs(ip->frag_off);

	info(" [ IPv4 ");
	info("Addr (%s => %s), ", src_ip, dst_ip);
	info("Proto (%u), ", ip->protocol);
	info("TTL (%u), ", ip->ttl);
	info("TOS (%u), ", ip->tos);
	info("Ver (%u), ", ip->version);
	info("IHL (%u), ", ntohs(ip->ihl));
	info("Tlen (%u), ", ntohs(ip->tot_len));
	info("ID (%u), \n", ntohs(ip->id));
	info("Res: %u NoFrag: %u MoreFrag: %u offset (%u), ", FRAG_OFF_RESERVED_FLAG(printable_frag_off) ? 1 : 0,
	     FRAG_OFF_NO_FRAGMENT_FLAG(printable_frag_off) ? 1 : 0, FRAG_OFF_MORE_FRAGMENT_FLAG(printable_frag_off) ? 1 : 0, FRAG_OFF_FRAGMENT_OFFSET(printable_frag_off));
	info("Chsum (0x%x) is %s", ntohs(ip->check), is_csum_correct(ip->check, ip) ? "correct" : "incorrect");

	info(" ] \n");
}

#endif	/* __PRINT_IP_H__ */

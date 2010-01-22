#ifndef	__PRINT_ETHERNET_H__
#define	__PRINT_ETHERNET_H__

#include <stdint.h>
#include <assert.h>
#include <netsniff-ng/macros.h>
#include <netsniff-ng/protocols/l2/ethernet.h>

/*
 * print_ethhdr - Just plain dumb formatting
 * @eth:            ethernet header
 */
static inline void print_ethhdr(struct ethhdr *eth)
{
	uint8_t *src_mac = eth->h_source;
	uint8_t *dst_mac = eth->h_dest;

	assert(eth);

	info(" [ ");

	info("MAC (%.2x:%.2x:%.2x:%.2x:%.2x:%.2x => %.2x:%.2x:%.2x:%.2x:%.2x:%.2x), ", src_mac[0], src_mac[1],
	     src_mac[2], src_mac[3], src_mac[4], src_mac[5], dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4],
	     dst_mac[5]);

	info("Proto (0x%.4x)", ntohs(eth->h_proto));

	info(" ] \n");
}

#endif	/* __PRINT_ETHERNET_H__ */

#ifndef	__PRINT_UDP_H__
#define	__PRINT_UDP_H__

#include <stdint.h>
#include <assert.h>
#include <netsniff-ng/macros.h>
#include <netsniff-ng/protocols/l4/udp.h>

/*
 * dump_udphdr_all - Just plain dumb formatting
 * @udp:            udp header
 */
void print_udphdr(struct udphdr *udp)
{
	info(" [ UDP ");

	info("Port (%u => %u), ", ntohs(udp->source), ntohs(udp->dest));
	info("Len (%u), ", ntohs(udp->len));
	info("Chsum (0x%x)", ntohs(udp->check));

	info(" ] \n");
}

#endif	/* __PRINT_UDP_H__ */

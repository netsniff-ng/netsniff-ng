#ifndef	__PRINT_TCP_H__
#define	__PRINT_TCP_H__

#include <stdint.h>
#include <assert.h>
#include <netsniff-ng/macros.h>
#include <netsniff-ng/protocols/l4/tcp.h>

/*
 * dump_tcphdr_all - Just plain dumb formatting
 * @tcp:            tcp header
 */
static void inline print_tcphdr(struct tcphdr *tcp)
{
	assert(tcp);

	info(" [ TCP ");

	info("Port (%u => %u), ", ntohs(tcp->source), ntohs(tcp->dest));
	info("SN (0x%x), ", ntohs(tcp->seq));
	info("AN (0x%x), ", ntohs(tcp->ack_seq));
	info("Data off (%d), ", ntohs(tcp->doff));
	info("Res 1 (%d), ", ntohs(tcp->res1));

	info("Flags (");

	if (tcp->urg == 1) {
		info("URG ");
	}
	if (tcp->ack == 1) {
		info("ACK ");
	}
	if (tcp->psh == 1) {
		info("PSH ");
	}
	if (tcp->rst == 1) {
		info("RST ");
	}
	if (tcp->syn == 1) {
		info("SYN ");
	}
	if (tcp->fin == 1) {
		info("FIN ");
	}
	if (tcp->ece == 1) {
		info("ECE ");
	}
	if (tcp->cwr == 1) {
		info("CWR ");
	}

	info("), ");

	info("Window (%d), ", ntohs(tcp->window));
	info("Hdrsum (0x%x), ", ntohs(tcp->check));
	info("Urg ptr (%u)", ntohs(tcp->urg_ptr));

	info(" ] \n");

	/* TODO check csum */
}

#endif	/* __PRINT_TCP_H__ */

/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010 Daniel Borkmann.
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <stdint.h>
#include <endian.h>
#include <netinet/in.h>    /* for ntohs() */
#include <asm/byteorder.h>

#include "proto.h"
#include "protos.h"
#include "lookup.h"
#include "built_in.h"
#include "pkt_buff.h"

struct tcphdr {
	uint16_t source;
	uint16_t dest;
	uint32_t seq;
	uint32_t ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__extension__ uint16_t res1:4,
			       doff:4,
			       fin:1,
			       syn:1,
			       rst:1,
			       psh:1,
			       ack:1,
			       urg:1,
			       ece:1,
			       cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__extension__ uint16_t doff:4,
			       res1:4,
			       cwr:1,
			       ece:1,
			       urg:1,
			       ack:1,
			       psh:1,
			       rst:1,
			       syn:1,
			       fin:1;
#else
# error  "Adjust your <asm/byteorder.h> defines"
#endif
	uint16_t window;
	uint16_t check;
	uint16_t urg_ptr;
} __packed;

#define tprintf_flag(flag, str, prev)	({		\
	bool __r = false;					\
	if (flag) {					\
		tprintf("%s%s", (prev) ? " " : "", str);	\
		__r = true;					\
	}							\
	__r;							\
})

static void tcp(struct pkt_buff *pkt)
{
	struct tcphdr *tcp = (struct tcphdr *) pkt_pull(pkt, sizeof(*tcp));
	uint16_t src, dest;
	const char *src_name, *dest_name;
	bool v = false;

	if (tcp == NULL)
		return;

	src = ntohs(tcp->source);
	dest = ntohs(tcp->dest);

	src_name = lookup_port_tcp(src);
	dest_name = lookup_port_tcp(dest);

	tprintf(" [ TCP ");
	tprintf("Port (%u", src);
	if (src_name)
		tprintf(" (%s%s%s)", colorize_start(bold), src_name,
			colorize_end());
	tprintf(" => %u", dest);
	if (dest_name)
		tprintf(" (%s%s%s)", colorize_start(bold), dest_name,
			colorize_end());
	tprintf("), ");
	tprintf("SN (0x%x), ", ntohl(tcp->seq));
	tprintf("AN (0x%x), ", ntohl(tcp->ack_seq));
	tprintf("DataOff (%u), ", tcp->doff);
	tprintf("Res (%u), ", tcp->res1);
	tprintf("Flags (");
	v = tprintf_flag(tcp->fin, "FIN", v);
	v = tprintf_flag(tcp->syn, "SYN", v);
	v = tprintf_flag(tcp->rst, "RST", v);
	v = tprintf_flag(tcp->psh, "PSH", v);
	v = tprintf_flag(tcp->ack, "ACK", v);
	v = tprintf_flag(tcp->urg, "URG", v);
	v = tprintf_flag(tcp->ece, "ECE", v);
	v = tprintf_flag(tcp->cwr, "CWR", v);
	tprintf("), ");
	tprintf("Window (%u), ", ntohs(tcp->window));
	tprintf("CSum (0x%.4x), ", ntohs(tcp->check));
	tprintf("UrgPtr (%u)", ntohs(tcp->urg_ptr));
	tprintf(" ]\n");
}

static void tcp_less(struct pkt_buff *pkt)
{
	struct tcphdr *tcp = (struct tcphdr *) pkt_pull(pkt, sizeof(*tcp));
	uint16_t src, dest;
	const char *src_name, *dest_name;

	if (tcp == NULL)
		return;

	src = ntohs(tcp->source);
	dest = ntohs(tcp->dest);

	src_name = lookup_port_tcp(src);
	dest_name = lookup_port_tcp(dest);

	tprintf(" TCP %u", src);
	if(src_name)
		tprintf("(%s%s%s)", colorize_start(bold), src_name,
			colorize_end());
	tprintf("/%u", dest);
	if(dest_name)
		tprintf("(%s%s%s)", colorize_start(bold), dest_name,
			colorize_end());
	tprintf(" F%s",colorize_start(bold));
	if (tcp->fin)
		tprintf(" FIN");
	if (tcp->syn)
		tprintf(" SYN");
	if (tcp->rst)
		tprintf(" RST");
	if (tcp->psh)
		tprintf(" PSH");
	if (tcp->ack)
		tprintf(" ACK");
	if (tcp->urg)
		tprintf(" URG");
	if (tcp->ece)
		tprintf(" ECE");
	if (tcp->cwr)
		tprintf(" CWR");
	tprintf("%s Win %u S/A 0x%x/0x%x", colorize_end(),
		ntohs(tcp->window), ntohl(tcp->seq), ntohl(tcp->ack_seq));
}

struct protocol tcp_ops = {
	.key = 0x06,
	.print_full = tcp,
	.print_less = tcp_less,
};

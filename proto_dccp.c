/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2009, 2010 Daniel Borkmann.
 * Copyright 2018 Markus Amend
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>    /* for ntohs() */

#include "proto.h"
#include "protos.h"
#include "pkt_buff.h"

struct dccphdr {
	uint16_t source;
	uint16_t dest;
	uint8_t data_offs;
	uint8_t cc_cscov;
	uint16_t checks;
#if defined(__LITTLE_ENDIAN_BITFIELD)
        __extension__ uint32_t x:1,
                               type:4,
                               res:3,
                               sqnr:24;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__extension__ uint32_t res:3,
			       type:4,
			       x:1,
			       sqnr:24;
#else
# error "Please fix <asm/byteorder.h>"
#endif

} __packed;

struct dccpexthdr {
        uint32_t seqnr_low;
} __packed;

struct ack_subhdr {
        uint32_t res:8,
		 acknr_low: 24;
} __packed;

struct ack_extsubhdr {
        uint16_t res;
	uint16_t acknr_high;
	uint32_t acknr_low;
} __packed;

static char* dccp_pkt_type(uint8_t type) {
	switch(type) {
	case 0: return "Request";
	case 1: return "Response";
	case 2: return "Data";
	case 3: return "Ack";
	case 4: return "DataAck";
	case 5: return "CloseReq";
	case 6: return "Close";
	case 7: return "Reset";
	case 8: return "Sync";
	case 9: return "SyncAck";
	case 10 ... 15: return "Reserved";
	}
	return "Undef";
}

static void dccp(struct pkt_buff *pkt)
{
	struct dccphdr *dccp = (struct dccphdr *) pkt_pull(pkt, sizeof(*dccp));
	struct dccpexthdr *dccpext = NULL;
	struct ack_subhdr *ack = NULL;
	struct ack_extsubhdr *ackext = NULL;
	uint16_t src, dest;
	uint64_t seqnr;
	int64_t acknr = -1;
	size_t used_hdr = 0;

	if (dccp == NULL)
		return;

	used_hdr += sizeof(*dccp);

	seqnr = (uint64_t) ntohl(dccp->sqnr);

	/* check for extended sequence number */
	if (dccp->x) {
		dccpext = (struct dccpexthdr *) pkt_pull(pkt, sizeof(*dccpext));
		if (dccpext == NULL)
			return;

		used_hdr += sizeof(*dccpext);
		seqnr = (((uint64_t) seqnr)<<24) | ntohl(dccpext->seqnr_low);
	}

	/* check for ack header */
	if (dccp->type == 1 || (dccp->type >= 2 && dccp->type <= 9)) {
		if (dccp->x) {
			/* Extended ack header */
			ackext = (struct ack_extsubhdr *) pkt_pull(pkt, sizeof(*ackext));
			if (ackext == NULL)
	                        return;

			used_hdr += sizeof(*ackext);
			acknr = (((uint64_t) ntohs(ackext->acknr_high))<<32) |
				ntohl(ackext->acknr_low);
		} else {
			/* standard ack header */
			ack = (struct ack_subhdr *) pkt_pull(pkt, sizeof(*ack));
                        if (ack == NULL)
                                return;

			used_hdr += sizeof(*ack);
			acknr = ntohl((uint32_t) ack->acknr_low);
		}
	}

	src = ntohs(dccp->source);
	dest = ntohs(dccp->dest);

	tprintf(" [ DCCP ");
	tprintf("Port (%u", src);
	tprintf(" => %u", dest);
	tprintf("), ");
	tprintf("Header Len (%u Bytes), ", dccp->data_offs * 4);
	tprintf("Type: %s, ", dccp_pkt_type((uint8_t) dccp->type));
	tprintf("Seqnr:%lu", seqnr);
	if (acknr > 0)
		tprintf(", AckNr:%lu", acknr);
	tprintf(" ]\n");
}

static void dccp_less(struct pkt_buff *pkt)
{
	struct dccphdr *dccp = (struct dccphdr *) pkt_pull(pkt, sizeof(*dccp));
	uint16_t src, dest;

	if (dccp == NULL)
		return;

	src = ntohs(dccp->source);
	dest = ntohs(dccp->dest);

	tprintf(" DCCP %u", src);
	tprintf("/%u", dest);
}

struct protocol dccp_ops = {
	.key = 0x21,
	.print_full = dccp,
	.print_less = dccp_less,
};

/*
 * netsniff-ng - the packet sniffing beast
 * Subject to the GPL, version 2.
 */

#include <arpa/inet.h>

#include "protos.h"
#include "pcap_io.h"
#include "pkt_buff.h"
#include "dissector.h"
#include "dissector_sll.h"
#include "dissector_eth.h"
#include "dissector_netlink.h"
#include "lookup.h"

static char *pkt_type2str(uint8_t pkttype)
{
	switch (pkttype) {
	case PACKET_HOST:
		return "host";
	case PACKET_BROADCAST:
		return "broadcast";
	case PACKET_MULTICAST:
		return "multicast";
	case PACKET_OTHERHOST:
		return "other host";
	case PACKET_OUTGOING:
		return "outgoing";
	case PACKET_USER:
		return "user";
	case PACKET_KERNEL:
		return "kernel";
	}

	return "Unknown";
}

static void sll_print_full(struct pkt_buff *pkt)
{
	struct sockaddr_ll *sll = pkt->sll;
	char addr_str[40] = {};

	tprintf(" [ Linux \"cooked\"");
	tprintf(" Pkt Type %d (%s)", sll->sll_pkttype,
		pkt_type2str(sll->sll_pkttype));
	tprintf(", If Type %d (%s)", sll->sll_hatype,
		device_type2str(sll->sll_hatype));
	tprintf(", Addr Len %d", sll->sll_halen);
	tprintf(", Src (%s)", device_addr2str(sll->sll_addr, sll->sll_halen,
		sll->sll_hatype, addr_str, sizeof(addr_str)));
	tprintf(", Proto 0x%x", ntohs(sll->sll_protocol));
	tprintf(" ]\n");

	switch (pcap_devtype_to_linktype(sll->sll_hatype)) {
	case LINKTYPE_EN10MB:
	case ___constant_swab32(LINKTYPE_EN10MB):
		pkt_set_dissector(pkt, &eth_lay2, ntohs(sll->sll_protocol));
		break;
	case LINKTYPE_NETLINK:
	case ___constant_swab32(LINKTYPE_NETLINK):
		pkt->dissector = dissector_get_netlink_entry_point();
		break;
	default:
		tprintf(" [ Unknown protocol ]\n");
	}
}

static void sll_print_less(struct pkt_buff *pkt)
{
	struct sockaddr_ll *sll = pkt->sll;
	char addr_str[40] = {};

	tprintf(" Pkt Type %d (%s)", sll->sll_pkttype,
		pkt_type2str(sll->sll_pkttype));
	tprintf(", If Type %d (%s)", sll->sll_hatype,
		device_type2str(sll->sll_hatype));
	tprintf(", Addr Len %d", sll->sll_halen);
	tprintf(", Src (%s)", device_addr2str(sll->sll_addr, sll->sll_halen,
		sll->sll_hatype, addr_str, sizeof(addr_str)));
	tprintf(", Proto 0x%x", ntohs(sll->sll_protocol));
}

struct protocol sll_ops = {
	.key = 0,
	.print_full = sll_print_full,
	.print_less = sll_print_less,
};

struct protocol *dissector_get_sll_entry_point(void)
{
	return &sll_ops;
}

struct protocol *dissector_get_sll_exit_point(void)
{
	return &none_ops;
}

void dissector_init_sll(int fnttype)
{
	dissector_set_print_type(&sll_ops, fnttype);
	dissector_set_print_type(&none_ops, fnttype);
	lookup_init(LT_OUI);
}

void dissector_cleanup_sll(void)
{
	lookup_cleanup(LT_OUI);
}

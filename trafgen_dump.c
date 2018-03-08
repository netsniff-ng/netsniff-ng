/*
 * netsniff-ng - the packet sniffing beast
 * Subject to the GPL, version 2.
 */

#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include "trafgen_l2.h"
#include "trafgen_l3.h"
#include "trafgen_l4.h"
#include "trafgen_proto.h"
#include "trafgen_dump.h"

#define DUMP(fmt, ...) fprintf((ctx)->file, fmt, ##__VA_ARGS__)

#define PKT_START() DUMP("{\n")
#define PKT_END() DUMP("}\n")

#define HDR_START(h) DUMP("  %s(", h)
#define HDR_END(h) DUMP("  ),\n")

#define FIELD_START(fmt, ...) DUMP(fmt",\n", ##__VA_ARGS__)
#define FIELD_END(fmt, ...) DUMP("    "fmt"\n", ##__VA_ARGS__)
#define FIELD(fmt, ...) DUMP("    "fmt",\n", ##__VA_ARGS__)

struct dump_ctx {
	FILE *file;
};

static int proto_dump_eth(struct dump_ctx *ctx, struct proto_hdr *hdr)
{
	uint8_t *mac;

	HDR_START("eth");

	mac = proto_hdr_field_get_bytes(hdr, ETH_DST_ADDR);
	FIELD_START("da=%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	mac = proto_hdr_field_get_bytes(hdr, ETH_SRC_ADDR);
	FIELD("sa=%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	FIELD_END("type=0x%x", proto_hdr_field_get_u16(hdr, ETH_TYPE));

	HDR_END();
	return 0;
}

static int proto_dump_vlan(struct dump_ctx *ctx, struct proto_hdr *hdr)
{
	HDR_START("vlan");

	FIELD_START("id=%d", proto_hdr_field_get_u16(hdr, VLAN_VID));
	FIELD("pcp=%d", proto_hdr_field_get_u16(hdr, VLAN_PCP));
	FIELD("dei=%d", proto_hdr_field_get_u16(hdr, VLAN_DEI));
	FIELD_END("tpid=0x%x", proto_hdr_field_get_u16(hdr, VLAN_TPID));

	HDR_END();
	return 0;
}

static int proto_dump_arp(struct dump_ctx *ctx, struct proto_hdr *hdr)
{
	char ip_str[INET_ADDRSTRLEN];
	uint16_t oper;
	uint8_t *mac;
	uint32_t ip;

	HDR_START("arp");

	mac = proto_hdr_field_get_bytes(hdr, ARP_SHA);
	FIELD_START("smac=%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	ip = proto_hdr_field_get_be32(hdr, ARP_SPA);
	inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));
	FIELD("sip=%s", ip_str);

	mac = proto_hdr_field_get_bytes(hdr, ARP_THA);
	FIELD("tmac=%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	ip = proto_hdr_field_get_be32(hdr, ARP_TPA);
	inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));
	FIELD("tip=%s", ip_str);

	oper = proto_hdr_field_get_u16(hdr, ARP_OPER);

	if (oper == ARPOP_REQUEST)
		FIELD_END("op=request");
	else if (oper == ARPOP_REPLY)
		FIELD_END("op=reply");
	else
		FIELD_END("op=0x%x", oper);

	HDR_END();
	return 0;
}

static int proto_dump_ip4(struct dump_ctx *ctx, struct proto_hdr *hdr)
{
	char ip_sa_str[INET_ADDRSTRLEN];
	char ip_da_str[INET_ADDRSTRLEN];
	uint32_t ip;

	ip = proto_hdr_field_get_be32(hdr, IP4_SADDR);
	inet_ntop(AF_INET, &ip, ip_sa_str, sizeof(ip_sa_str));

	ip = proto_hdr_field_get_be32(hdr, IP4_DADDR);
	inet_ntop(AF_INET, &ip, ip_da_str, sizeof(ip_da_str));

	HDR_START("ip4");

	FIELD_START("ver=0x%x", proto_hdr_field_get_u8(hdr, IP4_VER));
	FIELD("ihl=0x%x", proto_hdr_field_get_u8(hdr, IP4_IHL));
	FIELD("dscp=0x%x", proto_hdr_field_get_u8(hdr, IP4_DSCP));
	FIELD("ecn=0x%x", proto_hdr_field_get_u8(hdr, IP4_ECN));
	FIELD("tos=0x%x", proto_hdr_field_get_u8(hdr, IP4_TOS));
	FIELD("len=%d", proto_hdr_field_get_u16(hdr, IP4_LEN));
	FIELD("id=0x%x", proto_hdr_field_get_u16(hdr, IP4_ID));
	FIELD("flags=0x%x", proto_hdr_field_get_u16(hdr, IP4_FLAGS));
	if (proto_hdr_field_get_u16(hdr, IP4_MF))
		FIELD("mf");
	if (proto_hdr_field_get_u16(hdr, IP4_DF))
		FIELD("df");
	FIELD("frag=0x%x", proto_hdr_field_get_u16(hdr, IP4_FRAG_OFFS));
	FIELD("ttl=%d", proto_hdr_field_get_u8(hdr, IP4_TTL));
	FIELD("proto=0x%x", proto_hdr_field_get_u8(hdr, IP4_PROTO));
	FIELD("csum=0x%x", proto_hdr_field_get_u16(hdr, IP4_CSUM));
	FIELD("sa=%s", ip_sa_str);
	FIELD_END("da=%s", ip_da_str);

	HDR_END();
	return 0;
}

static int proto_dump_ip6(struct dump_ctx *ctx, struct proto_hdr *hdr)
{
	char ip_sa_str[INET6_ADDRSTRLEN];
	char ip_da_str[INET6_ADDRSTRLEN];
	uint8_t *ip;

	ip = proto_hdr_field_get_bytes(hdr, IP6_SADDR);
	inet_ntop(AF_INET6, ip, ip_sa_str, sizeof(ip_sa_str));

	ip = proto_hdr_field_get_bytes(hdr, IP6_DADDR);
	inet_ntop(AF_INET6, ip, ip_da_str, sizeof(ip_da_str));

	HDR_START("ip6");

	FIELD_START("ver=0x%x", proto_hdr_field_get_u32(hdr, IP6_VER));
	FIELD("tc=0x%x", proto_hdr_field_get_u32(hdr, IP6_CLASS));
	FIELD("fl=0x%x", proto_hdr_field_get_u32(hdr, IP6_FLOW_LBL));
	FIELD("len=%d", proto_hdr_field_get_u16(hdr, IP6_LEN));
	FIELD("nh=0x%x", proto_hdr_field_get_u8(hdr, IP6_NEXT_HDR));
	FIELD("hl=%d", proto_hdr_field_get_u8(hdr, IP6_HOP_LIMIT));
	FIELD("sa=%s", ip_sa_str);
	FIELD_END("da=%s", ip_da_str);

	HDR_END();
	return 0;
}

static int proto_dump_udp(struct dump_ctx *ctx, struct proto_hdr *hdr)
{
	HDR_START("udp");

	FIELD_START("dp=%d", proto_hdr_field_get_u16(hdr, UDP_SPORT));
	FIELD("sp=%d", proto_hdr_field_get_u16(hdr, UDP_DPORT));
	FIELD("len=%d", proto_hdr_field_get_u16(hdr, UDP_LEN));
	FIELD_END("csum=0x%x", proto_hdr_field_get_u16(hdr, UDP_CSUM));

	HDR_END();
	return 0;
}

static int proto_dump_tcp(struct dump_ctx *ctx, struct proto_hdr *hdr)
{
	HDR_START("tcp");

	FIELD_START("dp=%d", proto_hdr_field_get_u16(hdr, TCP_SPORT));
	FIELD("sp=%d", proto_hdr_field_get_u16(hdr, TCP_DPORT));
	FIELD("seq=0x%x", proto_hdr_field_get_u32(hdr, TCP_SEQ));
	FIELD("ackseq=0x%x", proto_hdr_field_get_u32(hdr, TCP_ACK_SEQ));
	FIELD("hlen=%d", proto_hdr_field_get_u16(hdr, TCP_DOFF));
	if (proto_hdr_field_get_u16(hdr, TCP_CWR))
		FIELD("cwr");
	if (proto_hdr_field_get_u16(hdr, TCP_ECE))
		FIELD("ecn");
	if (proto_hdr_field_get_u16(hdr, TCP_URG))
		FIELD("urg");
	if (proto_hdr_field_get_u16(hdr, TCP_ACK))
		FIELD("ack");
	if (proto_hdr_field_get_u16(hdr, TCP_PSH))
		FIELD("psh");
	if (proto_hdr_field_get_u16(hdr, TCP_RST))
		FIELD("rst");
	if (proto_hdr_field_get_u16(hdr, TCP_SYN))
		FIELD("syn");
	if (proto_hdr_field_get_u16(hdr, TCP_FIN))
		FIELD("fin");
	FIELD("win=%d", proto_hdr_field_get_u16(hdr, TCP_WINDOW));
	FIELD("csum=0x%x", proto_hdr_field_get_u16(hdr, TCP_CSUM));
	FIELD_END("urgptr=0x%x", proto_hdr_field_get_u16(hdr, TCP_URG_PTR));

	HDR_END();
	return 0;
}

static int proto_dump_hdr(struct dump_ctx *ctx, struct proto_hdr *hdr)
{
	switch (hdr->ops->id) {
	case PROTO_ETH:
		return proto_dump_eth(ctx, hdr);
	case PROTO_VLAN:
		return proto_dump_vlan(ctx, hdr);
	case PROTO_ARP:
		return proto_dump_arp(ctx, hdr);
	case PROTO_IP4:
		return proto_dump_ip4(ctx, hdr);
	case PROTO_IP6:
		return proto_dump_ip6(ctx, hdr);
	case PROTO_UDP:
		return proto_dump_udp(ctx, hdr);
	case PROTO_TCP:
		return proto_dump_tcp(ctx, hdr);
	default:
		return -1;
	}
}

int packet_dump_fd(struct packet *pkt, int fd)
{
	struct proto_hdr *hdr;
	enum proto_id pid;
	struct dump_ctx _ctx;
	struct dump_ctx *ctx = &_ctx;
	size_t dump_len = 0;
	uint32_t i;

	_ctx.file = fdopen(fd, "w");
	if (!_ctx.file)
		return -1;

	/* handle case if there is already proto headers */
	if (pkt->headers_count == 0) {
		hdr = proto_packet_apply(PROTO_ETH, pkt);

		while ((pid = proto_hdr_get_next_proto(hdr)) != __PROTO_MAX) {
			if (hdr->pkt_offset + hdr->len >= pkt->len)
				break;

			hdr = proto_packet_apply(pid, pkt);
		}
	}

	PKT_START();
	for (i = 0; i < pkt->headers_count; i++) {
		hdr = pkt->headers[i];

		if (proto_dump_hdr(ctx, hdr))
			break;

		dump_len += hdr->len;
	}

	/* print rest as a bytes */
	if (dump_len < pkt->len) {
		int j = 1;

		DUMP("  ");
		for (i = dump_len; i < pkt->len; ++i, ++j) {
			if (j % 15 == 0)
				DUMP("\n  ");
			DUMP("0x%02x,", pkt->payload[i]);
		}
		DUMP("\n");
	}
	PKT_END();

	fflush(ctx->file);
	return 0;
}

#ifndef TRAFGEN_L3_H
#define TRAFGEN_L3_H

enum ip4_field {
	IP4_VER,
	IP4_IHL,
	IP4_DSCP,
	IP4_ECN,
	IP4_TOS,
	IP4_LEN,
	IP4_ID,
	IP4_FLAGS,
	IP4_MF,
	IP4_DF,
	IP4_FRAG_OFFS,
	IP4_TTL,
	IP4_PROTO,
	IP4_CSUM,
	IP4_SADDR,
	IP4_DADDR,
};

enum ip6_field {
	IP6_VER,
	IP6_CLASS,
	IP6_FLOW_LBL,
	IP6_LEN,
	IP6_NEXT_HDR,
	IP6_HOP_LIMIT,
	IP6_SADDR,
	IP6_DADDR,
};

extern void protos_l3_init(void);

#endif /* TRAFGEN_L2_H */

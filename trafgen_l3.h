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
	IP4_FRAG_OFFS,
	IP4_TTL,
	IP4_PROTO,
	IP4_CSUM,
	IP4_SADDR,
	IP4_DADDR,
	IP4_DF,
	IP4_MF,
};

extern void protos_l3_init(void);

#endif /* TRAFGEN_L2_H */

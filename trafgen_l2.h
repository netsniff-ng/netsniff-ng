#ifndef TRAFGEN_L2_H
#define TRAFGEN_L2_H

enum eth_field {
	ETH_DST_ADDR,
	ETH_SRC_ADDR,
	ETH_PROTO_ID,
};

extern void protos_l2_init(void);

#endif /* TRAFGEN_L2_H */

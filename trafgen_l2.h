#ifndef TRAFGEN_L2_H
#define TRAFGEN_L2_H

enum eth_field {
	ETH_DST_ADDR,
	ETH_SRC_ADDR,
	ETH_TYPE,
};

enum arp_field {
	ARP_HTYPE,
	ARP_PTYPE,
	ARP_HLEN,
	ARP_PLEN,
	ARP_OPER,
	ARP_SHA,
	ARP_SPA,
	ARP_THA,
	ARP_TPA,
};

extern void protos_l2_init(void);

#endif /* TRAFGEN_L2_H */

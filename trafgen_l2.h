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

enum vlan_field {
	VLAN_TPID,
	VLAN_TCI,
	VLAN_PCP,
	VLAN_DEI,
	VLAN_VID,
	VLAN_ETYPE,
};

extern void protos_l2_init(void);

#endif /* TRAFGEN_L2_H */

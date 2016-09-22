#ifndef TRAFGEN_L2_H
#define TRAFGEN_L2_H

enum eth_field {
	ETH_DST_ADDR,
	ETH_SRC_ADDR,
	ETH_TYPE,
};

enum pause_field {
	PAUSE_OPCODE,
	PAUSE_TIME,
};

enum pfc_field {
	PFC_OPCODE,
	PFC_PRIO,
	PFC_PRIO_0,
	PFC_PRIO_1,
	PFC_PRIO_2,
	PFC_PRIO_3,
	PFC_PRIO_4,
	PFC_PRIO_5,
	PFC_PRIO_6,
	PFC_PRIO_7,
	PFC_TIME_0,
	PFC_TIME_1,
	PFC_TIME_2,
	PFC_TIME_3,
	PFC_TIME_4,
	PFC_TIME_5,
	PFC_TIME_6,
	PFC_TIME_7,
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

enum mpls_field {
	MPLS_LABEL,
	MPLS_TC,
	MPLS_LAST,
	MPLS_TTL,
};

extern void protos_l2_init(void);

#endif /* TRAFGEN_L2_H */

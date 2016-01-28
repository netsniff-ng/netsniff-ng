#ifndef TRAFGEN_L4_H
#define TRAFGEN_L4_H

enum udp_field {
	UDP_SPORT,
	UDP_DPORT,
	UDP_LEN,
	UDP_CSUM,
};

extern void protos_l4_init(void);

#endif /* TRAFGEN_L4_H */

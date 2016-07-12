#ifndef TRAFGEN_L4_H
#define TRAFGEN_L4_H

enum udp_field {
	UDP_SPORT,
	UDP_DPORT,
	UDP_LEN,
	UDP_CSUM,
};

enum tcp_field {
	TCP_SPORT,
	TCP_DPORT,
	TCP_SEQ,
	TCP_ACK_SEQ,
	TCP_DOFF,
	TCP_CWR,
	TCP_ECE,
	TCP_URG,
	TCP_ACK,
	TCP_PSH,
	TCP_RST,
	TCP_SYN,
	TCP_FIN,
	TCP_WINDOW,
	TCP_CSUM,
	TCP_URG_PTR,
};

enum icmpv4_field {
	ICMPV4_TYPE,
	ICMPV4_CODE,
	ICMPV4_CSUM,
	ICMPV4_ID,
	ICMPV4_SEQ,
	ICMPV4_REDIR_ADDR,
	ICMPV4_MTU,
};

enum icmpv6_field {
	ICMPV6_TYPE,
	ICMPV6_CODE,
	ICMPV6_CSUM,
};

extern void protos_l4_init(void);

#endif /* TRAFGEN_L4_H */

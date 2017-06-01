#ifndef TRAFGEN_L7_H
#define TRAFGEN_L7_H

enum dns_field {
	DNS_ID,
	DNS_QR,
	DNS_OPCODE,
	DNS_AA,
	DNS_TC,
	DNS_RD,
	DNS_RA,
	DNS_ZERO,
	DNS_RCODE,
	DNS_QD_COUNT,
	DNS_AN_COUNT,
	DNS_NS_COUNT,
	DNS_AR_COUNT,
};

enum dns_header {
	DNS_UNDEF_HDR,
	DNS_QUERY_HDR,
	DNS_ANSWER_HDR,
	DNS_AUTH_HDR,
	DNS_ADD_HDR,
};

enum dns_query_field {
	DNS_QUERY_NAME,
	DNS_QUERY_TYPE,
	DNS_QUERY_CLASS,
};

enum dns_rrecord_field {
	DNS_RRECORD_NAME,
	DNS_RRECORD_TYPE,
	DNS_RRECORD_CLASS,
	DNS_RRECORD_TTL,
	DNS_RRECORD_LEN,
	DNS_RRECORD_DATA,
};

extern void protos_l7_init(void);

#endif /* TRAFGEN_L7_H */

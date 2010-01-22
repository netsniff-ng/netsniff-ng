#ifndef	__PROTO_VLAN_H__
#define __PROTO_VLAN_H__

#include <stdint.h>
#include <assert.h>

#define VLAN_HLEN 4
#define ETH_P_8021QinQ	0x8200
#define VLAN_VID_MASK 0xfff

struct vlan_hdr {
	__be16  h_vlan_TCI;
	__be16  h_vlan_encapsulated_proto;
};

static inline struct vlan_hdr * get_vlan_hdr(uint8_t **pkt, uint32_t *pkt_len)
{
	struct vlan_hdr * vlan_header;
	assert(pkt);
	assert(*pkt);
	assert(*pkt_len > VLAN_HLEN);

	vlan_header = (struct vlan_hdr *) *pkt;
	pkt += VLAN_HLEN;
	pkt_len -= VLAN_HLEN;

	return(vlan_header);
}

static inline uint16_t get_vlan_tag(const struct vlan_hdr * header)
{
	assert(header);
	return(header->h_vlan_TCI & VLAN_VID_MASK);
}

static inline uint16_t get_vlan_encap_proto(const struct vlan_hdr * header)
{
	assert(header);
	return(header->h_vlan_encapsulated_proto);

}

#endif	/* __PROTO_VLAN_H__ */

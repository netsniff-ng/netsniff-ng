#ifndef PROTOS_H
#define PROTOS_H

struct protocol;

extern struct protocol arp_ops;
extern struct protocol ethernet_ops;
extern struct protocol icmpv4_ops;
extern struct protocol icmpv6_ops;
extern struct protocol igmp_ops;
extern struct protocol ip_auth_ops;
extern struct protocol ip_esp_ops;
extern struct protocol ipv4_ops;
extern struct protocol ipv6_ops;
extern struct protocol ipv6_dest_opts_ops;
extern struct protocol ipv6_fragm_ops;
extern struct protocol ipv6_hop_by_hop_ops;
extern struct protocol ipv6_in_ipv4_ops;
extern struct protocol ipv6_mobility_ops;
extern struct protocol ipv6_no_next_header_ops;
extern struct protocol ipv6_routing_ops;
extern struct protocol lldp_ops;
extern struct protocol none_ops;
extern struct protocol tcp_ops;
extern struct protocol udp_ops;
extern struct protocol dccp_ops;
extern struct protocol vlan_ops;
extern struct protocol ieee80211_ops;
extern struct protocol QinQ_ops;
extern struct protocol mpls_uc_ops;
extern struct protocol nlmsg_ops;

#endif /* PROTOS_H */

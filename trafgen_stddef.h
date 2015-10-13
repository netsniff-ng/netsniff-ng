/* Taken from Linux kernel, GPL, version 2.0 */

#define ETH_ALEN	6		/* Octets in one ethernet addr */
#define ETH_HLEN	14		/* Total octets in header. */
#define ETH_ZLEN	60		/* Min. octets in frame sans FCS */
#define ETH_DATA_LEN	1500		/* Max. octets in payload */
#define ETH_FRAME_LEN	1514		/* Max. octets in frame sans FCS */
#define ETH_FCS_LEN	4		/* Octets in the FCS */

#define ETH_SRC_RAND	drnd(ETH_ALEN)
#define ETH_DST_RAND	drnd(ETH_ALEN)

#define ETH_P_LOOP	0x0060		/* Ethernet Loopback packet */
#define ETH_P_PUP	0x0200		/* Xerox PUP packet */
#define ETH_P_PUPAT	0x0201		/* Xerox PUP Addr Trans packet */
#define ETH_P_IP	0x0800		/* Internet Protocol packet */
#define ETH_P_X25	0x0805		/* CCITT X.25 */
#define ETH_P_ARP	0x0806		/* Address Resolution packet */
#define	ETH_P_BPQ	0x08FF		/* G8BPQ AX.25 Ethernet Packet [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_IEEEPUP	0x0a00		/* Xerox IEEE802.3 PUP packet */
#define ETH_P_IEEEPUPAT	0x0a01		/* Xerox IEEE802.3 PUP Addr Trans packet */
#define ETH_P_BATMAN	0x4305		/* B.A.T.M.A.N.-Advanced packet [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_DEC       0x6000          /* DEC Assigned proto */
#define ETH_P_DNA_DL    0x6001          /* DEC DNA Dump/Load */
#define ETH_P_DNA_RC    0x6002          /* DEC DNA Remote Console */
#define ETH_P_DNA_RT    0x6003          /* DEC DNA Routing */
#define ETH_P_LAT       0x6004          /* DEC LAT */
#define ETH_P_DIAG      0x6005          /* DEC Diagnostics */
#define ETH_P_CUST      0x6006          /* DEC Customer use */
#define ETH_P_SCA       0x6007          /* DEC Systems Comms Arch */
#define ETH_P_TEB	0x6558		/* Trans Ether Bridging	*/
#define ETH_P_RARP      0x8035		/* Reverse Addr Res packet */
#define ETH_P_ATALK	0x809B		/* Appletalk DDP */
#define ETH_P_AARP	0x80F3		/* Appletalk AARP */
#define ETH_P_8021Q	0x8100          /* 802.1Q VLAN Extended Header */
#define ETH_P_IPX	0x8137		/* IPX over DIX	*/
#define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook */
#define ETH_P_PAUSE	0x8808		/* IEEE Pause frames. See 802.3 31B */
#define ETH_P_SLOW	0x8809		/* Slow Protocol. See 802.3ad 43B */
#define ETH_P_WCCP	0x883E		/* Web-cache coordination protocol defined in draft-wilson-wrec-wccp-v2-00.txt */
#define ETH_P_PPP_DISC	0x8863		/* PPPoE discovery messages */
#define ETH_P_PPP_SES	0x8864		/* PPPoE session messages */
#define ETH_P_MPLS_UC	0x8847		/* MPLS Unicast traffic	*/
#define ETH_P_MPLS_MC	0x8848		/* MPLS Multicast traffic */
#define ETH_P_ATMMPOA	0x884c		/* MultiProtocol Over ATM */
#define ETH_P_LINK_CTL	0x886c		/* HPNA, wlan link local tunnel */
#define ETH_P_ATMFATE	0x8884		/* Frame-based ATM Transport over Ethernet */
#define ETH_P_PAE	0x888E		/* Port Access Entity (IEEE 802.1X) */
#define ETH_P_AOE	0x88A2		/* ATA over Ethernet */
#define ETH_P_8021AD	0x88A8          /* 802.1ad Service VLAN	*/
#define ETH_P_802_EX1	0x88B5		/* 802.1 Local Experimental 1. */
#define ETH_P_TIPC	0x88CA		/* TIPC */
#define ETH_P_8021AH	0x88E7          /* 802.1ah Backbone Service Tag */
#define ETH_P_1588	0x88F7		/* IEEE 1588 Timesync */
#define ETH_P_FCOE	0x8906		/* Fibre Channel over Ethernet  */
#define ETH_P_TDLS	0x890D          /* TDLS */
#define ETH_P_FIP	0x8914		/* FCoE Initialization Protocol */
#define ETH_P_QINQ1	0x9100		/* deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_QINQ2	0x9200		/* deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_QINQ3	0x9300		/* deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_EDSA	0xDADA		/* Ethertype DSA [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_AF_IUCV   0xFBFB		/* IBM af_iucv [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_802_3	0x0001		/* Dummy type for 802.3 frames  */
#define ETH_P_AX25	0x0002		/* Dummy protocol id for AX.25  */
#define ETH_P_802_2	0x0004		/* 802.2 frames */
#define ETH_P_SNAP	0x0005		/* Internal only */
#define ETH_P_DDCMP     0x0006          /* DEC DDCMP: Internal only */
#define ETH_P_WAN_PPP   0x0007          /* Dummy type for WAN PPP frames*/
#define ETH_P_PPP_MP    0x0008          /* Dummy type for PPP MP frames */
#define ETH_P_LOCALTALK 0x0009		/* Localtalk pseudo type */
#define ETH_P_CAN	0x000C		/* CAN: Controller Area Network */
#define ETH_P_CANFD	0x000D		/* CANFD: CAN flexible data rate */
#define ETH_P_PPPTALK	0x0010		/* Dummy type for Atalk over PPP */
#define ETH_P_TR_802_2	0x0011		/* 802.2 frames */
#define ETH_P_MOBITEX	0x0015		/* Mobitex (kaz@cafe.net) */
#define ETH_P_CONTROL	0x0016		/* Card specific control frames */
#define ETH_P_IRDA	0x0017		/* Linux-IrDA */
#define ETH_P_ECONET	0x0018		/* Acorn Econet	*/
#define ETH_P_HDLC	0x0019		/* HDLC frames */
#define ETH_P_ARCNET	0x001A		/* 1A for ArcNet :-) */
#define ETH_P_DSA	0x001B		/* Distributed Switch Arch. */
#define ETH_P_TRAILER	0x001C		/* Trailer switch tagging */
#define ETH_P_PHONET	0x00F5		/* Nokia Phonet frames */
#define ETH_P_IEEE802154 0x00F6		/* IEEE802.15.4 frames */
#define ETH_P_CAIF	0x00F7		/* ST-Ericsson CAIF protocol */

#define INADDR_BROADCAST	0xffffffff	/* 255.255.255.255 */
#define INADDR_LOOPBACK		0x7f000001	/* 127.0.0.1 */
#define INADDR_UNSPEC_GROUP	0xe0000000	/* 224.0.0.0 */
#define INADDR_ALLHOSTS_GROUP	0xe0000001	/* 224.0.0.1 */
#define INADDR_ALLRTRS_GROUP	0xe0000002	/* 224.0.0.2 */
#define INADDR_MAX_LOCAL_GROUP	0xe00000ff	/* 224.0.0.255 */

#define IPPROTO_ICMP	1		/* Internet Control Message Protocol */
#define IPPROTO_IGMP	2		/* Internet Group Management Protocol */
#define IPPROTO_IPIP	4		/* IPIP tunnels (older KA9Q tunnels use 94) */
#define IPPROTO_TCP	6		/* Transmission Control Protocol */
#define IPPROTO_EGP	8		/* Exterior Gateway Protocol */
#define IPPROTO_PUP	12		/* PUP protocol	*/
#define IPPROTO_UDP	17		/* User Datagram Protocol */
#define IPPROTO_IDP	22		/* XNS IDP protocol */
#define IPPROTO_DCCP	33		/* Datagram Congestion Control Protocol */
#define IPPROTO_RSVP	46		/* RSVP protocol */
#define IPPROTO_GRE	47		/* Cisco GRE tunnels (rfc 1701,1702) */
#define IPPROTO_IPV6	41		/* IPv6-in-IPv4 tunnelling */
#define IPPROTO_ESP	50		/* Encapsulation Security Payload protocol */
#define IPPROTO_AH	51		/* Authentication Header protocol       */
#define IPPROTO_BEETPH	94		/* IP option pseudo header for BEET */
#define IPPROTO_PIM	103		/* Protocol Independent Multicast */
#define IPPROTO_COMP	108		/* Compression Header protocol */
#define IPPROTO_SCTP	132		/* Stream Control Transport Protocol */
#define IPPROTO_UDPLITE	136		/* UDP-Lite (RFC 3828) */

#define IP_ALEN			4
#define IP_VERSION		4
#define IP_TTL_DEFAULT		64
#define IP_HDR_OFF_DEFAULT	14
#define IP_SRC_RAND		drnd(IP_ALEN)
#define IP_DST_RAND		drnd(IP_ALEN)
#define IP_ID_RAND		drnd(2)
#define IP_CSUM_DEFAULT		csumip(IP_HDR_OFF_DEFAULT, 33)	/* IP-hdr offset from, to */

#define IPV6_ALEN		16
#define IPV6_VERSION		6
#define IPV6_HDR_OFF_DEFAULT	14
#define IPV6_SRC_RAND		drnd(IPV6_ALEN)
#define IPV6_DST_RAND		drnd(IPV6_ALEN)

#define ICMP_ECHOREPLY		0	/* Echo Reply */
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable */
#define ICMP_SOURCE_QUENCH	4	/* Source Quench */
#define ICMP_REDIRECT		5	/* Redirect (change route) */
#define ICMP_ECHO		8	/* Echo Request	*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded */
#define ICMP_PARAMETERPROB	12	/* Parameter Problem */
#define ICMP_TIMESTAMP		13	/* Timestamp Request */
#define ICMP_TIMESTAMPREPLY	14	/* Timestamp Reply */
#define ICMP_INFO_REQUEST	15	/* Information Request */
#define ICMP_INFO_REPLY		16	/* Information Reply */
#define ICMP_ADDRESS		17	/* Address Mask Request */
#define ICMP_ADDRESSREPLY	18	/* Address Mask Reply */

/* Codes for UNREACH. */
#define ICMP_NET_UNREACH	0	/* Network Unreachable */
#define ICMP_HOST_UNREACH	1	/* Host Unreachable */
#define ICMP_PROT_UNREACH	2	/* Protocol Unreachable */
#define ICMP_PORT_UNREACH	3	/* Port Unreachable */
#define ICMP_FRAG_NEEDED	4	/* Fragmentation Needed/DF set */
#define ICMP_SR_FAILED		5	/* Source Route failed */
#define ICMP_NET_UNKNOWN	6
#define ICMP_HOST_UNKNOWN	7
#define ICMP_HOST_ISOLATED	8
#define ICMP_NET_ANO		9
#define ICMP_HOST_ANO		10
#define ICMP_NET_UNR_TOS	11
#define ICMP_HOST_UNR_TOS	12
#define ICMP_PKT_FILTERED	13	/* Packet filtered */
#define ICMP_PREC_VIOLATION	14	/* Precedence violation */
#define ICMP_PREC_CUTOFF	15	/* Precedence cut off */
#define NR_ICMP_UNREACH		15	/* instead of hardcoding immediate value */

/* Codes for REDIRECT. */
#define ICMP_REDIR_NET		0	/* Redirect Net	*/
#define ICMP_REDIR_HOST		1	/* Redirect Host */
#define ICMP_REDIR_NETTOS	2	/* Redirect Net for TOS	*/
#define ICMP_REDIR_HOSTTOS	3	/* Redirect Host for TOS */

/* Codes for TIME_EXCEEDED. */
#define ICMP_EXC_TTL		0	/* TTL count exceeded */
#define ICMP_EXC_FRAGTIME	1	/* Fragment Reass time exceeded	*/

#define TCP_SEQ_RAND		drnd(4)
#define TCP_ACK_RAND		drnd(4)
#define TCP_SRC_RAND		drnd(2)
#define TCP_DST_RAND		drnd(2)
#define TCP_CSUM_DEFAULT	csumtcp(IP_HDR_OFF_DEFAULT, 34)	/* Offset IP, offset TCP */

#define TCP_FLAG_CWR		(1 << 7)
#define TCP_FLAG_ECE		(1 << 6)
#define TCP_FLAG_URG		(1 << 5)
#define TCP_FLAG_ACK		(1 << 4)
#define TCP_FLAG_PSH		(1 << 3)
#define TCP_FLAG_RST		(1 << 2)
#define TCP_FLAG_SYN		(1 << 1)
#define TCP_FLAG_FIN		(1 << 0)

#define TCP_RESERVED_BITS	0x0F00
#define TCP_DATA_OFFSET		0xF000

/* Misc things */
#define JOIN(x, y)		x ## y

#define IF_0(x)
#define IF_1(x)			x
#define IF(bit, x)		JOIN(IF_, bit)(x)

#define IF_ELSE_0(x, y)		y
#define IF_ELSE_1(x, y)		x
#define IF_ELSE(bit, x, y)	JOIN(IF_ELSE_, bit)(x, y)

#define be16(x)			c16(x)
#define be32(x)			c32(x)
#define be64(x)			c64(x)

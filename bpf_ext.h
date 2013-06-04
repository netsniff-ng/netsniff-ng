#ifndef BPF_EXT
#define BPF_EXT

#ifndef SKF_AD_OFF
# define SKF_AD_OFF			(-0x1000)
#endif
#ifndef SKF_AD_PROTOCOL
# define SKF_AD_PROTOCOL		0
#endif
#ifndef SKF_AD_PKTTYPE
# define SKF_AD_PKTTYPE			4
#endif
#ifndef SKF_AD_IFINDEX
# define SKF_AD_IFINDEX			8
#endif
#ifndef SKF_AD_NLATTR
# define SKF_AD_NLATTR			12
#endif
#ifndef SKF_AD_NLATTR_NEST
# define SKF_AD_NLATTR_NEST		16
#endif
#ifndef SKF_AD_MARK
# define SKF_AD_MARK			20
#endif
#ifndef SKF_AD_QUEUE
# define SKF_AD_QUEUE			24
#endif
#ifndef SKF_AD_HATYPE
# define SKF_AD_HATYPE			28
#endif
#ifndef SKF_AD_RXHASH
# define SKF_AD_RXHASH			32
#endif
#ifndef SKF_AD_CPU
# define SKF_AD_CPU			36
#endif
#ifndef SKF_AD_VLAN_TAG
# define SKF_AD_VLAN_TAG		44
#endif
#ifndef SKF_AD_VLAN_TAG_PRESENT
# define SKF_AD_VLAN_TAG_PRESENT	48
#endif
#ifndef SKF_AD_PAY_OFFSET
# define SKF_AD_PAY_OFFSET		52
#endif

#endif /* BPF_EXT */

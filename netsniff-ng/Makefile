netsniff-ng-libs =	-lpthread

ifeq ($(CONFIG_LIBPCAP), 1)
netsniff-ng-libs +=	-lpcap
endif
ifeq ($(CONFIG_GEOIP), 1)
netsniff-ng-libs +=	-lGeoIP \
			-lz
endif
ifeq ($(CONFIG_LIBNL), 1)
netsniff-ng-libs +=	$(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --libs libnl-3.0) \
			$(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --libs libnl-genl-3.0) \
			$(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --libs libnl-route-3.0)
endif

netsniff-ng-objs =	dissector.o \
			dissector_sll.o \
			dissector_eth.o \
			dissector_80211.o \
			dissector_netlink.o \
			lookup.o \
			proto_arp.o \
			proto_ethernet.o \
			proto_icmpv4.o \
			proto_icmpv6.o \
			proto_igmp.o \
			proto_ip_authentication_hdr.o \
			proto_ip_esp.o \
			proto_ipv4.o \
			proto_ipv6.o \
			proto_ipv6_dest_opts.o \
			proto_ipv6_fragm.o \
			proto_ipv6_hop_by_hop.o \
			proto_ipv6_in_ipv4.o \
			proto_ipv6_mobility_hdr.o \
			proto_ipv6_no_nxt_hdr.o \
			proto_ipv6_routing.o \
			proto_lldp.o \
			proto_none.o \
			proto_tcp.o \
			proto_udp.o \
			proto_dccp.o \
			proto_vlan.o \
			proto_vlan_q_in_q.o \
			proto_mpls_unicast.o \
			proto_80211_mac_hdr.o \
			privs.o \
			proc.o \
			dev.o \
			str.o \
			sig.o \
			sock.o \
			irq.o \
			iosched.o \
			ioops.o \
			link.o \
			xmalloc.o \
			hash.o \
			bpf.o \
			pcap_rw.o \
			pcap_sg.o \
			pcap_mm.o \
			ring_rx.o \
			ring_tx.o \
			ring.o \
			tprintf.o \
			timer.o \
			die.o \
			sysctl.o \
			netsniff-ng.o

ifeq ($(CONFIG_LIBPCAP), 1)
netsniff-ng-objs +=	bpf_comp.o
endif
ifeq ($(CONFIG_GEOIP), 1)
netsniff-ng-objs +=	geoip.o
endif
ifeq ($(CONFIG_HWTSTAMP), 1)
netsniff-ng-objs +=	tstamping.o
endif
ifeq ($(CONFIG_LIBNL), 1)
netsniff-ng-objs +=	mac80211.o \
			proto_nlmsg.o
endif

netsniff-ng-eflags = -DNEED_TCPDUMP_LIKE_FILTER

ifeq ($(CONFIG_LIBNL), 1)
netsniff-ng-eflags += $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --cflags libnl-3.0) \
		      $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --cflags libnl-genl-3.0) \
		      $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) $(PKG_CONFIG) --cflags libnl-route-3.0)
endif

netsniff-ng-confs =	ether.conf \
			tcp.conf \
			udp.conf \
			oui.conf \
			geoip.conf

mausezahn-libs =	-lcli \
			-lnet \
			-lpcap \
			-lrt \
			-lpthread \
			-lm

mausezahn-objs =	str.o \
			die.o \
			dev.o \
			sock.o \
			link.o \
			sysctl.o \
			xmalloc.o \
			staging/layer1.o \
			staging/layer2.o \
			staging/layer3.o \
			staging/layer4.o \
			staging/hextools.o \
			staging/tools.o \
			staging/lookupdev.o \
			staging/time.o \
			staging/modifications.o \
			staging/send_eth.o \
			staging/send.o \
			staging/cdp.o \
			staging/rtp.o \
			staging/dns.o \
			staging/rcv_rtp.o \
			staging/syslog.o \
			staging/cli.o \
			staging/cli_cmds.o \
			staging/cli_launch.o \
			staging/cli_legacy.o \
			staging/cli_packet.o \
			staging/cli_interface.o \
			staging/cli_set.o \
			staging/cli_dns.o \
			staging/cli_arp.o \
			staging/cli_bpdu.o \
			staging/cli_eth.o \
			staging/cli_ip.o \
			staging/cli_udp.o \
			staging/cli_tcp.o \
			staging/cli_rtp.o \
			staging/cli_tools.o \
			staging/cli_igmp.o \
			staging/cli_lldp.o \
			staging/cli_sequence.o \
			staging/mops.o \
			staging/mops_update.o \
			staging/mops_tools.o \
			staging/mops_checksums.o \
			staging/mops_threads.o \
			staging/mops_dot1Q.o \
			staging/mops_mpls.o \
			staging/mops_ip.o \
			staging/mops_tcp.o \
			staging/mops_ext.o \
			staging/mops_ext_arp.o \
			staging/mops_ext_bpdu.o \
			staging/mops_ext_rtp.o \
			staging/mopsrx_arp.o \
			staging/mops_ext_igmp.o \
			staging/mops_ext_lldp.o \
			staging/mops_sequence.o \
			staging/automops.o \
			staging/parse_xml.o \
			staging/tx_switch.o \
			staging/llist.o \
			staging/directmops.o \
			staging/mausezahn.o

mausezahn-eflags = -O2 -I. -I.. \
		   -DVERSION_STRING=\"$(VERSION_STRING)\" \
		   -DVERSION_LONG=\"$(VERSION_LONG)\"

mausezahn-confs =

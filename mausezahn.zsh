#compdef mausezahn
#
# mausezahn.zsh -- zsh completion function for mausezahn
#
# Copyright (C) 2013 Hideo Hattori <hhatto.jp@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.

typeset -A opt_args

_packet_type () {
    _values \
        "arp" \
        "bpdu" \
        "cdp" \
        "ip" \
        "icmp" \
        "udp" \
        "tcp" \
        "dns" \
        "rtp" \
        "syslog" \
        "lldp"
}

_interface_keywords () {
    _values "interface keyword" \
        "rand[Use a random MAC address]" \
        "bc[Use a broadcast MAC address]" \
        "own[Use own interface MAC address (default for source MAC)]" \
        "stp[Use IEEE 802.1d STP multicast address]" \
        "cisco[Use Cisco multicast address as used for CDP, VTP, or PVST+]"
}

_interfaces () {
    _wanted interfaces expl 'network interface' \
    _net_interfaces
    _values "Pseudo-device that captures on all interfaces" "any"
}

_arguments -s -S \
    "-x[Interactive mode with telnet CLI, default port: 25542]" \
    "-l[Listen address in interactive mode, default: 0.0.0.0]" \
    "(-6)-4[IPv4 mode (default)]" \
    "(-4)-6[IPv6 mode]" \
    "-c[Send packet count times, default:1, infinite:0]" \
    "-d[Apply delay between transmissions. The delay value can be specified in usec (default, no additional unit needed), or in msec (e.g. 100m or 100msec), or in seconds (e.g. 100s or 100sec)]" \
    "-r[Multiplies the specified delay with a random value]" \
    "-p[Pad the raw frame to specified length (using random bytes)]" \
    "-a[Use specified source mac address, no matter what has been specified with other arguments; keywords see below, Default is own interface]:keyword:_interface_keywords" \
    "-b[Same with destination mac address; keywords]:keywords:_interface_keywords" \
    "-A[Use specified source IP address (default is own interface IP)]" \
    "-B[Send packet to specified destination IP or domain name]" \
    "-P[Use the specified ASCII payload]" \
    "-f[Read the ASCII payload from a file]:filename:_files" \
    "-F[Read the hexadecimal payload from a file]:filename:_files" \
    "-Q[Specify 802.1Q VLAN tag and optional Class of Service, you can specify multiple 802.1Q VLAN tags (QinQ...) by separating them via a comma or a period (e.g. '5:10,20,2:30')]" \
    "-t[Specify packet type for autobuild (you don't need to care for encapsulations in lower layers, most packet types allow/require additional packet-specific arguments in an <arg-string>; Currently supported types: arp, bpdu, cdp, ip, icmp, udp, tcp, dns, rtp, syslog, lldp and more; For context-help use 'help' as <arg-string>!]:packet_type:_packet_type" \
    "-T[Specify packet type for server mode, currently only rtp is supported; Enter -T help or -T rtp help for further information]" \
    "-M[Insert a MPLS label, enter '-M help' for a syntax description]" \
    "(-V -VV -VVV)"{-V,-VV,-VVV}"[Verbose and more verbose mode]" \
    "-q[Quiet mode, even omit 'important' standard short messages]" \
    "-S[Simulation mode: DOES NOT put anything on the wire, this is typically combined with one of the verbose modes (v or V)]" \
    "-v[Show version and exit]:" \
    "-h[Print help and exit]:" \
    "*::args:_gnu_generic"

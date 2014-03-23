#compdef astraceroute
#
# astraceroute.zsh -- zsh completion function for astraceroute
#
# Copyright (C) 2013 Hideo Hattori <hhatto.jp@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.

typeset -A opt_args

_interfaces () {
    _wanted interfaces expl 'network interface' \
    _net_interfaces
    _values "Pseudo-device that captures on all interfaces" "any"
}

_arguments -s -S \
    "(-H --host)"{-H,--host}"[Host/IPv4/IPv6 to lookup AS route to]:host:_hosts" \
    "(-p --port)"{-p,--port}"[Hosts port to lookup AS route to]:port:_gnu_generic" \
    "(-i -d --dev)"{-i,-d,--dev}"[Networking device i.e., eth0]:device:_interfaces" \
    "(-b --bind)"{-b,--bind}"[IP address to bind to, Must specify -6 for an IPv6 address]" \
    "(-4 --ipv4)"{-4,--ipv4}"[Use IPv4 requests (default)]" \
    "(-6 --ipv6)"{-6,--ipv6}"[Use IPv6 requests]" \
    "(-n --numeric)"{-n,--numeric}"[Do not do reverse DNS lookup for hops]" \
    "(-u --update)"{-u,--update}"[Update GeoIP databases]" \
    "(-L --latitude)"{-L,--latitude}"[Show latitude and longitude]" \
    "(-N --dns)"{-N,--dns}"[Do a reverse DNS lookup for hops]" \
    "(-f --init-ttl)"{-f,--init-ttl}"[Set initial TTL]:ttl:_gnu_generic" \
    "(-m --max-ttl)"{-m,--max--ttl}"[Set maximum TTL]:ttl:_gnu_generic" \
    "(-q --num-probes)"{-q,--num-probes}"[Number of max probes for each hop (default: 3)]:num:_gnu_generic" \
    "(-x --timeout)"{-x,--timeout}"[Probe response timeout in sec (default: 3)]:timeout:_gnu_generic" \
    "(-S --syn)"{-S,--syn}"[Set TCP SYN flag in packets]" \
    "(-A --ack)"{-A,--ack}"[Set TCP ACK flag in packets]" \
    "(-F --fin)"{-F,--fin}"[Set TCP FIN flag in packets]" \
    "(-P --psh)"{-P,--psh}"[Set TCP PSH flag in packets]" \
    "(-U --urg)"{-U,--urg}"[Set TCP URG flag in packets]" \
    "(-R --rst)"{-R,--rst}"[Set TCP RST flag in packets]" \
    "(-E --ecn-syn)"{-E,--ecn-syn}"[Send ECN SYN packets (RFC3168)]" \
    "(-t --tos)"{-t,--tos}"[Set the IP TOS field]:tos:_gnu_generic" \
    "(-G --nofrag)"{-G,--nofrag}"[Set do not fragment bit]" \
    "(-X --payload)"{-X,--payload}"[Specify a payload string to test DPIs]:string:_gnu_generic" \
    "(-Z --show-packet)"{-Z,--show-packet}"[Show returned packet on each hop]" \
    "(-l --totlen)"{-l,--totlen}"[Specify total packet len]:lengths:_gnu_generic" \
    {-v,--version}"[Print version and exit]:" \
    {-h,--help}"[Print help and exit]:" \
    "*::args:_gnu_generic"

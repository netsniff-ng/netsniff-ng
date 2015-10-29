#compdef flowtop
#
# flowtop.zsh -- zsh completion function for flowtop
#
# Copyright (C) 2013 Hideo Hattori <hhatto.jp@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.

typeset -A opt_args

_arguments -s -S \
    "(-4 --ipv4)"{-4,--ipv4}"[Show only IPv4 flows (default)]" \
    "(-6 --ipv6)"{-6,--ipv6}"[Show only IPv6 flows (default)]" \
    "(-T --tcp)"{-T,--tcp}"[Show only TCP flows (default)]" \
    "(-U --udp)"{-U,--udp}"[Show only UDP flows]" \
    "(-D --dccp)"{-D,--dccp}"[Show only DCCP flows]" \
    "(-I --icmp)"{-I,--icmp}"[Show only ICMP/ICMPv6 flows]" \
    "(-S --sctp)"{-S,--sctp}"[Show only SCTP flows]" \
    "(-n --no-dns)"{-n,--no-dns}"[Don't perform hostname lookup]" \
    "(-G --no-geoip)"{-G,--no-geoip}"[Don't perform GeoIPlookup]" \
    "(-s --show-src)"{-s,--show-src}"[Also show source, not only dest]" \
    "(-b --bits)"{-b,--bits}"[Show rates in bits/s instead of bytes/s]" \
    "(-u --update)"{-u,--update}"[Update GeoIP databases]" \
    "(-t --interval)"{-t,--interval}"[Refresh time in seconds (def: 1s)]:interval:_gnu_generic" \
    {-v,--version}"[Print version and exit]:" \
    {-h,--help}"[Print help and exit]:" \
    "*::args:_gnu_generic"

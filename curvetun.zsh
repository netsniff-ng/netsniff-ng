#compdef curvetun
#
# curvetun.zsh -- zsh completion function for curvetun
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
    "(-k --keygen)"{-k,--keygen}"[Generate public/private keypair]" \
    "(-x --export)"{-x,--export}"[Export your public data for remote servers]" \
    "(-C --dumpc)"{-C,--dumpc}"[Dump parsed clients]" \
    "(-S --dumps)"{-S,--dumps}"[Dump parsed servers]" \
    "(-D --nofork)"{-D,--nofork}"[Do not daemonize]" \
    "(-d --dev)"{-d,--dev}"[Networking tunnel device, e.g. tun0]:device:_interfaces" \
    {-v,--version}"[Print version]:" \
    {-h,--help}"[Print this help]:" \
    "(-s --server -N --no-logging -p --port -t --stun -u --udp -4 --ipv4 -6 --ipv6 -c --client)"{-c,--client}"[Client mode, server alias optional]:client:_gnu_generic" \
    "(-c --client -s --server)"{-s,--server}"[Server mode]" \
    "(-c --client -N --no-logging)"{-N,--no-logging}"[Disable server logging (for better anonymity)]" \
    "(-c --client -p --port)"{-p,--port}"[Port number (mandatory)]:port:_gnu_generic" \
    "(-c --client -t --stun)"{-t,--stun}"[Show public IP/Port mapping via STUN]:stun:_gnu_generic" \
    "(-c --client -u --udp)"{-u,--udp}"[Use UDP as carrier instead of TCP]" \
    "(-c --client -4 --ipv4)"{-4,--ipv4}"[Tunnel devices are IPv4]" \
    "(-c --client -6 --ipv6)"{-6,--ipv6}"[Tunnel devices are IPv6 (default: same as carrier protocol)]" \
    "*::args:_gnu_generic"

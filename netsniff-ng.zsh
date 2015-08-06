#compdef netsniff-ng
#
# netsniff-ng.zsh -- zsh completion function for netsniff-ng
#
# Copyright (C) 2013 Hideo Hattori <hhatto.jp@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.

typeset -A opt_args
local context state line

_cpu () {
    _cpus=(${${(f)"$(grep processor /proc/cpuinfo | awk '{print $3}')"}})
    compadd -a _cpus
}

_user_info () {
    user_info=(${${(f)"$(awk -F':' '{print $3":"$1}' /etc/passwd)"}})
    _describe -t usr "user info" user_info && ret=0
}

_group_info () {
    group_info=(${${(f)"$(awk -F':' '{print $4":"$1}' /etc/passwd)"}})
    _describe -t usr "group info" group_info && ret=0
}

_interfaces () {
    _wanted interfaces expl 'network interface' \
    _net_interfaces
    _values "Pseudo-device that captures on all interfaces" "any"
}

_arguments -s -S \
    "(-i -d --dev --in)"{-i,-d,--dev,--in}"[Input source as netdev, pcap or pcap stdin]:input:_interfaces" \
    "(-o --out)"{-o,--out}"[Output sink as netdev, pcap, directory, trafgen, or stdout]::_gnu_generic" \
    "(-C --fanout-group)"{-C,--fanout-group}"[Join packet fanout group]" \
    "(-K --fanout-type)"{-K,--fanout-type}"[Apply fanout discipline: hash|lb|cpu|rnd|roll|qm]" \
    "(-L --fanout-opts)"{-L,--fanout-opts}"[Additional fanout options: defrag|roll]" \
    "(-f --filter)"{-f,--filter}"[Use BPF filter file from bpfc or tcpdump-like expression]" \
    "(-t --type)"{-t,--type}"[Filter type]:filter:(host broadcast multicast others outgoing)" \
    "(-F --interval)"{-F,--interval}"[Dump interval if -o is a dir: <num>KiB/MiB/GiB/s/sec/min/hrs]:interval:_gnu_generic" \
    "(-J --jumbo-support)"{-J,--jumbo-support}"[Support for 64KB Super Jumbo Frames (def: 2048B)]" \
    "(-R --rfraw)"{-R,--rfraw}"[Capture or inject raw 802.11 frames]" \
    "(-n --num)"{-n,--num}"[Number of packets until exit (def: 0)]" \
    "(-P --prefix)"{-P,--prefix}"[Prefix for pcaps stored in directory]" \
    "(-T --magic)"{-T,--magic}"[Pcap magic number/pcap format to store, see -D]" \
    "(-w --cooked)"{-w,--cooked}"[Use Linux \"cooked\" header instead of link header]" \
    "(-D --dump-pcap-types)"{-D,--dump-pcap-types}"[Dump pcap types and magic numbers and quit]" \
    "(-B --dump-bpf)"{-B,--dump-bpf}"[Dump generated BPF assembly]" \
    "(-r --rand)"{-r,--rand}"[Randomize packet forwarding order (dev->dev)]" \
    "(-M --no-promisc)"{-M,--no-promisc}"[No promiscuous mode for netdev]" \
    "(-N --no-hwtimestamp)"{-N,--no-hwtimestamp}"[Disable hardware timestamping]" \
    "(-A --no-sock-mem)"{-A,--no-sock-mem}"[Don\'t tune core socket memory]" \
    "(-m --mmap)"{-m,--mmap}"[Mmap(2) pcap file i.e., for replaying pcaps]" \
    "(-G --sg)"{-G,--sg}"[Scatter/gather pcap file I/O]" \
    "(-c --clrw)"{-c,--clrw}"[Use slower read(2)/write(2) I/O]" \
    "(-S --ring-size)"{-S,--ring-size}"[Specify ring size to: <num>KiB/MiB/GiB]:ringsize:" \
    "(-k --kernel-pull)"{-k,--kernel-pull}"[Kernel pull from user interval in us (def: 10us)]:kernelpull:_gnu_generic" \
    "(-b --bind-cpu)"{-b,--bind-cpu}"[Bind to specific CPU]:cpunum:_cpu" \
    "(-u --user)"{-u,--user}"[Drop privileges and change to userid]:user:_user_info" \
    "(-g --group)"{-g,--group}"[Drop privileges and change to groupid]:group:_group_info" \
    "(-H --prio-high)"{-H,--prio-high}"[Make this high priority process]" \
    "(-Q --notouch-irq)"{-Q,--notouch-irq}"[Do not touch IRQ CPU affinity of NIC]" \
    "(-s --silent)"{-s,--silent}"[Do not print captured packets]" \
    "(-q --less)"{-q,--less}"[Print less-verbose packet information]" \
    "(-X --hex)"{-X,--hex}"[Print packet data in hex format]" \
    "(-l --ascii)"{-l,--ascii}"[Print human-readable packet data]" \
    "(-U --update)"{-U,--update}"[Update GeoIP databases]" \
    "(-V --verbose)"{-V,--verbose}"[Be more verbose]" \
    {-v,--version}"[Show version and exit]:" \
    {-h,--help}"[Guess what?!]:" \
    "*::args:_gnu_generic"

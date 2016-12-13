#compdef trafgen
#
# trafgen.zsh -- zsh completion function for trafgen
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
    "(-i -c --in --conf)"{-i,-c,--in,--conf}"[Packet configuration file/stdin]:input:_files" \
    "(-o -d --out --dev)"{-o,-d,--out,--dev}"[Networking device i.e., eth0]:device:_interfaces" \
    "(-p --cpp)"{-p,--cpp}"[Run packet config through C preprocessor]" \
    "(-D --define)"{-D,--define}"[Add macro definition for the C preprocessor]::" \
    "(-J --jumbo-support)"{-J,--jumbo-support}"[Support 64KB super jumbo frames (def: 2048B)]" \
    "(-R --rfraw)"{-R,--rfraw}"[Inject raw 802.11 frames]" \
    "(-s --smoke-test)"{-s,--smoke-test}"[Probe if machine survived fuzz-tested packet]" \
    "(-n --num)"{-n,--num}"[Number of packets until exit (def: 0)]" \
    "(-r --rand)"{-r,--rand}"[Randomize packet selection (def: round robin)]" \
    "(-P --cpus)"{-P,--cpus}"[Specify number of forks(<= CPUs) (def: #CPUs)]:cpunum:_cpu" \
    "(-t --gap)"{-t,--gap}"[Set approx. interpacket gap (s/ms/us/ns, def: us)]:gap:" \
    "(-b --rate)"(-b,--rate)"[Send traffic at specified rate (pps/B/kB/MB/GB/kbit/Mbit/Gbit/KiB/MiB/GiB):rate:" \
    "(-S --ring-size)"{-S,--ring-size}"[Manually set mmap size (KiB/MiB/GiB)]:ringsize:" \
    "(-E --seed)"{-E,--seed}"[Manually set srand(3) seed]" \
    "(-u --user)"{-u,--user}"[Drop privileges and change to userid]:user:_user_info" \
    "(-g --group)"{-g,--group}"[Drop privileges and change to groupid]:group:_group_info" \
    "(-H --prio-high)"{-H,--prio-high}"[Make this high priority process]" \
    "(-A --no-sock-mem)"{-A,--no-sock-mem}"[Do not change default socket memory setting]" \
    "(-Q --notouch-irq)"{-Q,--notouch-irq}"[Do not touch IRQ CPU affinity of NIC]" \
    "(-q --qdisc-path)"{-q,--qdisc-path}"[Enable qdisc kernel path (default off since 3.14)]" \
    "(-e --example)"{-e,--example}"[Show built-in packet config example]:" \
    "(-V --verbose)"{-V,--verbose}"[Be more verbose]" \
    "(-C --no-cpu-stats)"{-C,--no-cpu-stats}"[Do not print CPU time statistics on exit]" \
    {-v,--version}"[Show version and exit]:" \
    {-h,--help}"[Guess what?!]:" \
    "*::args:_gnu_generic"

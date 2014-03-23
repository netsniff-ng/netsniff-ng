#compdef ifpps
#
# ifpps.zsh -- zsh completion function for ifpps
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
    "(-d --dev)"{-d,--dev}"[Device to fetch statistics for i.e., eth0]:device:_interfaces" \
    "(-p --promisc)"{-p,--promisc}"[Promiscuous mode]" \
    "(-P --percentage)"{-P,--percentage}"[Show percentage of theoretical line rate]" \
    "(-t --interval)"{-t,--interval}"[Refresh time in sec (default 1 s)]:interval:_gnu_generic" \
    "(-n --num-cpus)"{-n,--num-cpus}"[Number of top hitter CPUs to display in ncurses mode (default 10)]" \
    "(-C --csv)"{-C,--csv}"[Output to terminal as CSV  E.g. post-processing with Gnuplot et al.]" \
    "(-l --loop)"{-l,--loop}"[Loop terminal output]" \
    "(-o --omit-header)"{-o,--omit-header}"[Do not print the CSV header]" \
    "(-m --median)"{-m,--median}"[Display median values]" \
    "(-W --no-warn)"{-W,--no-warn}"[Suppress warnings]" \
    {-v,--version}"[Print version and exit]:" \
    {-h,--help}"[Print help and exit]:" \
    "*::args:_gnu_generic"

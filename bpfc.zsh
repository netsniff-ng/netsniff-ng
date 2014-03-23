#compdef bpfc
#
# bpfc.zsh --  zsh completion function for bpfc
#
# Copyright (C) 2013 Hideo Hattori <hhatto.jp@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.

typeset -A opt_args

_arguments -s -S \
    "(-i --input)"{-i,--input}"[Berkeley Packet Filter file]:input:_files" \
    "(-p --cpp)"{-p,--cpp}"[Run bpf program through C preprocessor]" \
    "(-f --format)"{-f,--format}"[Output format]:output:(C netsniff-ng xt_bpf tcpdump)" \
    "(-b --bypass)"{-b,--bypass}"[Bypass filter validation (e.g. for bug testing)]" \
    "(-d --dump)"{-d,--dump}"[Dump supported instruction table]" \
    "(-V --verbose)"{-V,--verbose}"[Be more verbose]" \
    {-v,--version}"[Print version and exit]:" \
    {-h,--help}"[Print help and exit]:" \
    "*::args:_gnu_generic"

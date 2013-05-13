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
    "(-V --verbose)"{-V,--verbose}"[Be more verbose]" \
    {-v,--version}"[Print version]:" \
    {-h,--help}"[Print this help]:" \
    "*::args:_gnu_generic"

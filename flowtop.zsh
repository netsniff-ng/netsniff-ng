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
    "(-T --tcp)"{-T,--tcp}"[Show only TCP flows (default)]" \
    "(-U --udp)"{-U,--udp}"[Show only UDP flows]" \
    "(-s --show-src)"{-s,--show-src}"[Also show source, not only dest]" \
    "--city-db[Specifiy path for geoip city database]:path:_files" \
    "--country-db[Specifiy path for geoip country database]:path:_files" \
    {-v,--version}"[Print version]:" \
    {-h,--help}"[Print this help]:" \
    "*::args:_gnu_generic"

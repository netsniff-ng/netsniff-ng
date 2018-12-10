#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# update-oui.py -- update netsniff-ng oui.conf from official IEEE OUI list
#
# Copyright (C) 2013 Tobias Klauser <tklauser@distanz.ch>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.

import os
import sys
import re
import getopt
try:
    from urllib.request import urlopen
except ImportError as e:
    raise Exception("Please run this script with Python 3")

DEFAULT_OUPUT_FILE = "oui.conf"
DEFAULT_OUI_URL = "http://standards.ieee.org/develop/regauth/oui/oui.txt"

OUI_PATTERN = re.compile("^\s*([a-fA-F0-9]{6})\s+\(base 16\)\s+(.*)$")

def usage():
    print("""usage: {0} [OPTION...]
available options:
    -f  force overwrite of existing file
    -o  set output file (default: {1})
    -u  set URL to fetch OUI list from (default: {2})
    -h  show this help and exit""".format(os.path.basename(sys.argv[0]),
                                          DEFAULT_OUPUT_FILE, DEFAULT_OUI_URL))

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "fo:u:h")
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        sys.exit(-1)

    overwrite = False
    output_file = DEFAULT_OUPUT_FILE
    oui_url = DEFAULT_OUI_URL
    for o, a in opts:
        if o == '-f':
            overwrite = True
        elif o == '-o':
            output_file = a
        elif o == '-u':
            oui_url = a
        elif o == '-h':
            usage()
            sys.exit(0)
        else:
            assert False, "unhandled option"

    if not overwrite and os.path.exists(output_file):
        print("Error: output file {} already exists".format(output_file))
        sys.exit(-1)

    print("Updating OUI information in {} from {}... ".format(output_file, oui_url))

    fh_url = urlopen(oui_url)
    encoding = fh_url.headers.get_content_charset()
    if not encoding:
        encoding = "utf-8"

    ouis = []
    for line in fh_url:
        m = OUI_PATTERN.match(line.decode(encoding))
        if m:
            oui = "0x{}".format(m.group(1))
            vendor = m.group(2).rstrip()
            ouis.append((oui, vendor))

    fh_file = open(output_file, 'w')
    for oui, vendor in sorted(ouis):
        fh_file.write("{}, {}\n".format(oui, vendor))

    fh_url.close()
    fh_file.close()

    print("{} OUIs written to {}".format(len(ouis), output_file))

if __name__ == '__main__':
    main()

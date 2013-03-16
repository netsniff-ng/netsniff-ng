#!/bin/bash
# -*- coding: utf-8 -*-
#
# nacl_path.sh -- NaCl path export script
#
# Copyright (C) 2009-2011 Emmanuel Roullit <emmanuel@netsniff-ng.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.

nacl_include_path="$1"
nacl_lib_path="$2"

if test -z $nacl_include_path || test -z $nacl_lib_path; then
	echo "Please input the path where NaCl is like the following:"
	echo "./$0.sh <include_path> <lib_path>"
	exit 1
fi

echo "export NACL_INC_DIR=$nacl_include_path" >> ~/.bashrc
echo "export NACL_LIB_DIR=$nacl_lib_path" >> ~/.bashrc

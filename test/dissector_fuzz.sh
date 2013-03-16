#!/usr/bin/env bash
# -*- coding: utf-8 -*-
#
# dissector_fuzz.sh -- fuzz test netsniff-ng's dissector and pcap io methods
#		       with shitty pcap example files from the Wireshark archive
#
# Copyright (C) 2012 Daniel Borkmann <borkmann@redhat.com>
# Copyright (C) 2012 Stefan Seering <sseerin@imn.htwk-leipzig.de>
#
# Note: build and *install* the toolkit first before running this script!
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.

set -u

if [ ${BASH_VERSINFO} -lt 3 ] ; then
	echo 'Error: Your bash need to be version 3 or newer. Exiting.'
	exit 1 # operators like =~ produce errors silently in old bash versions, so exit here
fi

archive='ftp://wireshark.org/automated/captures/'
show_output='' # empty string evaluates to false
run_through='' # empty string evaluates to false
count_cores=0
count_files=0
netsniff_ng_opts=''

if [ $# -gt 0 ] ; then
	if [ "$1" = '-h' -o "$1" = '--help' -o "$1" = '--usage' ] ; then
		echo 'Usage: dissector_fuzz [-s (show netsniff-ng output, default: no)] [-r (keep running on errors, default: no)] [netsniff-ng long-args]'
		exit 0
	fi

	for opt in $@ ; do
		if [ "${opt}" = '-s' ] ; then
			show_output='true'
		elif [ "${opt}" = '-r' ] ; then
			run_through='true'
		else
			netsniff_ng_opts="${netsniff_ng_opts} ${opt}";
		fi
	done
fi

mkdir -p fuzzing
cd fuzzing
wget -r -Nc -np -nd -A.pcap "$archive"  |& grep -E "%|^--"
ulimit -c unlimited
rm -f core
for file in *.pcap
do
	echo "Testing file $file ..."
	if [ $show_output ]; then
		netsniff-ng --in "$file" "${netsniff_ng_opts}"
	else
		netsniff-ng --in "$file" "${netsniff_ng_opts}" > /dev/null
	fi
	if [ -e core ]; then
		echo "Fuck, core dumped on $file!"
		let count_cores=count_cores+1
		if [ $run_through ]; then
			rm core
		else
			exit
		fi
	fi
done

if which cowsay > /dev/null ; then
	echo_cmd='cowsay'
else
	echo_cmd='echo'
fi

${echo_cmd} 'Your fuckup Score'
echo " * tested pcaps: $count_files"
echo " * core dumps:   $count_cores"

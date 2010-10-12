#!/usr/bin/perl

use warnings;
use strict;

use Config;
use POSIX qw(strftime);

die "No version string supplied!\n" if($#ARGV == -1);

my $build = strftime "%x,%I:%M%p", gmtime;
my $version = $ARGV[0];

open(FP, "> version.h") or die "Cannot create version.h! $!\n";
print FP <<EOF;
#ifndef VERSION_H
#define VERSION_H

#define PROGNAME_STRING  "netsniff-ng"
#define VERSION_STRING   "$version"
#define BUILD_STRING     "$Config{archname}~$build"

#endif /* VERSION_H */
EOF

close(FP);

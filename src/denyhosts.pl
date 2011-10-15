#!/usr/bin/perl

#
# A tiny Perl hack that makes a country statistic of your /etc/hosts.deny
# Copyright 2011 Daniel Borkmann <borkmann@netsniff-ng.org>
# Subject to the GNU GPL, version 2.
# Debian Dep: libgeo-ip-perl
#

use warnings;
use strict;
use Geo::IP;

my %ht;
my $db = Geo::IP->new(GEOIP_MEMORY_CACHE);
open IN, "<", "/etc/hosts.deny" or die $!;
while (<IN>) {
	my $country;
	next if (/^\s*#/);
	next if (/^\s+$/);
	if (/^\s*\S+:\s*([0-9\.]+)\s*$/) {
		$country = $db->country_name_by_addr($1);
		if (defined($country)) {
			$ht{$country}++;
		}
	} elsif (/^\s*\S+:\s*(\S+)\s*$/) {
		$country = $db->country_name_by_name($1);
		if (defined($country)) {
			$ht{$country}++;
		}
	}
}
close IN;
foreach (keys(%ht)) {
	print "$_: $ht{$_}\n";
}


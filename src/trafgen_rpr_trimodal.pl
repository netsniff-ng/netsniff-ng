#!/usr/bin/perl

# netsniff-ng - the packet sniffing beast
# Copyright 2011 Daniel Borkmann <daniel@netsniff-ng.org>
# Subject to the GPL.
# Configuration file generator for trafgen.
# Generates RPR Trimodal packet distribution (64:60, 512:20, 1518:20)

use warnings;
use strict;

my %conf = (
	64   => 60,
	512  => 20,
	1518 => 20
);

print "# Run in round-robin mode with trafgen!\n";
print "# E.g. trafgen --dev eth0 --conf <this-as-file> --bind 0\n\n";

my $sum = 0;
foreach (values(%conf)) {
	$sum = $sum + $_;
}

for (my $pkt = 0; $pkt < $sum; ++$pkt) {
	my ($len, $done) = (0, 0);

	do {
		my @list = keys(%conf);
		my $index = int(rand(scalar(@list)));
		my $key = $list[$index];
		if ($conf{$key} > 0) {
			$conf{$key}--;
			$len = $key;
			$done = 1;
		}
	} while ($done == 0);

	print "\$P$pkt {\n";
	for (my $byte = 0; $byte < $len; ++$byte) {
		for (my $off = 0; $off < 13 && $byte < $len; ++$off, ++$byte) {
			my $cur = sprintf("0x%02x", int(rand(256)));
			print "$cur, ";
		}
		print "\n";
	}
	print "}\n\n";
}


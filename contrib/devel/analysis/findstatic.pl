#!/usr/bin/perl

# Andrew Tridgell <tridge@samba.org>
# Daniel Borkmann <daniel@netsniff-ng.org>

# Distributed under the terms of the GNU General Public License v2 or later.

use strict;
use warnings;

die "Usage: findstatic.pl \`find . -name \"*.o\"\`\n" if ($#ARGV == -1);

my $saved_delim = $/;
undef $/;

my $syms = `nm -o @ARGV`;
$/ = $saved_delim;

my @lines = split(/\n/s, $syms);

my %def;
my %undef;
my %stype;

my %typemap = (
	"T" => "function",
	"C" => "uninitialised variable",
	"D" => "initialised variable",
);

for (my $i = 0; $i <= $#lines; ++$i) {
	my $line = $lines[$i];
	if ($line =~ /(.*):[a-f0-9]* ([TCD]) (.*)/) {
		my $fname = $1;
		my $symbol = $3;
		push(@{$def{$fname}}, $symbol);
		$stype{$symbol} = $2;
	}
	if ($line =~ /(.*):\s* U (.*)/) {
		my $fname = $1;
		my $symbol = $2;
		push(@{$undef{$fname}}, $symbol);
	}
}

foreach my $f (keys %def) {
	my $found_one = 0;
	print "Checking $f\n";
	foreach my $s (@{$def{$f}}) {
		my $found = 0;
		foreach my $f2 (keys %undef) {
			if ($f2 ne $f) {
				foreach my $s2 (@{$undef{$f2}}) {
					if ($s2 eq $s) {
						$found = 1;
						$found_one = 1;
					}
				}
			}
		}
		if ($found == 0) {
			my $t = $typemap{$stype{$s}};
			print "  '$s' is unique to $f  ($t)\n";
		}
	}
	if ($found_one == 0) {
		print "  all symbols in '$f' are unused (main program?)\n";
	}
}

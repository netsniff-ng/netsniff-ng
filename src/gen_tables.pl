#!/usr/bin/perl

# Twofish table generator
# $Id: tables.pl,v 2.12 2001/05/21 17:38:02 ams Exp $
# Copyright 2001 Abhijit Menon-Sen <ams@wiw.org>

use strict;
use warnings;

require 'misc.pl';

my ($qtab, $mtab) = ([], []);

my @ror4 = (0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15);
my @ashx = (0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7);

# Finite field arithmetic for GF(2^8) with the modular polynomial:
# x^8 + x^6 + x^5 + x^3 + 1

my $G = 0x0169;

my @t5b  = (0, $G >> 2 & 0xff, $G >> 1 & 0xff, ($G>>1)^($G>>2)&0xff);
my @tef  = (0, $t5b[3], $t5b[2], $t5b[1]);

my $qt0 = [
	[ 8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4 ],
	[ 2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5 ],
];

my $qt1 = [
	[ 14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13 ],
	[ 1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8 ],
];

my $qt2 = [
	[ 11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1 ],
	[ 4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15 ],
];

my $qt3 = [
	[ 13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10 ],
	[ 11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10 ],
];

for my $i (0..15) {
	for my $j (0..15) {
		my $n = 16*$i+$j;
		my ($a, $b, $c, $p, $q, $r);

		$a = $i ^ $j;        $p = $ashx[$i] ^ $ror4[$j];
		$b = $qt0->[0][$a];  $q = $qt1->[0][$p];
		$c = $qt0->[1][$a];  $r = $qt1->[1][$p];

		$qtab->[0][$n] = $qt3->[0][$ashx[$b]^$ror4[$q]] << 4 | $qt2->[0][$b ^ $q];
		$qtab->[1][$n] = $qt3->[1][$ashx[$c]^$ror4[$r]] << 4 | $qt2->[1][$c ^ $r];
	}
}

for my $i (0..255) {
	my ($a, $b, $c);

	$a = $qtab->[1][$i];
	$b = $a ^ $a>>2 ^ $t5b[$a & 3];
	$c = $a ^ $a>>1 ^ $a>>2 ^ $tef[$a & 3];

	$mtab->[0][$i] = ($a + ($b << 8) + ($c << 16) + ($c << 24))."UL";
	$mtab->[2][$i] = ($b + ($c << 8) + ($a << 16) + ($c << 24))."UL";

	$a = $qtab->[0][$i];
	$b = $a ^ $a>>2 ^ $t5b[$a & 3];
	$c = $a ^ $a>>1 ^ $a>>2 ^ $tef[$a & 3];

	$mtab->[1][$i] = ($c + ($c << 8) + ($b << 16) + ($a << 24))."UL";
	$mtab->[3][$i] = ($b + ($a << 8) + ($c << 16) + ($b << 24))."UL";
}

my @q = map { join ",\n", indent(1, cwrap(76, @$_)) } @$qtab;
my @m = map { join ",\n", indent(1, cwrap(76, @$_)) } @$mtab;

(my $text = <<"TABLES") =~ s/^\| {0,3}//gm;
|   #ifndef TWOFISH_TABLES_H
|   #define TWOFISH_TABLES_H
|
|   unsigned char q[2][256] = {
|   {
|   $q[0]
|   },
|   {
|   $q[1]
|   }
|   };
|
|   uint32_t m[4][256] = {
|   {
|   $m[0]
|   },
|   {
|   $m[1]
|   },
|   {
|   $m[2]
|   },
|   {
|   $m[3]
|   }
|   };
|
|   #endif /* TWOFISH_TABLES_H */
TABLES

open F, ">twofish_tables.h" or die "twofish_tables.h: $!\n";
print F $text;
close F;


#!/usr/bin/perl

# Part of Twofish's table generator.
# $Id: misc.pl,v 1.2 2001/02/12 23:32:27 ams Exp $
# Copyright 2001 Abhijit Menon-Sen <ams@wiw.org>

use strict;
use warnings;

sub align
{
	my @aligned = ();
	my $columns = @{$_[0]};
	my @lengths = (0)x$columns;

	foreach (@_) {
		for my $i (0..$columns-1) {
			my $len = length $_->[$i];
			$lengths[$i] = $len if $len > $lengths[$i];
		}
	}

	foreach (@_) {
		my $text = "";
		for my $i (0..$columns-1) {
			$text .= $_->[$i]." "x($lengths[$i]-length($_->[$i]));
		}
		push @aligned, $text;
	}

	return @aligned;
}

sub cwrap
{
	my $n = shift;
	my ($i, $text, @text) = (0, "");

	foreach (@_) {
		if (length($text) + length($_) + 2 < $n) {
			$text .= ", $_";
			push @{$text[$i]}, $_;
		} else {
			$i++;
			$text = $_;
			push @{$text[$i]}, $_;
		}
	}

	return map { join(", ", @$_) } @text;
}

sub indent
{
	my $n = shift;

	return map { "	"x$n.$_ } @_;
}

1;

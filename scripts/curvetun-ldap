#!/usr/bin/perl

#
# curvetun_ldap.pl: a minimal curvetun/clients generator that fetches
#		    user/pubkey entries from LDAP
#
# Part of netsniff-ng.
# Copyright 2011 Daniel Borkmann <borkmann@gnumaniacs.org>
# Subject to the GNU GPL, version 2.
#
# Used attributes are 'uid' and 'public_ctun_key', but they may be changed
# int the source, of course. For Debian users: apt-get install libnet-ldap-perl
#

use strict;
use warnings;
use Getopt::Std;
use Net::LDAP;

my %opts;
my ($server, $base, $filter, $file);
my $port = 389;
my $client_name_attr = "uid";
my $client_pkey_attr = "public_ctun_key";

sub help
{
	print "\ncurvetun_ldap.pl, LDAP client file generator\n";
	print "http://www.netsniff-ng.org\n\n";
	print "Usage: curvetun_ldap.pl [options]\n";
	print "Options:\n";
	print "  -s <ldap-server> LDAP server\n";
	print "  -p <ldap-port>   LDAP port (default: 389)\n";
	print "  -b <string>      LDAP base domain\n";
	print "  -f <string>      LDAP filter expression\n";
	print "  -o <file>        Output curvetun client file\n";
	print "  -h               Show this help\n";
	print "\n";
	print "Example:\n";
	print "   curvetun_ldap.pl -s ldap.host.ch \\\n";
	print "                    -b \"l=Bar,ou=Fu,o=Host,c=CH\" \\\n";
	print "                    -f \"(cn=*)\" -o ~/.curvetun/clients\n";
	print "\n";
	print "Please report bugs to <bugs\@netsniff-ng.org>\n";
	print "Copyright (C) 2011 Daniel Borkmann <dborkma\@tik.ee.ethz.ch>,\n";
	print "Swiss federal institute of technology (ETH Zurich)\n";
	print "License: GNU GPL version 2\n";
	print "This is free software: you are free to change and redistribute it.\n";
	print "There is NO WARRANTY, to the extent permitted by law.\n\n";

	exit 0;
}

getopt('hs:p:b:f:o:', \%opts);
if ((not $opts{s} and not $opts{b} and not $opts{f}) or
    defined $opts{h}) {
	help();
}

$server = $opts{s};
$port = $opts{p} if $opts{p};
$base = $opts{b};
$filter = $opts{f};
$file = $opts{o} if $opts{o};

sub main
{
	my ($ldap, $res);
	my @entries;
	if (defined $file) {
		open FH, ">", $file or die $!;
	}
	$ldap = Net::LDAP->new($server, port => $port, timeout => 30) or die "$!";
	$ldap->bind(version => 3);
	$res = $ldap->search(filter => $filter, base => $base);
	if ($res->count == 0) {
		die "No results from LDAP query!\n";
	}
	@entries = $res->entries;
	foreach my $entry (@entries) {
		next if (not $entry->get_value($client_name_attr) or
			 not $entry->get_value($client_pkey_attr));
		if (defined $file) {
			print FH $entry->get_value($client_name_attr).";".
			         $entry->get_value($client_pkey_attr)."\n";
		} else {
			print $entry->get_value($client_name_attr).";".
			      $entry->get_value($client_pkey_attr)."\n";
		}
	}
	$ldap->unbind;
	if (defined $file) {
		close FH;
	}
}

main();


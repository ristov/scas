#!/usr/bin/perl -w
#
# scas-print 0.01 - scas-print.pl
# Copyright (C) 2020 Risto Vaarandi
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#


use strict;

use Storable;
use Getopt::Long;

use vars qw(
  $USAGE
  $attrtable
  $candidates
  %candidates
  %clusters
  $entropy
  $statefile
);

$USAGE = qq!Usage: $0 [options]

Options:

  --attrtable=<size threshold>
  --entropy=<entropy threshold>

    If the attribute hash table contains <size threshold> or more keys, and
    the normalized information entropy of key values is <entropy threshold>
    or more, print asterisk (*) instead of individual key values. Default 
    value for <size threshold> is 50, and default value for <entropy threshold>
    is 0.8.

  --statefile=<state file>

    Path to state file. This option is mandatory.

  --candidates

    Print cluster candidates instead of clusters.

  --help, -?

    Print the usage information.

  --version

    Print the version information.


The scas-print tool reads cluster and candidate information from the state 
file provided with the --statefile option, and prints clusters or candidates
in a human readable format to standard output. It is assumed that the state 
file has been produced by the scas-cluster tool.

!;


sub get_options {

  my($help, $version);

  if (!scalar(@ARGV)) {
    print $USAGE;
    exit(0);
  }

  $attrtable = 50;
  $candidates = 0;
  $entropy = 0.8;
  $help = 0;
  $version = 0;

  GetOptions( "attrtable=i" => \$attrtable,
              "entropy=f" => \$entropy,
              "statefile=s" => \$statefile,
              "candidates" => \$candidates,
              "help|?" => \$help,
              "version" => \$version );

  if ($help) {
    print $USAGE;
    exit(0);
  }

  if ($version) {
    print "scas-print version 0.01, Copyright (C) 2020 Risto Vaarandi\n";
    exit(0);
  }

  if (!defined($statefile)) {
    print STDERR "--statefile option is mandatory\n";
    exit(1);
  }

  if ($attrtable <= 0) {
    print STDERR "Invalid attribute table size $attrtable: must be positive integer\n";
    exit(1);
  }

  if ($entropy <= 0 || $entropy > 1) {
    print STDERR "Invalid attribute table entropy $entropy: must be positive real number not greater than 1\n";
    exit(1);
  }

}


sub read_state_file {

  my($ref);

  $ref = eval { retrieve($statefile) };

  if (!defined($ref)) {
    print STDERR "Can't read state file $statefile: $!\n";
    exit(1);
  }

  %candidates = %{$ref->{"Candidates"}};
  %clusters = %{$ref->{"Clusters"}};
}


sub dump_list {

  my($list) = $_[0];
  my($id, $sig, $ptr, $attr, $value, @sigs, $n, $e);

  foreach $id (keys %{$list}) {

    print "ID: $id\n";
    print "CreationTime: ", 
          scalar(localtime($list->{$id}->{"CreationTime"})), "\n";
    print "UpdateTime: ", 
          scalar(localtime($list->{$id}->{"UpdateTime"})), "\n";
    print "Matches: ", $list->{$id}->{"Matches"}, "\n";

    @sigs = ();

    foreach $sig (sort keys %{$list->{$id}->{"Signatures"}}) {
      push @sigs, $list->{$id}->{"Signatures"}->{$sig}->{"Signature"} .  
                  " ($sig)";
    }

    print "Number of signatures: ", scalar(@sigs), "\n";
    print "Signatures:\n\t", join("\n\t", @sigs), "\n";

    foreach $sig (sort keys %{$list->{$id}->{"Signatures"}}) { 

      $ptr = $list->{$id}->{"Signatures"}->{$sig};

      print "SignatureID: $sig\n";
      print "SignatureText: ", $ptr->{"Signature"}, "\n";

      foreach $attr (sort keys %{$ptr->{"Attributes"}}) {

        $n = scalar(keys %{$ptr->{"Attributes"}->{$attr}});
        $e = $ptr->{"Entropies"}->{$attr};

        print "\tAttribute $attr:\n";
        print "\tNumber of values: $n\n"; 
        print "\tEntropy: $e\n";

        if ($n >= $attrtable && $e >= $entropy) { 
          print "\t\t*\n";
          next; 
        }

        foreach $value (sort { $ptr->{"Attributes"}->{$attr}->{$b} <=>
                               $ptr->{"Attributes"}->{$attr}->{$a} }
                        keys %{$ptr->{"Attributes"}->{$attr}}) {
          print "\t\t", $value, " = ", 
                        $ptr->{"Attributes"}->{$attr}->{$value}, "\n";
        }

      }

    }

    print "\n";
  }
}


binmode(STDOUT, ":encoding(UTF-8)");

get_options();

read_state_file();

if ($candidates) {

  print "Total number of candidates: ", scalar(keys %candidates), "\n\n";
  dump_list(\%candidates);

} else {

  print "Total number of clusters: ", scalar(keys %clusters), "\n\n";
  dump_list(\%clusters);

}


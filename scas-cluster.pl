#!/usr/bin/perl -w
#
# scas-cluster 0.03 - scas-cluster.pl
# Copyright (C) 2020-2022 Risto Vaarandi
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

use POSIX qw(:errno_h);
use JSON;
use Storable;
use Sys::Syslog;
use Getopt::Long;


use vars qw(
  $USAGE
  $alpha
  $attrkey_init_val
  $blocksize
  $candidate_dumpfile
  $candidate_timeout
  %candidates
  $cluster_dumpfile
  $cluster_timeout
  %clusters
  $dumpdata
  $dumpdir
  $dumpstate
  $expsimilarity
  $input_buffer
  $last_maintenance
  $max_attrtable_entropy
  $max_attrtable_size
  $max_candidates
  $max_clusters
  $max_candidate_age
  $min_attrkey_val
  $output_fh
  $output_file
  $pid_file
  $reopen_output
  $scantime
  $sleeptime
  $statefile
  $syslog_facility
  $syslog_level
  $syslog_tag
  $terminate
);


$USAGE = qq!Usage: $0 [options]

Options:

  --max-candidate-age=<max candidate age> 

    If cluster candidate age exceeds <max candidate age> seconds, promote 
    the candidate to cluster. Default value for <max candidate age> is 
    86400 seconds (1 day).

  --candidate-timeout=<candidate timeout>

    If cluster candidate has not seen matches during more than 
    <candidate timeout> seconds, drop the candidate. Default value for 
    <candidate timeout> is 3600 seconds (1 hour).

  --cluster-timeout=<cluster timeout>

    If cluster has not seen matches during more than <cluster timeout> 
    seconds, drop the cluster. Default value for <cluster timeout> is 
    604800 seconds (1 week).

  --alpha=<alpha>

    The value of alpha for EWMA calculations. This option is mandatory.
 
  --attrkey-init-value=<init value>

    Initialize the value of new attribute hash table key to <init value>.
    Default value for <init value> is (1 / (2/alpha - 1)).

  --min-attrkey-value=<value threshold>

    If the value of attribute hash table key drops below <value threshold>,
    the key is removed from attribute hash table, in order to reduce memory
    consumption of attribute hash tables. Default value for <value threshold> 
    is (0.2 * (1 / (2/alpha - 1))).

  --max-attrtable-size=<size threshold>
  --max-attrtable-entropy=<entropy threshold>

    If the attribute hash table contains <size threshold> or more keys, and
    the normalized information entropy of key values is <entropy threshold>
    or more, the attribute hash table produces a full match during alert
    clustering process. Default value for <size threshold> is 50, and default 
    value for <entropy threshold> is 0.8.

  --expsimilarity, --noexpsimilarity

    In addition to finding regular similarity for each incoming alert group,
    include the result from experimental similarity functions in output
    alert groups. Default is --noexpsimilarity.

  --dumpdir=<dump directory>

    On the reception of USR1 signal, create dump files for candidates
    and clusters in directory <dump directory>. Default value for 
    <dump directory> is /tmp.

  --statefile=<state file>

    If this command line option is provided, the program writes its
    internal state to <state file> on termination, and restores 
    candidates and clusters from <state file> when it starts. The state 
    file <state file> is also produced on the reception of USR2 signal.

  --sleeptime=<sleep time>

    Sleep time in seconds -- if no new syslog messages were read from
    standard input, the program sleeps for <sleep time> seconds.
    Default value for <sleep time> is 1.0 seconds.

  --blocksize=<block size>

    IO block size in bytes. Default value for <block size> is 16384 bytes.

  --scantime=<scan time>

    After each <scan time> seconds, scan all data structures for
    housekeeping purposes. Default value for <scan time> is 10 seconds.

  --output=<output file>

    Write clustering results to <output file>, creating the file if it does 
    not exist. Each clustered alert group is in JSON format and is written 
    as a single line to the file. Note that on the reception of HUP signal, 
    the file will be reopened (and recreated if it no longer exists, in order 
    to facilitate log rotation). Specifying - for <output file> denotes 
    standard output.

  --syslog-tag=<tag>

    Log clustering results to syslog with syslog tag <tag>.
    Without this option, clustering results are not logged to syslog.

  --syslog-facility=<facility>

    If clustering results are logged to syslog, use syslog facility <facility>.
    Default value for <facility> is user.

  --syslog-level=<level>

    If clustering results are logged to syslog, use syslog level <level>.
    Default value for <level> is info.

  --pid=<pid file>

    Store process ID to file <pid file>.

  --help, -?

    Print the usage information.

  --version

    Print the version information.


The scas-cluster tool implements a stream clustering algorithm for incoming
IDS alert groups received from the scas-group tool. The scas-cluster tool 
maintains centroids for detected clusters and cluster candidates, with each 
centroid being identified by a sequence of sorted signature IDs. Therefore, 
each centroid represents a specific attack type that manifests itself by 
alerts triggered by the given combination of signatures.

For each incoming alert group, all signature IDs are extracted from the group
and sorted. Resulting sequence C is then used for looking up the cluster with 
the same ID. If the cluster with ID of C exists, a similarity (from range 0..1)
with the cluster centroid is calculated, and alert group is merged with the 
cluster centroid. If the cluster C does not exist but the cluster candidate 
with ID of C is found, alert group is merged with the candidate centroid and 
similarity is set to -1. If the cluster candidate C does not exist, a new 
candidate with ID of C is created and similarity is set to -1. Finally, the
alert group is written to outputs in JSON format with its similarity score.

After each N seconds given with --scantime=N option, a maintenance procedure 
is executed which drops clusters and cluster candidates that have not been 
updated by merging during last K and L seconds respectively, with K and L 
being provided with --cluster-timeout=K and --candidate-timeout=L options.
If a cluster candidate has stayed in memory for more than M seconds without 
being dropped (M is given with --max-candidate-age=M option), it will be 
promoted to cluster. Therefore, the maintenance procedure ensures that the 
stream clustering algorithm is able to adjust to environment changes, creating 
clusters for new frequent alert patterns and dropping clusters after 
corresponding patterns have become infrequent.

For a cluster and cluster candidate centroid, the clustering module employs 
the following data structure -- for each attribute of each signature from
the centroid ID, there is an attribute hash table which stores recently seen 
attribute values as keys. 
For each attribute table key, the corresponding value ranges from 0 to 1 and 
represents the frequency estimate the given key (attribute value) has been 
seen in past alert groups. 
For example, if the attribute table for the InternalIP attribute holds the 
key-value pairs 192.168.1.1=0.75 and 192.168.1.2=0.5, then about 75% and 50% 
of previously seen alert groups have contained the InternalIP attribute value 
192.168.1.1 and 192.168.1.2 respectively.
For implementing frequency tracking in a memory efficient way, each frequency
value in the attribute table is maintained as an exponentially weighted moving 
average (EWMA) which is calculated recursively for time series X_1, X_2, ...:

EWMA_1 = X_1,  if i = 1
EWMA_i = A * X_i  +  (1 - A) * EWMA_(i-1),  if i > 1

The input parameter A (positive real number not greater than 1) is provided 
with the --alpha=A option. EWMA is known to estimate the average of last
(2/A)-1 observations from time series X_1, X_2, ...

When a new candidate centroid is created for an alert group, attribute tables 
are created for each signature in the alert group. Values for each attribute 
are then extracted from the alert group, and keys are created from values in 
relevant attribute tables, initializing them to 1.
When an alert group is merged with a candidate or cluster centroid, keys in 
attribute tables are updated with either 1 or 0 according to above EWMA 
calculation scheme, depending on whether a given attribute value is present 
in the alert group. If the alert group has an attribute value that is not 
present as a key in corresponding attribute table, new key is created and 
initialized to I (provided with --attrkey-init-value=I option).

Before an alert group is merged with its cluster centroid, the similarity 
between the alert group and its centroid is calculated. This involves 
extracting all values for each attribute of each signature from the alert 
group, and using them as keys for retrieving frequency values from 
corresponding attribute tables. If the key is not present, frequency value 
of 0 is assumed. The similarity is then calculated as an average of frequency 
values over all attributes and signatures. 

For example, suppose that the alert group comes in which contains data for 
two signatures S1 and S2 that have two attributes ExternalIP and InternalIP.
Also suppose that for signature S1, values 192.168.1.1 and 192.168.1.2 are 
present for InternalIP attribute in the alert group, while for ExternalIP
attribute the values are 10.1.1.1 and 10.1.1.2. For signature S2, InternalIP
and ExternalIP attributes have single values 192.168.1.3 and  10.1.1.3
respectively. Finally, suppose the cluster centroid with the ID of (S1,S2)
holds the attribute tables with the following key-value pairs:

S1->InternalIP
  192.168.1.1 = 0.9
  192.168.1.2 = 0.5

S1->ExternalIP
  10.1.1.1 = 0.3
  10.1.1.2 = 0.2
  10.1.1.3 = 0.1

S2->InternalIP
  192.168.1.3 = 0.6
  192.168.1.4 = 0.7

S2->ExternalIP
  10.1.1.1 = 0.8

For two attributes of the S1 signature in the alert group, the similarity is
calculated as follows:

((0.9 + 0.5) / 2 + (0.3 + 0.2) / 2) / 2 = 0.475

For two attributes of the S2 signature in the alert group, the similarity is
calculated as follows:

(0.6 + 0) / 2 = 0.3

For the entire alert group of two signatures, the similarity is calculated
as follows:

(0.475 + 0.3) / 2 = 0.3875

For an attribute that can assume a large number of different values with 
an equal probability, the attribute table will contain large number of keys 
with small values which will always yield a low similarity score for the  
attribute. However, since no attribute value can be regarded as unusual,
a high similarity score should be returned instead for all values.
For detecting such cases, normalized information entropy is calculated for
frequency values in each attribute table. If V_1, ..., V_k are frequency
values of attribute table, normalized vector (X_1, ..., X_k) is found for 
them, where X_i = V_i / (V_1 + ... + V_k). Normalized information entropy 
for attribute table with values V_1, ..., V_k is then calculated as follows: 

-(X_1 * log(X_1) + ... + X_k * log(X_k)) / log(k),  if k > 1
-1,  if k = 1

Note that normalized information entropy ranges from 0 to 1 for k > 1,
with values close to 1 indicating that V_1, ..., V_k are similar.
If the table contains S or more keys and its information entropy is E or 
more, similarity 1 is returned for the given attribute (S and E are given 
with --max-attrtable-size=S and --max-attrtable-entropy=E options).

For instance, if the attribute table S1->ExternalIP in the above example 
would contain S key-value pairs with normalized information entropy of E, 
the similarity for two attributes of the S1 signature would be:

(1 + (0.3 + 0.2) / 2) / 2 = 0.625

For the entire alert group of two signatures, the similarity would be:

(0.625 + 0.3) / 2 = 0.4625

The similarity between alert group and its cluster centroid ranges from 0 
to 1, with values close to 1 indicating that the attribute values of the alert 
group have been frequently seen in the past, while lower similarity values 
indicate the presence of unusual attribute values. Since the similarity score
of -1 is assigned to outlier alert groups, alert groups with lower similarity 
scores under some user-defined threshold (e.g., 0.5) represent unusual alert 
groups which deserve closer attention from human analysts.

After the similarity score has been calculated for the alert group, it
will be written together with its similarity score to all outputs in JSON 
format. The outputs are configured with --output and --syslog-tag options.

Also, detected cluster centroids represent frequent alert patterns, and
in order to output them in human readable format, send the scas-cluster
process the USR1 signal (both the cluster and candidate centroids will be
written to the directory provided with --dumpdir option). Note that when 
the scas-cluster process receives the USR2 signal and has been started with 
--statefile option, it will create its state file, and cluster centroid 
information can be printed from the state file with the scas-print tool.

!;


#####################################################################


# function for processing command line options

sub get_options {

  my($help, $version);

  if (!scalar(@ARGV)) {
    print $USAGE;
    exit(0);
  }

  $max_candidate_age = 86400;
  $candidate_timeout = 3600;
  $cluster_timeout = 604800;
  $max_attrtable_size = 50;
  $max_attrtable_entropy = 0.8;
  $expsimilarity = 0;
  $dumpdir = "/tmp";
  $sleeptime = 1;
  $blocksize = 16384;
  $scantime = 10;
  $output_file = undef;
  $syslog_tag = undef;
  $syslog_facility = "user";
  $syslog_level = "info";
  $help = 0;
  $version = 0;

  GetOptions( "max-candidate-age=i" => \$max_candidate_age,
              "candidate-timeout=i" => \$candidate_timeout,
              "cluster-timeout=i" => \$cluster_timeout,
              "alpha=f" => \$alpha,
              "attrkey-init-value=f" => \$attrkey_init_val,
              "min-attrkey-value=f" => \$min_attrkey_val,
              "max-attrtable-size=i" => \$max_attrtable_size,
              "max-attrtable-entropy=f" => \$max_attrtable_entropy,
              "expsimilarity!" => \$expsimilarity,
              "dumpdir=s" => \$dumpdir,
              "statefile=s" => \$statefile,
              "sleeptime=f" => \$sleeptime,
              "blocksize=i" => \$blocksize,
              "scantime=i" => \$scantime,
              "output=s" => \$output_file,
              "syslog-tag=s" => \$syslog_tag,
              "syslog-facility=s" => \$syslog_facility,
              "syslog-level=s" => \$syslog_level,
              "pid=s" => \$pid_file,
              "help|?" => \$help,
              "version" => \$version );

  if ($help) {
    print $USAGE;
    exit(0);
  }

  if ($version) {
    print "scas-cluster version 0.03, Copyright (C) 2020-2022 Risto Vaarandi\n";
    exit(0);
  }

  if ($max_candidate_age <= 0) {
    print STDERR "Invalid max candidate age $max_candidate_age: must be positive integer\n";
    exit(1);
  }

  if ($candidate_timeout <= 0) {
    print STDERR "Invalid candidate timeout $candidate_timeout: must be positive integer\n";
    exit(1);
  }

  if ($cluster_timeout <= 0) {
    print STDERR "Invalid cluster timeout $cluster_timeout: must be positive integer\n";
    exit(1);
  }

  if (!defined($alpha)) {
    print STDERR "--alpha option is mandatory\n";
    exit(1);
  }

  if ($alpha <= 0 || $alpha > 1) {
    print STDERR "Invalid alpha $alpha: must be positive real number not greater than 1\n";
    exit(1);
  }

  if (!defined($attrkey_init_val)) {
    $attrkey_init_val = 1 / (2/$alpha - 1);
  }

  if ($attrkey_init_val <= 0 || $attrkey_init_val > 1) {
    print STDERR "Invalid attribute key init value $attrkey_init_val: must be positive real number not greater than 1\n";
    exit(1);
  }

  if (!defined($min_attrkey_val)) {
    $min_attrkey_val = 0.2 * (1 / (2/$alpha - 1));
  }

  if ($min_attrkey_val <= 0 || $min_attrkey_val > 1) {
    print STDERR "Invalid min attribute key value $min_attrkey_val: must be positive real number not greater than 1\n";
    exit(1);
  }

  if ($min_attrkey_val > $attrkey_init_val) {
    print STDERR "Invalid min attribute key value $min_attrkey_val: must not be greater than attribute key init value (current setting --attrkey-init-value=$attrkey_init_val)\n";
    exit(1);
  }

  if ($max_attrtable_size <= 0) {
    print STDERR "Invalid max attribute table size $max_attrtable_size: must be positive integer\n";
    exit(1);
  }

  if ($max_attrtable_entropy <= 0 || $max_attrtable_entropy > 1) {
    print STDERR "Invalid max attribute table entropy $max_attrtable_entropy: must be positive real number not greater than 1\n";
    exit(1);
  }

  if ($sleeptime <= 0) {
    print STDERR "Invalid sleep time $sleeptime: must be positive real number\n";
    exit(1);
  }

  if ($blocksize <= 0) {
    print STDERR "Invalid IO block size $blocksize: must be positive integer\n";
    exit(1);
  }

  if ($scantime <= 0) {
    print STDERR "Invalid scan time $scantime: must be positive integer\n";
    exit(1);
  }

  if (!defined($output_file) && !defined($syslog_tag)) {
    print STDERR "Defining at least one output with --output or --syslog-tag option is mandatory\n";
    exit(1);
  }
}


# function for updating the information entropy of attribute table

sub update_entropy {

  my($ptr, $attr) = @_;
  my($value, @values, $n, $sum, $entropy, $p);

  @values = values %{$ptr->{"Attributes"}->{$attr}};

  $sum = 0;
  foreach $value (@values) { $sum += $value; }

  $n = scalar(@values);

  if ($n > 1 && $sum != 0) {

    $entropy = 0;

    foreach $value (@values) {
      $p = $value / $sum;
      if ($p != 0) { $entropy -= $p * log($p); }
    }
        
    $entropy /= log($n);

  } else { $entropy = -1; }
  
  $ptr->{"Entropies"}->{$attr} = $entropy;
}


# function for updating all information entropies of the centroid

sub find_entropies {

  my($elem) = $_[0];
  my($ptr, $sig, $attr);

  foreach $sig (keys %{$elem->{"Signatures"}}) {

    $ptr = $elem->{"Signatures"}->{$sig};

    if (!exists($ptr->{"Entropies"})) { $ptr->{"Entropies"} = {}; }

    foreach $attr (keys %{$ptr->{"Attributes"}}) { 

      update_entropy($ptr, $attr);
    }

  } 
}


# function for calculating similarity between alert group and its cluster;
# the similarity will be stored under Similarity field in alert group
# data structure, while Similarity2 represents an additional experimental
# similarity function which has to be enabled with --expsimilarity option

sub find_similarity {

  my($ref) = $_[0];
  my(@id, $id, $ptr, $ptr2);
  my($sig, $attr, $value, $cluster_valuecount, $attr_entropy);
  my($sigscore, $sigscore2, $sigcount); 
  my($attrscore, $attrscore2, $attrcount); 
  my($valuescore, $valuescore2, $valuecount);
  my($score, $score2);

  # find the cluster ID for alert group

  @id = sort keys %{$ref->{"Signatures"}};

  $id = join(" ", @id);
  
  # if alert group does not have a cluster, set similarity to -1

  if (!exists($clusters{$id})) {

    $ref->{"Similarity"} = -1;
    $ref->{"Similarity2"} = -1;

    return;
  }

  # if alert group's cluster is stale, drop it and set similarity to -1

  if (time() - $clusters{$id}->{"UpdateTime"} > $cluster_timeout) {

    delete $clusters{$id};

    $ref->{"Similarity"} = -1;
    $ref->{"Similarity2"} = -1;

    return;
  }

  # find similarity between alert group and its cluster centroid

  $sigscore = 0;
  $sigscore2 = 0;
  $sigcount = scalar(@id);

  $ref->{"AttrSimilarity"} = {};
  $ref->{"AttrSimilarity2"} = {};

  foreach $sig (keys %{$ref->{"Signatures"}}) {

    $ptr = $ref->{"Signatures"}->{$sig};
    $ptr2 = $clusters{$id}->{"Signatures"}->{$sig};

    $attrscore = 0;
    $attrscore2 = 0;
    $attrcount = scalar(keys %{$ptr->{"Attributes"}});

    $ref->{"AttrSimilarity"}->{$sig} = [];
    $ref->{"AttrSimilarity2"}->{$sig} = [];

    foreach $attr (keys %{$ptr->{"Attributes"}}) {

      # if the centroid lacks an attribute that is present in alert group,
      # skip similarity calculation for the attribute (should never happen)

      if (!exists($ptr2->{"Attributes"}->{$attr})) {
        --$attrcount;
        next;
      }

      # check if centroid attribute table holds a larger number of key-value
      # pairs, with values having a high normalized information entropy

      $cluster_valuecount = scalar(keys %{$ptr2->{"Attributes"}->{$attr}});
      $attr_entropy = $ptr2->{"Entropies"}->{$attr};

      if ($cluster_valuecount >= $max_attrtable_size && 
          $attr_entropy >= $max_attrtable_entropy) {

        ++$attrscore;
        ++$attrscore2;

        push @{$ref->{"AttrSimilarity"}->{$sig}}, "$attr=1";
        push @{$ref->{"AttrSimilarity2"}->{$sig}}, "$attr=1";

        next;
      }

      $valuescore = 0;
      $valuescore2 = 0;
      $valuecount = scalar(keys %{$ptr->{"Attributes"}->{$attr}});

      # if the alert group attribute lacks values, skip similarity 
      # calculation for the attribute, in order to avoid division by 0

      if (!$valuecount) {
        --$attrcount;
        next;
      }

      # find similarity for individual attribute

      foreach $value (keys %{$ptr->{"Attributes"}->{$attr}}) {

        if (exists($ptr2->{"Attributes"}->{$attr}->{$value})) { 
          $valuescore += $ptr2->{"Attributes"}->{$attr}->{$value};
          ++$valuescore2; 
        }
      }

      $score = $valuescore / $valuecount;
      $score2 = $valuescore2 / $valuecount;

      $attrscore += $score; 
      $attrscore2 += $score2; 

      push @{$ref->{"AttrSimilarity"}->{$sig}}, "$attr=$score";
      push @{$ref->{"AttrSimilarity2"}->{$sig}}, "$attr=$score2";
    }

    $sigscore += $attrscore / $attrcount; 
    $sigscore2 += $attrscore2 / $attrcount; 
  } 

  # find similarity for the entire alert group

  $sigscore /= $sigcount;
  $sigscore2 /= $sigcount;

  $ref->{"Similarity"} = $sigscore;
  $ref->{"Similarity2"} = $sigscore2;
}


# function for creating JSON string for outputting the alert group

sub format_alert_group {

  my($ref) = $_[0];
  my($ref2, $sig, $attr, $ptr, $sigdata, $json);

  # create an output JSON data structure for alert group (force numeric 
  # context for numbers, in order to ensure their proper appearance in JSON)

  $ref2 = { "CreationTime" => $ref->{"CreationTime"} + 0,
            "CreationTimeText" => scalar(localtime($ref->{"CreationTime"})),
            "EventCount" => $ref->{"Events"} + 0,
            "SignatureCount" => scalar(keys %{$ref->{"Signatures"}}),
            "Similarity" => $ref->{"Similarity"} + 0,
            "Similarity_int" => int($ref->{"Similarity"} * 100),
            "AlertData" => [],
            "Alerts" => [] };

  if ($expsimilarity) {

    $ref2->{"Similarity2"} = $ref->{"Similarity2"} + 0;
    $ref2->{"Similarity2_int"} = int($ref->{"Similarity2"} * 100);
  }

  foreach $sig (sort keys %{$ref->{"Signatures"}}) {

    # store data for each signature in the alert group to JSON
    # ($sigdata is a reference to data that is stored to JSON)

    $ptr = $ref->{"Signatures"}->{$sig};

    push @{$ref2->{"Alerts"}}, $ptr->{"Signature"};

    $sigdata = { "SignatureText" => $ptr->{"Signature"},
                 "SignatureID" => $sig };

    # if the attribute is basic that every signature has (Proto, IntIP, 
    # ExtIP, IntPort and ExtPort), store attribute values to JSON

    foreach $attr (keys %{$ptr->{"Attributes"}}) {

      if ($attr eq "Proto" || $attr eq "IntIP" || $attr eq "ExtIP" ||
          $attr eq "IntPort" || $attr eq "ExtPort") {

        $sigdata->{$attr} = [ keys %{$ptr->{"Attributes"}->{$attr}} ];
      }
    }

    # store external IP address as a separate JSON field

    if (!exists($ref2->{"ExtIP"})) {
      $ref2->{"ExtIP"} = $sigdata->{"ExtIP"}->[0];
    }

    # store similarity data for individual attributes to JSON
    # (not done if alert group is an outlier, since for outliers
    # there are no similarity data for individual attributes)

    if ($ref->{"Similarity"} != -1) {

      $sigdata->{"AttrSimilarity"} = 
                join(" ", sort @{$ref->{"AttrSimilarity"}->{$sig}});

      if ($expsimilarity) {

        $sigdata->{"AttrSimilarity2"} = 
                  join(" ", sort @{$ref->{"AttrSimilarity2"}->{$sig}});
      }
    }

    push @{$ref2->{"AlertData"}}, $sigdata;
  }

  # create a textual string from all signature texts, and store it to JSON

  $ref2->{"AlertGroup"} = join(", ", @{$ref2->{"Alerts"}});

  # convert stored data to JSON string (canonical-option forces the sorting 
  # of field names in the string), and return the JSON string

  eval { $json = JSON->new->utf8->canonical->encode($ref2); };

  if ($@) {
    print STDERR "Can't create JSON data structure: $@\n";
    return undef;
  }

  return $json;
}


# function for merging the alert group with cluster/candidate centroid

sub update_element {

  my($elem, $ref) = @_;
  my($sig, $attr, $value, $diff, %updated);
  my($ptr, $ptr2);

  # update cluster or cluster candidate with alert group data

  foreach $sig (keys %{$elem->{"Signatures"}}) {

    $ptr = $elem->{"Signatures"}->{$sig};
    $ptr2 = $ref->{"Signatures"}->{$sig};

    foreach $attr (keys %{$ptr->{"Attributes"}}) {

      %updated = ();

      # check all key-value pair in the attribute table

      foreach $value (keys %{$ptr->{"Attributes"}->{$attr}}) {

        # if the corresponding attribute in the alert group has the value 
        # which equals to key, update ewma-based value of attribute table 
        # key with 1, otherwise update it with 0

        if (exists($ptr2->{"Attributes"}->{$attr}->{$value})) {

          $diff = 1 - $ptr->{"Attributes"}->{$attr}->{$value};

        } else {

          $diff = -$ptr->{"Attributes"}->{$attr}->{$value};
        }

        $ptr->{"Attributes"}->{$attr}->{$value} += $alpha * $diff;
        $updated{$value} = 1;
      }

      # if the alert group attribute has values for which there are
      # no keys in the attribute table, create keys for such values

      foreach $value (keys %{$ptr2->{"Attributes"}->{$attr}}) {

        if (!exists($updated{$value})) { 
          $ptr->{"Attributes"}->{$attr}->{$value} = $attrkey_init_val;
        }
      }

    }

  } 

  $elem->{"UpdateTime"} = time();

  ++$elem->{"Matches"};
}


# function for processing the alert group after similarity calculation

sub update_lists {

  my($ref) = $_[0];
  my(@id, $id, $time);
  my($sig, $attr, $value, $ptr);

  # find the cluster ID for alert group

  @id = sort keys %{$ref->{"Signatures"}};

  $id = join(" ", @id);
  
  $time = time();

  # if cluster ID refers to a stale cluster, drop the cluster

  if (exists($clusters{$id}) &&
      $time - $clusters{$id}->{"UpdateTime"} > $cluster_timeout) {

    delete $clusters{$id};
  }

  # if cluster ID refers to a cluster candidate which has reached 
  # the maximum age, promote the candidate to cluster

  if (exists($candidates{$id}) &&
      $time - $candidates{$id}->{"CreationTime"} > $max_candidate_age) {

    $clusters{$id} = $candidates{$id};
    delete $candidates{$id};
  }

  # check if after previous steps the cluster ID refers to a cluster or
  # cluster candidate, and update the corresponding centroid; if neither
  # cluster nor candidate exists, create a new candidate

  if (exists($clusters{$id})) {

    update_element($clusters{$id}, $ref);

    find_entropies($clusters{$id});
 
  } elsif (exists($candidates{$id})) {

    update_element($candidates{$id}, $ref);

    find_entropies($candidates{$id});

  } else {

    $candidates{$id} = { "CreationTime" => $time, 
                         "UpdateTime" => $time,
                         "Matches" => 1,
                         "Signatures" => $ref->{"Signatures"} };

    foreach $sig (keys %{$candidates{$id}->{"Signatures"}}) {

      $ptr = $candidates{$id}->{"Signatures"}->{$sig};

      foreach $attr (keys %{$ptr->{"Attributes"}}) {

        foreach $value (keys %{$ptr->{"Attributes"}->{$attr}}) {
          $ptr->{"Attributes"}->{$attr}->{$value} = 1;
        }

      }
    }

    find_entropies($candidates{$id});
  }

  # if the number of clusters or candidates exceeds the previously 
  # recorded maximum, update the maximum

  if ($max_clusters < scalar(keys %clusters)) {
    $max_clusters = scalar(keys %clusters);
  }

  if ($max_candidates < scalar(keys %candidates)) {
    $max_candidates = scalar(keys %candidates);
  }
}


# function for dropping key-value pairs from attribute tables 
# that have values smaller than configured threshold

sub drop_attributes {

  my($elem) = $_[0];
  my($sig, $ptr, $attr, $value, $ret);

  foreach $sig (keys %{$elem->{"Signatures"}}) {

    $ptr = $elem->{"Signatures"}->{$sig};

    foreach $attr (keys %{$ptr->{"Attributes"}}) {

      $ret = 0;

      foreach $value (keys %{$ptr->{"Attributes"}->{$attr}}) {

        if ($ptr->{"Attributes"}->{$attr}->{$value} < $min_attrkey_val) {
          delete $ptr->{"Attributes"}->{$attr}->{$value};
          $ret = 1;
        }
      }

      if ($ret) { update_entropy($ptr, $attr); }
    }

  }
}


# function for maintaining lists of cluster and candidate centroids

sub maintain_lists {

  my($time, $id);

  $time = time();

  # maintain the list of candidate centroids

  foreach $id (keys %candidates) {

    # drop the candidate if it is stale

    if ($time - $candidates{$id}->{"UpdateTime"} > $candidate_timeout) {
      delete $candidates{$id};
      next;
    }

    # if the candidate has reached the maximum age, promote it to cluster

    if ($time - $candidates{$id}->{"CreationTime"} > $max_candidate_age) {

      $clusters{$id} = $candidates{$id};
      delete $candidates{$id};
      next;
    }

    # scan the attribute tables of the candidate, 
    # and remove key-value pairs with too small values

    drop_attributes($candidates{$id});
  } 

  # maintain the list of cluster centroids

  foreach $id (keys %clusters) {

    # drop the cluster if it is stale

    if ($time - $clusters{$id}->{"UpdateTime"} > $cluster_timeout) {
      delete $clusters{$id};
      next;
    }

    # scan the attribute tables of the cluster, 
    # and remove key-value pairs with too small values

    drop_attributes($clusters{$id});
  }

  # if the number of clusters or candidates exceeds the previously 
  # recorded maximum, update the maximum

  if ($max_clusters < scalar(keys %clusters)) {
    $max_clusters = scalar(keys %clusters);
  }

  if ($max_candidates < scalar(keys %candidates)) {
    $max_candidates = scalar(keys %candidates);
  }
}


# function for writing cluster/candidate cenroid to a file

sub dump_list {

  my($handle, $list) = @_;
  my($id, $sig, $ptr, $attr, $value, @sigs);

  foreach $id (keys %{$list}) {

    print $handle "ID: $id\n";
    print $handle "CreationTime: ", 
                  scalar(localtime($list->{$id}->{"CreationTime"})), "\n";
    print $handle "UpdateTime: ", 
                  scalar(localtime($list->{$id}->{"UpdateTime"})), "\n";
    print $handle "Matches: ", $list->{$id}->{"Matches"}, "\n";

    @sigs = ();

    foreach $sig (sort keys %{$list->{$id}->{"Signatures"}}) {
      push @sigs, $list->{$id}->{"Signatures"}->{$sig}->{"Signature"} . 
                  " ($sig)";
    }

    print $handle "Number of signatures: ", scalar(@sigs), "\n";
    print $handle "Signatures:\n\t", join("\n\t", @sigs), "\n";

    foreach $sig (sort keys %{$list->{$id}->{"Signatures"}}) { 

      $ptr = $list->{$id}->{"Signatures"}->{$sig};

      print $handle "SignatureID: $sig\n";
      print $handle "SignatureText: ", $ptr->{"Signature"}, "\n";

      foreach $attr (sort keys %{$ptr->{"Attributes"}}) {

        print $handle "\tAttribute $attr:\n";
        print $handle "\tNumber of values: ", 
                      scalar(keys %{$ptr->{"Attributes"}->{$attr}}), "\n";
        print $handle "\tEntropy: ", $ptr->{"Entropies"}->{$attr}, "\n";

        foreach $value (sort { $ptr->{"Attributes"}->{$attr}->{$b} <=>
                               $ptr->{"Attributes"}->{$attr}->{$a} }
                        keys %{$ptr->{"Attributes"}->{$attr}}) {
          print $handle "\t\t", $value, " = ", 
                        $ptr->{"Attributes"}->{$attr}->{$value}, "\n";
        }

      }

    }

    print $handle "\n";
  }
}


# function for writing all cluster and candidate centroids to a file

sub dump_lists {

  my($handle);

  if (!open($handle, ">:encoding(UTF-8)", $candidate_dumpfile)) {
    print STDERR "Can't open dump file $candidate_dumpfile: $!\n";
    exit(1);
  }

  print $handle "Candidates (total ", scalar(keys %candidates), 
                ", max $max_candidates):\n\n";
  dump_list($handle, \%candidates);

  close($handle);

  if (!open($handle, ">:encoding(UTF-8)", $cluster_dumpfile)) {
    print STDERR "Can't open dump file $cluster_dumpfile: $!\n";
    exit(1);
  }

  print $handle "Clusters (total ", scalar(keys %clusters), 
                ", max $max_clusters):\n\n";
  dump_list($handle, \%clusters);

  close($handle);
}


# function for reading the state file with centroid data structures

sub read_state_file {

  my($ref);

  $ref = eval { retrieve($statefile) };

  if (!defined($ref)) {
    print STDERR "Can't read state file $statefile: $!\n";
    return;
  }

  %candidates = %{$ref->{"Candidates"}};
  %clusters = %{$ref->{"Clusters"}};
}


# function for producing the state file with centroid data structures

sub write_state_file {

  my($ref, $ret);

  $ref = { "Candidates" => \%candidates, "Clusters" => \%clusters };

  $ret = eval { store($ref, $statefile) };

  if (!defined($ret)) {
    print STDERR "Can't write state file $statefile: $!\n";
    exit(1);
  }
}


# function for reading a line from standard input

sub read_line {

  my($pos, $line, $rin, $ret, $n);

  # if input buffer contains a full line, return it

  $pos = index($input_buffer, "\n");

  if ($pos != -1) {
    $line = substr($input_buffer, 0, $pos);
    substr($input_buffer, 0, $pos + 1) = "";
    return $line;
  }

  for (;;) {

    # check with select(2) if new input bytes are available

    $rin = '';
    vec($rin, fileno(STDIN), 1) = 1;
    $ret = select($rin, undef, undef, 0);

    # if select(2) failed and it was interrupted by signal, retry select(2),
    # otherwise terminate the program 

    if (!defined($ret) || $ret < 0) { 
      if ($! == EINTR) { next; }
      print STDERR "IO error when polling standard input: $!\n";
      exit(1);
    }

    # if select(2) reported that no new bytes are available, return undef

    if ($ret == 0) { return undef; }

    # read new bytes from standard input with read(2)

    $n = sysread(STDIN, $input_buffer, $blocksize, length($input_buffer));

    # if read(2) failed and it was interrupted by signal, retry polling
    # with select(2) and reading, otherwise terminate the program 

    if (!defined($n)) {
      if ($! == EINTR) { next; }
      print STDERR "IO error when reading from standard input: $!\n";
      exit(1);
    }

    # if select(2) reported the availability of new bytes but read(2)
    # returned 0 bytes, EOF has been reached, and therefore raise the
    # terminate flag and return undef

    if ($n == 0) { 
      $terminate = 1;
      return undef; 
    }

    # if input buffer contains a full line, return it, otherwise continue 
    # with the polling and reading loop for getting the rest of the line

    $pos = index($input_buffer, "\n");

    if ($pos != -1) {
      $line = substr($input_buffer, 0, $pos);
      substr($input_buffer, 0, $pos + 1) = "";
      return $line;
    }

  }
}


# function for opening all configured outputs

sub open_outputs {

  if (defined($output_file)) {

    if ($output_file ne "-") {

      while (!open($output_fh, ">>", $output_file)) {
        if ($! == EINTR)  { next; }
        print STDERR "Can't open output file $output_file for writing: $!\n";
        exit(1);
      }

    } else {

      while (!open($output_fh, ">&", STDOUT)) {
        if ($! == EINTR)  { next; }
        print STDERR "Can't dup standard output: $!\n";
        exit(1);
      }
    }

    select($output_fh);
    $| = 1;
    select(STDOUT);
  }

  if (defined($syslog_tag)) {

    eval { openlog($syslog_tag, "pid", $syslog_facility) };

    if ($@) {
      print STDERR "Can't connect to syslog: $@\n";
      exit(1);
    }
  }

}


# signal handlers

sub hup_handler {

  $SIG{HUP} = \&hup_handler;
  $reopen_output = 1;
}


sub usr1_handler {

  $SIG{USR1} = \&usr1_handler;
  $dumpdata = 1;
}


sub usr2_handler {

  $SIG{USR2} = \&usr2_handler;
  $dumpstate = 1;
}


sub term_handler {

  $SIG{TERM} = \&term_handler;
  $terminate = 1;
}


# function for implementing the main processing loop

sub main_loop {

  my($time, $line, $ref, $json);

  for (;;) {

    if ($reopen_output) {

      if (defined($output_file)) { close($output_fh); }
      if (defined($syslog_tag)) { eval { closelog() }; }

      open_outputs();

      $reopen_output = 0;
    }

    if ($dumpdata) {
      dump_lists();
      $dumpdata = 0;
    }

    if ($dumpstate) {
      if (defined($statefile)) { write_state_file(); }
      $dumpstate = 0;
    }

    if ($terminate) {
      if (defined($statefile)) { write_state_file(); }
      exit(0);
    }

    $time = time();

    if ($time - $last_maintenance >= $scantime) {
      maintain_lists();  
      $last_maintenance = $time;
    }

    $line = read_line();

    if (!defined($line)) {
      select(undef, undef, undef, $sleeptime);
      next;
    }

    # decode incoming JSON data

    eval { $ref = decode_json($line); };

    if ($@) {
      print STDERR "Malformed JSON '$line': $@\n";
      next;
    }

    # find alert group similarity to matching cluster and
    # store similarity score in alert group data structure

    find_similarity($ref);

    # convert the alert group to JSON format

    $json = format_alert_group($ref);

    if (!defined($json)) { next; }

    # log alert group JSON to all outputs

    if (defined($output_file)) {
      print $output_fh $json, "\n";
    }

    if (defined($syslog_tag)) {
      eval { syslog($syslog_level, '@cee: ' . $json) };
    }

    # update cluster/candidate lists with data from new alert group

    update_lists($ref);  
  }

}


#####################################################################

# parse command line options

get_options();

# create pid file if --pid command line option was provided

if (defined($pid_file)) {

  my($handle);

  if (!open($handle, ">", $pid_file)) {
    print STDERR "Can't open pidfile $pid_file: $!\n";
    exit(1);
  }

  print $handle "$$\n";

  close($handle);
}

# initialize variables

$candidate_dumpfile = "$dumpdir/candidates.txt";
$cluster_dumpfile = "$dumpdir/clusters.txt";

$input_buffer = "";

$last_maintenance = 0;

# set signal handlers for HUP, USR1, USR2 and TERM

$reopen_output = 0;
$SIG{HUP} = \&hup_handler;

$dumpdata = 0;
$SIG{USR1} = \&usr1_handler;

$dumpstate = 0;
$SIG{USR2} = \&usr2_handler;

$terminate = 0;
$SIG{TERM} = \&term_handler;

# make standard error unbuffered

select STDERR;
$| = 1;
select STDOUT;

# if --statefile command line option has been provided,
# restore candidates and clusters from state file

if (defined($statefile)) { read_state_file(); }

# record max number of clusters and candidates

$max_clusters = scalar(keys %clusters);
$max_candidates = scalar(keys %candidates);

# open all outputs

open_outputs();

# main loop

main_loop();

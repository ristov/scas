#!/usr/bin/perl -w
#
# scas-group 0.03 - scas-group.pl
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
use Net::CIDR::Lite;
use Getopt::Long;


use vars qw(
  $USAGE
  %alerts
  %app_proto_func
  $blocksize
  $homenets
  $input_buffer
  $output_fh
  $output_file
  $parser_regexp
  $pid_file
  $reopen_output
  $session_length
  $session_timeout
  $sleeptime
);


$USAGE = qq!Usage: $0 [options]

Options:

  --homenet=<homenet> ...

    One or more home networks, where each network is given with a separate
    --homenet option. Providing at least one --homenet option is mandatory.

  --parser=<regular expression>

    Regular expression for matching and parsing input lines, so that
    Suricata EVE messages are extracted. The regular expression must set 
    \$+{json} match variable to JSON data string from the EVE message. 
    For example, the following regular expression parses Suricata EVE 
    messages from syslog log files:
    'suricata(?:\\[\\d+\\])?: \@cee:\\s*(?<json>\\{.+\\})\\s*\$'
    By default, no regular expression is applied for matching and parsing 
    input lines, and it is assumed that each input line is a valid JSON 
    data string representing a valid Suricata EVE message.

  --session-timeout=<session timeout>

    Session timeout in seconds -- if no IDS alert messages have been 
    observed for an external IP address during <session timeout> seconds,
    session for this IP address is regarded as complete.
    Default value for <session timeout> is 60 seconds.

  --session-length=<session length>

    Maximum session length in seconds -- if IDS alert messages have been
    observed for an external IP address during <session length> seconds,
    so that the session has not timed out (see --session-timeout option),
    session for this IP address is regarded as complete.
    Default value for <session length> is 300 seconds.
    
  --sleeptime=<sleep time>

    Sleep time in seconds -- if no new messages were read from
    standard input, the program sleeps for <sleep time> seconds.
    Default value for <sleep time> is 1.0 seconds.

  --blocksize=<block size>

    IO block size in bytes. Default value for <block size> is 16384 bytes.

  --output=<output file>

    Write IDS alert groups that represent sessions to file <output file>,
    creating the file if it does not exist. Each alert group is in JSON 
    format and is written as a single line to the file. Note that on 
    the reception of HUP signal, the file will be reopened (and recreated
    if it no longer exists, in order to facilitate log rotation). 
    Default value for <output file> is - which denotes standard output.

  --pid=<pid file>

    Store process ID to file <pid file>.

  --help, -?

    Print the usage information.

  --version

    Print the version information.


The scas-group tool reads Suricata IDS alerts in EVE format from standard 
input and creates alert groups from incoming alerts, so that each group 
would contain alert data for the same external IP address. 
Any IP address not belonging to network(s) defined with --homenet option(s) 
is regarded as external. Each alert group contains alert data from some 
timeframe or session, where session length is defined with --session-timeout 
and --session-length options. 
The data included in the alert group include attributes and their values for 
all alerts like signature IDs, IP addresses and ports, transport protocol 
information, and application layer specific information. The output from this 
tool is in JSON format and designed to be processed by the scas-cluster tool.

!;


#####################################################################


sub get_options {

  my(@homenets, $regexp, $help, $version);

  if (!scalar(@ARGV)) {
    print $USAGE;
    exit(0);
  }

  $session_timeout = 60;
  $session_length = 300;
  $blocksize = 16384;
  $sleeptime = 1;
  $output_file = "-";
  $parser_regexp = undef;
  $pid_file = undef;
  $help = 0;
  $version = 0;

  GetOptions( "homenet=s" => \@homenets,
              "parser=s" => \$regexp,
              "session-timeout=i" => \$session_timeout,
              "session-length=i" => \$session_length,
              "sleeptime=f" => \$sleeptime,
              "blocksize=i" => \$blocksize,
              "output=s" => \$output_file,
              "pid=s" => \$pid_file,
              "help|?" => \$help,
              "version" => \$version );

  if ($help) {
    print $USAGE;
    exit(0);
  }

  if ($version) {
    print "scas-group version 0.03, Copyright (C) 2020-2022 Risto Vaarandi\n";
    exit(0);
  }

  if (!scalar(@homenets)) {
    print STDERR "--homenet option is mandatory\n";
    exit(1);
  }

  $homenets = eval { Net::CIDR::Lite->new(@homenets) };

  if ($@) {
    print STDERR "Invalid home network(s) ", join(" ", @homenets), ": $@\n";
    exit(1);
  }

  if (defined($regexp)) { 

    $parser_regexp = eval { qr/$regexp/ };

    if ($@) {
      print STDERR "Invalid regular expression $regexp: $@\n";
      exit(1);
    }

  }

  if ($session_timeout <= 0) {
    print STDERR "Invalid session timeout $session_timeout: must be positive integer\n";
    exit(1);
  }

  if ($session_length <= 0) {
    print STDERR "Invalid session length $session_length: must be positive integer\n";
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

}


sub detect_int_ext {

  my($srcip, $srcport, $dstip, $dstport) = @_;
  my($intip, $intport, $extip, $extport);

  if ($homenets->find($srcip)) {
    $intip = $srcip;
    $intport = $srcport;
    $extip = $dstip;
    $extport = $dstport;
  }
  elsif ($homenets->find($dstip)) {
    $intip = $dstip;
    $intport = $dstport;
    $extip = $srcip;
    $extport = $srcport;
  }
  
  if (!defined($intip)) {
    return (undef, undef, undef, undef);
  }

  if ($homenets->find($extip)) {
    return (undef, undef, undef, undef);
  }

  return ($intip, $intport, $extip, $extport);
}


sub process_tls_alert {

  my($ref, $attref) = @_;

  # if app_proto field of the alert is set to "tls", but tls attributes 
  # are missing from the alert, return immediately

  if (!exists($ref->{"tls"})) { return; }

  # parse tls specific attributes

  if (!exists($attref->{"TlsFingerprint"})) {
    $attref->{"TlsFingerprint"} = {};
  }

  if (exists($ref->{"tls"}->{"fingerprint"})) {
    $attref->{"TlsFingerprint"}->{$ref->{"tls"}->{"fingerprint"}} = 1;
  }

  if (!exists($attref->{"TlsIssuerDn"})) {
    $attref->{"TlsIssuerDn"} = {};
  }

  if (exists($ref->{"tls"}->{"issuerdn"})) {
    $attref->{"TlsIssuerDn"}->{$ref->{"tls"}->{"issuerdn"}} = 1;
  }

  if (!exists($attref->{"TlsJa3hash"})) {
    $attref->{"TlsJa3hash"} = {};
  }

  if (exists($ref->{"tls"}->{"ja3"}->{"hash"})) {
    $attref->{"TlsJa3hash"}->{$ref->{"tls"}->{"ja3"}->{"hash"}} = 1;
  }

  if (!exists($attref->{"TlsSni"})) {
    $attref->{"TlsSni"} = {};
  }

  if (exists($ref->{"tls"}->{"sni"})) {
    $attref->{"TlsSni"}->{$ref->{"tls"}->{"sni"}} = 1;
  }

  if (!exists($attref->{"TlsSubject"})) {
    $attref->{"TlsSubject"} = {};
  }

  if (exists($ref->{"tls"}->{"subject"})) {
    $attref->{"TlsSubject"}->{$ref->{"tls"}->{"subject"}} = 1;
  }

  if (!exists($attref->{"TlsVersion"})) {
    $attref->{"TlsVersion"} = {};
  }

  if (exists($ref->{"tls"}->{"version"})) {
    $attref->{"TlsVersion"}->{$ref->{"tls"}->{"version"}} = 1;
  }

}


sub process_smtp_alert {

  my($ref, $attref) = @_;
  my($type, $elem);

  # if app_proto field of the alert is set to "smtp", but smtp attributes 
  # are missing from the alert, return immediately

  if (!exists($ref->{"smtp"})) { return; }

  # parse smtp specific attributes

  if (!exists($attref->{"SmtpHelo"})) {
    $attref->{"SmtpHelo"} = {};
  }

  if (exists($ref->{"smtp"}->{"helo"})) {
    $attref->{"SmtpHelo"}->{$ref->{"smtp"}->{"helo"}} = 1;
  }

  if (!exists($attref->{"SmtpMailFrom"})) {
    $attref->{"SmtpMailFrom"} = {};
  }

  if (exists($ref->{"smtp"}->{"mail_from"})) {
    $attref->{"SmtpMailFrom"}->{$ref->{"smtp"}->{"mail_from"}} = 1;
  }

  if (!exists($attref->{"SmtpRcptTo"})) {
    $attref->{"SmtpRcptTo"} = {};
  }

  if (exists($ref->{"smtp"}->{"rcpt_to"})) {

    $type = ref($ref->{"smtp"}->{"rcpt_to"});

    if ($type eq "ARRAY") {

      foreach $elem (@{$ref->{"smtp"}->{"rcpt_to"}}) {
        $attref->{"SmtpRcptTo"}->{$elem} = 1;
      }

    } elsif ($type eq "") {
      $attref->{"SmtpRcptTo"}->{$ref->{"smtp"}->{"rcpt_to"}} = 1;
    }
  }

  if (!exists($attref->{"EmailFrom"})) {
    $attref->{"EmailFrom"} = {};
  }

  if (exists($ref->{"email"}->{"from"})) {
    $attref->{"EmailFrom"}->{$ref->{"email"}->{"from"}} = 1;
  }

  if (!exists($attref->{"EmailStatus"})) {
    $attref->{"EmailStatus"} = {};
  }

  if (exists($ref->{"email"}->{"status"})) {
    $attref->{"EmailStatus"}->{$ref->{"email"}->{"status"}} = 1;
  }

  if (!exists($attref->{"EmailTo"})) {
    $attref->{"EmailTo"} = {};
  }

  if (exists($ref->{"email"}->{"to"})) {

    $type = ref($ref->{"email"}->{"to"});

    if ($type eq "ARRAY") {

      foreach $elem (@{$ref->{"email"}->{"to"}}) {
        $attref->{"EmailTo"}->{$elem} = 1;
      }

    } elsif ($type eq "") {
      $attref->{"EmailTo"}->{$ref->{"email"}->{"to"}} = 1;
    }
  }

}


sub process_dns_alert {

  my($ref, $attref) = @_;
  my($elem);

  # if app_proto field of the alert is set to "dns", but dns attributes 
  # are missing from the alert, return immediately

  if (!exists($ref->{"dns"})) { return; }

  # parse dns specific attributes

  if (!exists($attref->{"DnsRrname"})) {
    $attref->{"DnsRrname"} = {};
  }

  if (!exists($attref->{"DnsRrtype"})) {
    $attref->{"DnsRrtype"} = {};
  }

  if (exists($ref->{"dns"}->{"query"})) {

    foreach $elem (@{$ref->{"dns"}->{"query"}}) {

      if (exists($elem->{"rrname"})) {
        $attref->{"DnsRrname"}->{$elem->{"rrname"}} = 1;
      }

      if (exists($elem->{"rrtype"})) {
        $attref->{"DnsRrtype"}->{$elem->{"rrtype"}} = 1;
      }

    }
  }

}


sub process_ssh_alert {

  my($ref, $attref) = @_;

  # if app_proto field of the alert is set to "ssh", but ssh attributes 
  # are missing from the alert, return immediately

  if (!exists($ref->{"ssh"})) { return; }

  # parse ssh specific attributes

  if (!exists($attref->{"SshServerProto"})) {
    $attref->{"SshServerProto"} = {};
  }

  if (exists($ref->{"ssh"}->{"server"}->{"proto_version"})) {
    $attref->{"SshServerProto"}->{$ref->{"ssh"}->{"server"}->{"proto_version"}} = 1;
  }

  if (!exists($attref->{"SshServerSoftware"})) {
    $attref->{"SshServerSoftware"} = {};
  }

  if (exists($ref->{"ssh"}->{"server"}->{"software_version"})) {
    $attref->{"SshServerSoftware"}->{$ref->{"ssh"}->{"server"}->{"software_version"}} = 1;
  }

  if (!exists($attref->{"SshClientProto"})) {
    $attref->{"SshClientProto"} = {};
  }

  if (exists($ref->{"ssh"}->{"client"}->{"proto_version"})) {
    $attref->{"SshClientProto"}->{$ref->{"ssh"}->{"client"}->{"proto_version"}} = 1;
  }

  if (!exists($attref->{"SshClientSoftware"})) {
    $attref->{"SshClientSoftware"} = {};
  }

  if (exists($ref->{"ssh"}->{"client"}->{"software_version"})) {
    $attref->{"SshClientSoftware"}->{$ref->{"ssh"}->{"client"}->{"software_version"}} = 1;
  }

}


sub process_http_alert {

  my($ref, $attref) = @_;
  my($key, @keys);
  
  # if app_proto field of the alert is set to "http", but http attributes 
  # are missing from the alert, return immediately

  if (!exists($ref->{"http"})) { return; }

  # parse http specific attributes

  if (!exists($attref->{"HttpHostname"})) {
    $attref->{"HttpHostname"} = {};
  }

  if (exists($ref->{"http"}->{"hostname"})) {
    $attref->{"HttpHostname"}->{$ref->{"http"}->{"hostname"}} = 1;
  }

  if (!exists($attref->{"HttpContentType"})) {
    $attref->{"HttpContentType"} = {};
  }

  if (exists($ref->{"http"}->{"http_content_type"})) {
    $attref->{"HttpContentType"}->{$ref->{"http"}->{"http_content_type"}} = 1;
  }

  if (!exists($attref->{"HttpMethod"})) {
    $attref->{"HttpMethod"} = {};
  }

  if (exists($ref->{"http"}->{"http_method"})) {
    $attref->{"HttpMethod"}->{$ref->{"http"}->{"http_method"}} = 1;
  }

  if (!exists($attref->{"HttpRequestBody"})) {
    $attref->{"HttpRequestBody"} = {};
  }

  if (exists($ref->{"http"}->{"http_request_body_printable"})) {
    @keys = split(' ', $ref->{"http"}->{"http_request_body_printable"});
    foreach $key (@keys) { $attref->{"HttpRequestBody"}->{$key} = 1; }
  }

  if (!exists($attref->{"HttpResponseBody"})) {
    $attref->{"HttpResponseBody"} = {};
  }

  if (exists($ref->{"http"}->{"http_response_body_printable"})) {
    @keys = split(' ', $ref->{"http"}->{"http_response_body_printable"});
    foreach $key (@keys) { $attref->{"HttpResponseBody"}->{$key} = 1; }
  }

  if (!exists($attref->{"HttpUserAgent"})) {
    $attref->{"HttpUserAgent"} = {};
  }

  if (exists($ref->{"http"}->{"http_user_agent"})) {
    $attref->{"HttpUserAgent"}->{$ref->{"http"}->{"http_user_agent"}} = 1;
  }

  if (!exists($attref->{"HttpProtocol"})) {
    $attref->{"HttpProtocol"} = {};
  }

  if (exists($ref->{"http"}->{"protocol"})) {
    $attref->{"HttpProtocol"}->{$ref->{"http"}->{"protocol"}} = 1;
  }

  if (!exists($attref->{"HttpStatus"})) {
    $attref->{"HttpStatus"} = {};
  }

  if (exists($ref->{"http"}->{"status"})) {
    $attref->{"HttpStatus"}->{$ref->{"http"}->{"status"}} = 1;
  }

  if (!exists($attref->{"HttpUrl"})) {
    $attref->{"HttpUrl"} = {};
  }

  if (exists($ref->{"http"}->{"url"})) {
    $attref->{"HttpUrl"}->{$ref->{"http"}->{"url"}} = 1;
  }
  
}


sub process_alert {

  my($ref) = $_[0];
  my($id, $sigref, $attref, $app_proto);

  if (!exists($alerts{$ref->{"extip"}})) {

    $alerts{$ref->{"extip"}} = { "CreationTime" => time(), 
                                 "Events" => 0,
                                 "Signatures" => {} };
  }

  $id = $ref->{"alert"}->{"gid"} . ":" .  $ref->{"alert"}->{"signature_id"};
  
  if (!exists($alerts{$ref->{"extip"}}->{"Signatures"}->{$id})) {
    $alerts{$ref->{"extip"}}->{"Signatures"}->{$id} = {};
    $alerts{$ref->{"extip"}}->{"Signatures"}->{$id}->{"Attributes"} = {};
  }

  $sigref = $alerts{$ref->{"extip"}}->{"Signatures"}->{$id};
  $attref = $sigref->{"Attributes"};

  $sigref->{"Signature"} = $ref->{"alert"}->{"signature"};

  $attref->{"Proto"}->{$ref->{"proto"}} = 1;
  $attref->{"IntIP"}->{$ref->{"intip"}} = 1;
  $attref->{"IntPort"}->{$ref->{"intport"}} = 1;
  $attref->{"ExtIP"}->{$ref->{"extip"}} = 1;
  $attref->{"ExtPort"}->{$ref->{"extport"}} = 1;

  $alerts{$ref->{"extip"}}->{"UpdateTime"} = time();  

  ++$alerts{$ref->{"extip"}}->{"Events"};  

  $app_proto = exists($ref->{"app_proto"})?$ref->{"app_proto"}:"Missing";

  if (exists($app_proto_func{$app_proto})) { 
    $app_proto_func{$app_proto}->($ref, $attref);
  }

}


sub print_alerts_for_ip {

  my($ip) = $_[0];
  my($json);

  eval { $json = encode_json($alerts{$ip}); };

  if ($@) {
    print STDERR "Can't create JSON data structure: $@\n";
    return;
  }

  print $output_fh $json, "\n"; 
}


sub report_alerts {

  my($ip, $time);

  $time = time();

  foreach $ip (keys %alerts) {

    if ($time - $alerts{$ip}->{"CreationTime"} > $session_length) {
      print_alerts_for_ip($ip);
      delete $alerts{$ip};
    }
    elsif ($time - $alerts{$ip}->{"UpdateTime"} > $session_timeout) {
      print_alerts_for_ip($ip);
      delete $alerts{$ip};
    }

  }
}


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
    # returned 0 bytes, EOF has been reached, and exit from program

    if ($n == 0) { exit(0); }

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


sub open_output_file {

  my($file) = $_[0];
  my($fh);

  if ($file ne "-") {

    while (!open($fh, ">>", $file)) {
      if ($! == EINTR)  { next; }
      print STDERR "Can't open output file $file for writing: $!\n";
      exit(1);
    }

  } else {

    while (!open($fh, ">&", STDOUT)) {
      if ($! == EINTR)  { next; }
      print STDERR "Can't dup standard output: $!\n";
      exit(1);
    }
  }

  select($fh);
  $| = 1;
  select(STDOUT);

  return $fh;
}


sub hup_handler {

  $SIG{HUP} = \&hup_handler;
  $reopen_output = 1;
}


sub main_loop {

  my($line, $json, $ref, $src_port, $dst_port);

  for (;;) {

    if ($reopen_output) {

      close($output_fh);
      $output_fh = open_output_file($output_file);

      $reopen_output = 0;
    }

    report_alerts();  

    $line = read_line();

    if (!defined($line)) {
      select(undef, undef, undef, $sleeptime);
      next;
    }

    if (defined($parser_regexp)) {

      if ($line !~ $parser_regexp) {
        next;
      }

      if (!defined($+{json})) { next; }

      $json = $+{json};

    } else {

      $json = $line;
    }

    # decode JSON data in Suricata EVE event

    eval { $ref = decode_json($json); };

    if ($@) {
      print STDERR "Malformed JSON '$json': $@\n";
      next;
    }

    # ignore events which are not IDS alerts

    if ($ref->{"event_type"} ne "alert") { next; }

    $src_port = exists($ref->{"src_port"})?$ref->{"src_port"}:0;
    $dst_port = exists($ref->{"dest_port"})?$ref->{"dest_port"}:0;
 
    ($ref->{"intip"}, $ref->{"intport"}, $ref->{"extip"}, $ref->{"extport"}) = 
      detect_int_ext($ref->{"src_ip"}, $src_port, $ref->{"dest_ip"}, $dst_port);

    if (!defined($ref->{"intip"})) { next; }

    process_alert($ref);  

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

$input_buffer = "";

$app_proto_func{"tls"} = \&process_tls_alert;
$app_proto_func{"smtp"} = \&process_smtp_alert;
$app_proto_func{"dns"} = \&process_dns_alert;
$app_proto_func{"ssh"} = \&process_ssh_alert;
$app_proto_func{"http"} = \&process_http_alert;

# set signal handler for HUP

$reopen_output = 0;
$SIG{HUP} = \&hup_handler;

# make standard error unbuffered

select(STDERR);
$| = 1;
select(STDOUT);

# open output file or dup standard output

$output_fh = open_output_file($output_file);

# main loop

main_loop();

#!/usr/bin/env perl
use strict;
use warnings 'all';
use Monitoring::Plugin;
use Monitoring::Plugin::Functions;
use Monitoring::Plugin::ExitResult;
use Monitoring::Plugin::Getopt;
use Monitoring::Plugin::Threshold;
use Net::SNMP qw/&oid_lex_sort &snmp_dispatcher &oid_base_match/;

use Data::Dumper 'Dumper';

my $VERSION = '0.01';
use constant {
  FREENAS_MIB_zpoolDescr => '1.3.6.1.4.1.50536.1.1.1.1.2',
  FREENAS_MIB_zpoolAllocationUnits => '1.3.6.1.4.1.50536.1.1.1.1.3',
  FREENAS_MIB_zpoolSize => '1.3.6.1.4.1.50536.1.1.1.1.4',
  FREENAS_MIB_zpoolUsed => '1.3.6.1.4.1.50536.1.1.1.1.5',
};

sub _getopts {
  #my $ng= Monitoring::Plugin::Getopt->new(
  my $ng= Monitoring::Plugin->new(
    shortname => "freenas_zpool_size",
    usage => "Usage: %s -H <host> -C <community> -z <zpool>" 
      . "-w <warning> -c <critical>",
    version => '2c',
    url => 'https://github.com/apendragon/check_freenas_zpool',
    blurb => 'This plugin uses FREENAS MIB to query zpool status with SNMP',
  );

  $ng->add_arg(
    'warning|w=i',
    q(Exit with WARNING status if usage greater than INTEGER percent),
    70,
    1
  );

  $ng->add_arg(
    'critical|c=i',
    q(Exit with CRITICAL status if usage greater than INTEGER percent),
    80,
    1
  );

  $ng->add_arg(
    'zpool|z=s',
    q(zpool name to query usage),
    'freenas-boot',
    1
  );

  $ng->add_arg(
    'hostname|H=s',
    q(Hostname to query - required),
    'localhost',
    1
  );

  $ng->add_arg(
    'community|C=s',
    q(SNMP community),
    'public',
    1
  );

  $ng->getopts;
  $ng;
}

sub _snmpv2 {
  my $ng = shift;
  my ($session, $error) = Net::SNMP->session(
    -hostname     => $ng->opts->hostname,
    -community    => $ng->opts->community,
    -nonblocking => 1,
    -translate   => [-octetstring => 0],
    -version     => 'snmpv2c',
  );

  if (!defined $session) {
    printf "ERROR: %s.\n", $error;
    exit 1;
  }
  _get_zpoolDescr($session, $ng);

  snmp_dispatcher();
  $session->close();
}

sub _get_zpoolDescr {
  my ($session, $ng) = @_;
  my $result = $session->get_table(
    -baseoid        => &FREENAS_MIB_zpoolDescr,
    -callback       => [ \&_zpoolDescr_callback, $ng ],
  );

  if (!defined $result) {
    $session->close();
    $ng->plugin_die("no result has been received");
  }
}

sub _zpoolDescr_callback {
  my ($session, $ng) = @_;
  my $list = $session->var_bind_list();
  if (!defined $list) {
    $ng->plugin_die(session->error());
  }

  my @names = $session->var_bind_names();
  my $next  = undef;
  my $oid = undef;
  while (@names) {
    $next = shift @names;
    if ($list->{$next} eq $ng->opts->zpool) {
      $oid = $next;
      last;
    } 
  }
  if (!defined $oid) {
    $ng->plugin_die(sprintf("no zpool descr matches '%s'", $ng->zpool));
  }

  my $index = chop($oid);
  _get_zpoolSize($session, $ng, $index);
}

sub _get_zpoolSize {
  my ($session, $ng, $index) = @_;

  my $result = $session->get_request(
    -varbindlist    => [ sprintf('%s.%s', &FREENAS_MIB_zpoolSize, $index) ],
    -callback       => [ \&_zpoolSize_callback, $ng, $index ],
  );

  if (!defined $result) {
    $ng->plugin_die(session->error());
  }
}

sub _zpoolSize_callback {
  my ($session, $ng, $index) = @_;
  my $list = $session->var_bind_list();
  if (!defined $list) {
    $ng->plugin_die(session->error());
  }

  my @names = $session->var_bind_names();
  my $next  = undef;
  my $size = undef;
  while (@names) {
    $next = shift @names;
    $size = $list->{$next};
    last;
  }
  if (!defined $size) {
    $ng->plugin_die(
      sprintf("no zpool size matches '%s.%s'", &FREENAS_MIB_zpoolSize, $index)
    );
  }
  _get_zpoolUsed($session, $ng, $index, $size);
}

sub _get_zpoolUsed {
  my ($session, $ng, $index, $size) = @_;

  my $result = $session->get_request(
    -varbindlist    => [ sprintf('%s.%s', &FREENAS_MIB_zpoolUsed, $index) ],
    -callback       => [ \&_zpoolUsed_callback, $ng, $index, $size ],
  );

  if (!defined $result) {
    $ng->plugin_die(session->error());
  }
}

sub _zpoolUsed_callback {
  my ($session, $ng, $index, $size) = @_;
  my $list = $session->var_bind_list();
  if (!defined $list) {
    $ng->plugin_die(session->error());
  }

  my @names = $session->var_bind_names();
  my $next  = undef;
  my $used = undef;
  while (@names) {
    $next = shift @names;
    $used = $list->{$next};
    last;
  }
  if (!defined $size) {
    $ng->plugin_die(
      sprintf("no zpool used matches '%s.%s'", &FREENAS_MIB_zpoolUsed, $index)
    );
  }
  _check_threshold($ng, $size, $used);
}

sub _check_threshold {
  my ($ng, $size, $used) = @_;
  my $value = sprintf('%u', $used/$size*100);
  $ng->plugin_exit(
    $ng->check_threshold(
      check => $value,
      warning => $ng->opts->warning,
      critical => $ng->opts->critical,
    ),
    $value
  );
}

sub _main {
  my $ng = _getopts;
  _snmpv2($ng);
};

_main;

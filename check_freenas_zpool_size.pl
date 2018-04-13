#!/usr/bin/env perl
use strict;
use warnings 'all';
use Carp;
use Monitoring::Plugin;
#TODO mange snmp import
use Net::SNMP qw/ &snmp_dispatcher/;

use Data::Dumper 'Dumper';

my $VERSION = '0.01';
use constant {
  FREENAS_MIB_zpoolDescr => '1.3.6.1.4.1.50536.1.1.1.1.2',
  FREENAS_MIB_zpoolAllocationUnits => '1.3.6.1.4.1.50536.1.1.1.1.3',
  FREENAS_MIB_zpoolSize => '1.3.6.1.4.1.50536.1.1.1.1.4',
  FREENAS_MIB_zpoolUsed => '1.3.6.1.4.1.50536.1.1.1.1.5',
};

#close snmp session if open
sub _die {
  my ($session, $ng, $msg) = @_;
  if (!defined $msg) {
    $msg = defined($session)
      ? $session->error()
      : "unable to open snmp session";
  }
  $session->close() if defined($session);
  #TODO manage -v option
  $ng->plugin_die($msg);
}

sub _getopts {
  my $ng= Monitoring::Plugin->new(
    shortname => "freenas_zpool_size",
    usage => "Usage: %s -H <host> -C <community> -z <zpool> " 
      . "-w <warning> -c <critical> -t <timeout>",
    version => $VERSION ,
    url => 'https://github.com/freenas-monitoring-plugins/check_freenas_zpool_size',
    blurb => 'This plugin uses FREENAS-OID to query zpool size with SNMP',
  );
  
  _get_opt_warning($ng);
  _get_opt_critical($ng);
  _get_opt_zpool($ng);
  _get_opt_hostname($ng);
  _get_opt_community($ng);
  _get_opt_timeout($ng);
  $ng->getopts;
  $ng;
}

sub _get_opt_warning($) {
  my $ng = shift;
  $ng->add_arg(
    spec => 'warning|w=i',
    help => q(Exit with WARNING status if usage greater than INTEGER percent),
    required => 1
  );
}

sub _get_opt_critical($) {
  my $ng = shift;
  $ng->add_arg(
    spec => 'critical|c=i',
    help => q(Exit with CRITICAL status if usage greater than INTEGER percent),
    required => 1
  );
}

sub _get_opt_zpool($) {
  my $ng = shift;
  $ng->add_arg(
    spec => 'zpool|z=s',
    help => q(zpool name to query usage),
    required => 1
  );
}

sub _get_opt_hostname($) {
  my $ng = shift;
  $ng->add_arg(
    spec => 'hostname|H=s',
    help => q(Hostname to query - required),
    required => 1
  );
}

sub _get_opt_community($) {
  my $ng = shift;
  $ng->add_arg(
    spec => 'community|C=s',
    help => q(SNMP community),
    required => 1
  );
}

sub _get_opt_timeout($) {
  my $ng = shift;
  $ng->add_arg(
    spec => 'timeout|t=i',
    help => q(SNMP timeout),
    default => '15',
    required => 1
  );
}

sub _init_snmp {
  my $ng = shift;
  my ($session, $error) = Net::SNMP->session(
    -hostname     => $ng->opts->hostname,
    -community    => $ng->opts->community,
    -nonblocking => 1,
    -translate   => [-octetstring => 0],
    -version     => 'snmpv2c',
    -timeout     => $ng->opts->timeout,
  );

  _die($session, $ng) if (!defined $session);
  _get_zpoolDescr($session, $ng);
  snmp_dispatcher();
}

sub _get_zpoolDescr {
  my ($session, $ng) = @_;
  my $result = $session->get_table(
    -baseoid        => &FREENAS_MIB_zpoolDescr,
    -callback       => [ \&_zpoolDescr_callback, $ng ],
  );

  _die($session, $ng) if (!defined $result);
}

sub _zpoolDescr_callback {
  my ($session, $ng) = @_;
  my $list = $session->var_bind_list();
  _die($session, $ng) if !defined $list;

  my $oid = undef;
  while (my ($k, $v) = each %$list) {
    if ($v eq $ng->opts->zpool) {
      $oid = $k;
      last;
    }
  }

  if (!defined $oid) {
    _die($session, $ng, sprintf("no zpool descr matches '%s'",
        $ng->opts->zpool));
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

  _die($session, $ng) if !defined $result;
}

sub _zpoolSize_callback {
  my ($session, $ng, $index) = @_;
  my $list = $session->var_bind_list();
  _die($session, $ng) if !$list;

  my $size = undef;
  for my $v (values %$list) {
    $size = $v;
    last;
  }

  if (!defined $size) {
    _die($session, $ng, 
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

  _die($session, $ng) if !defined $result;
}

sub _zpoolUsed_callback {
  my ($session, $ng, $index, $size) = @_;
  my $list = $session->var_bind_list();
  _die($session, $ng) if !$list;

  my $used = undef;
  for my $v (values %$list) {
    $used = $v;
    last;
  }

  if (!defined $used) {
    _die($session, $ng, 
      sprintf("no zpool used matches '%s.%s'", &FREENAS_MIB_zpoolUsed, $index)
    );
  }
  _get_zpoolAllocationUnits($session, $ng, $index, $size, $used);
}

sub _get_zpoolAllocationUnits {
  my ($session, $ng, $index, $size, $used) = @_;

  my $result = $session->get_request(
    -varbindlist    => [ sprintf('%s.%s', &FREENAS_MIB_zpoolAllocationUnits, $index) ],
    -callback       => [ \&_zpoolAllocationUnits_callback, $ng, $index, $size, $used ],
  );

  _die($session, $ng) if !defined $result;
}

sub _zpoolAllocationUnits_callback {
  my ($session, $ng, $index, $size, $used) = @_;
  my $list = $session->var_bind_list();
  _die($session, $ng) if !$list;

  my $aunits = undef;
  for my $v (values %$list) {
    $aunits = $v;
    last;
  }

  if (!defined $aunits) {
    _die($session, $ng, 
      sprintf("no zpool allocation units matches '%s.%s'", 
        &FREENAS_MIB_zpoolAllocationUnits, $index)
    );
  }
  $session->close();
  _check_threshold($ng, $size, $used, $aunits);
}

sub _check_threshold {
  my ($ng, $size, $used, $aunits) = @_;
  my $value = sprintf('%u', $used/$size*100);
  #TODO handle parameterized units
  my $psize = sprintf('%u', $size*$aunits/1024/1024);
  my $pused = sprintf('%u', $used*$aunits/1024/1024);
  $ng->plugin_exit(
    $ng->check_threshold(
      check => $value,
      warning => $ng->opts->warning,
      critical => $ng->opts->critical,
    ),
    sprintf('%s: %s/%s MB (%s%%)', $ng->opts->zpool, $pused, $psize, $value)
  );
}

sub main {
  my $ng = _getopts;
  #TODO handle all SNMP versionss
  _init_snmp($ng);
};

main;

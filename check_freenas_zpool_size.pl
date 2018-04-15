#!/usr/bin/env perl
use strict;
use warnings 'all';

our $VERSION = '0.01';
use Net::SNMP qw/:debug :snmp/;
use Monitoring::Plugin;

#Crypt/Rijndae is required to use AES as privacy protocol with snmpv3

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
  $ng->plugin_die($msg);
}

sub getopts {
  my $ng= Monitoring::Plugin->new(
    shortname => "freenas_zpool_size",
    usage => "Usage: %s -H <host> -C <community> -z <zpool> " 
      . "-w <warning> -c <critical> -t <timeout> "
      . "[-u <username> -p <password> -X <passphrase> "
      . "-a <authentication_type> -x <privacy_protocol>]",
    version => $VERSION,
    url => 'https://github.com/freenas-monitoring-plugins/check_freenas_zpool_size',
    blurb => 'This plugin uses FREENAS-MIB to query zpool size with SNMP',
  );
  
  _get_opt_critical($ng);
  _get_opt_community($ng);
  _get_opt_hostname($ng);
  _get_opt_timeout($ng);
  _get_opt_warning($ng);
  _get_opt_zpool($ng);
  _get_opt_username($ng);
  _get_opt_password($ng);
  _get_opt_passphrase($ng);
  _get_opt_auth_type($ng);
  _get_opt_privacy_protocol($ng);
  $ng->getopts;
  $ng;
}

sub _get_opt_community($) {
  my $ng = shift;
  $ng->add_arg(
    spec => 'community|C=s',
    help => q(SNMP community),
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

sub _get_opt_hostname($) {
  my $ng = shift;
  $ng->add_arg(
    spec => 'hostname|H=s',
    help => q(Hostname to query - required),
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

sub _get_opt_warning($) {
  my $ng = shift;
  $ng->add_arg(
    spec => 'warning|w=i',
    help => q(Exit with WARNING status if usage greater than INTEGER percent),
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

# get snmpv3 opts
sub _get_opt_username($) {
  my $ng = shift;
  $ng->add_arg(
    spec => 'username|u=s',
    help => q(snmpv3 username to use),
  );
}

sub _get_opt_password($) {
  my $ng = shift;
  $ng->add_arg(
    spec => 'password|p=s',
    help => q(snmpv3 password to use),
  );
}

sub _get_opt_passphrase($) {
  my $ng = shift;
  $ng->add_arg(
    spec => 'passphrase|X=s',
    help => q(snmpv3 passphrase to use),
  );
}

sub _get_opt_auth_type($) {
  my $ng = shift;
  $ng->add_arg(
    spec => 'authprotocol|a=s',
    help => "snmpv3 authentication type to use (MD5/SHA)",
  );
}

sub _get_opt_privacy_protocol($) {
  my $ng = shift;
  $ng->add_arg(
    spec => 'privprotocol|x=s',
    help => "snmpv3 privacy protocol to use (AES/DES)",
  );
}

sub _snmp_debug {
  my $ng = shift;
  return DEBUG_ALL if $ng->opts->verbose >= 3;
  return DEBUG_MESSAGE if $ng->opts->verbose >= 3;
  return DEBUG_NONE;
}

sub _switch_snmp_version {
  my $ng = shift;
  return 'snmpv3' if defined $ng->opts->username;
  return 'snmpv3' if defined $ng->opts->password;
  return 'snmpv3' if defined $ng->opts->passphrase;
  return 'snmpv3' if defined $ng->opts->auth_type;
  return 'snmpv3' if defined $ng->opts->privacy_protocol;
  return 'snmpv2c';
}

sub _init_snmpv2c {
  my $ng = shift;
  my ($session, $error) = Net::SNMP->session(
    -hostname     => $ng->opts->hostname,
    -community    => $ng->opts->community,
    -nonblocking => 1,
    -translate   => [-octetstring => 0],
    -debug       => _snmp_debug($ng),
    -version     => 'snmpv2c',
    -timeout     => $ng->opts->timeout,
  );

  _die($session, $ng) if (!defined $session);
  $session;
}

sub _init_snmpv3 {
  my $ng = shift;
  my ($session, $error) = Net::SNMP->session(
    -hostname     => $ng->opts->hostname,
    -nonblocking => 1,
    -translate   => [-octetstring => 0],
    -debug       => _snmp_debug($ng),
    -version     => 'snmpv3',
    -timeout     => $ng->opts->timeout,
    -username    => $ng->opts->username,
    -authpassword => $ng->opts->password,
    -authprotocol => $ng->opts->authprotocol,
    -privpassword => $ng->opts->passphrase,
    -privprotocol => lc($ng->opts->privprotocol),

  );

  _die($session, $ng) if (!defined $session);
  $session;
}

sub _init_snmp {
  my $ng = shift;
  my $snmpv = _switch_snmp_version($ng);
  $snmpv eq 'snmpv3' ? _init_snmpv3($ng) : _init_snmpv2c($ng);
}

sub check {
  my ($ng, $session) = @_;
  _get_zpoolDescr($session, $ng);
  snmp_dispatcher();
}
# hash used to store collected snmp info.
# Avoids to pass a lot of args in cascading called functions.
sub _collected($) {
  my $index = shift;
  {
    oid_index => $index,
    size => undef,
    used => undef,
    allocation_units => undef,
  };
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
  my $collected = _collected(chop($oid));
  _get_zpoolSize($session, $ng, $collected);
}

sub _get_zpoolSize {
  my ($session, $ng, $collected) = @_;

  my $result = $session->get_request(
    -varbindlist    => [ 
      sprintf('%s.%s', &FREENAS_MIB_zpoolSize, $collected->{oid_index}),
    ],
    -callback       => [ \&_zpoolSize_callback, $ng, $collected ],
  );

  _die($session, $ng) if !defined $result;
}

# collect the zpool size
sub _zpoolSize_callback {
  my ($session, $ng, $collected) = @_;
  my $list = $session->var_bind_list();
  _die($session, $ng) if !$list;

  my $size = undef;
  for my $v (values %$list) {
    $size = $v;
    last;
  }

  if (!defined $size) {
    _die($session, $ng, 
      sprintf("no zpool size matches '%s.%s'", &FREENAS_MIB_zpoolSize,
        $collected->{oid_index})
    );
  }
  $collected->{size} = $size;
  _get_zpoolUsed($session, $ng, $collected);
}

sub _get_zpoolUsed {
  my ($session, $ng, $collected) = @_;

  my $result = $session->get_request(
    -varbindlist    => [ 
      sprintf('%s.%s', &FREENAS_MIB_zpoolUsed, $collected->{oid_index}) ],
    -callback       => [ \&_zpoolUsed_callback, $ng, $collected],
  );

  _die($session, $ng) if !defined $result;
}

# collect the zpool used
sub _zpoolUsed_callback {
  my ($session, $ng, $collected) = @_;
  my $list = $session->var_bind_list();
  _die($session, $ng) if !$list;

  my $used = undef;
  for my $v (values %$list) {
    $used = $v;
    last;
  }

  if (!defined $used) {
    _die($session, $ng, 
      sprintf("no zpool used matches '%s.%s'", &FREENAS_MIB_zpoolUsed, 
        $collected->{oid_index})
    );
  }
  $collected->{used} = $used;
  _get_zpoolAllocationUnits($session, $ng, $collected);
}

sub _get_zpoolAllocationUnits {
  my ($session, $ng, $collected) = @_;

  my $result = $session->get_request(
    -varbindlist => [ 
      sprintf('%s.%s', &FREENAS_MIB_zpoolAllocationUnits, 
        $collected->{oid_index}) ],
    -callback => [ \&_zpoolAllocationUnits_callback, $ng, $collected],
  );

  _die($session, $ng) if !defined $result;
}

# collect the allocation units
sub _zpoolAllocationUnits_callback {
  my ($session, $ng, $collected) = @_;
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
        &FREENAS_MIB_zpoolAllocationUnits, $collected->{oid_index})
    );
  }
  $collected->{allocation_units} = $aunits;
  $session->close();
  _check_threshold($ng, $collected);
}

sub _check_threshold {
  my ($ng, $collected) = @_;
  my $value = sprintf('%u', $collected->{used}/$collected->{size}*100);
  #TODO handle parameterized units
  my $psize = sprintf('%u',
    $collected->{size}*$collected->{allocation_units}/1024/1024);
  my $pused = sprintf('%u',
    $collected->{used}*$collected->{allocation_units}/1024/1024);
  $ng->plugin_exit(
    $ng->check_threshold(
      check => $value,
      warning => $ng->opts->warning,
      critical => $ng->opts->critical,
    ),
    sprintf('%s: %s/%s MB (%s%%)', $ng->opts->zpool, $pused, $psize, $value)
  );
}

my $ng = getopts();
my $session = _init_snmp($ng);
check($ng, $session);

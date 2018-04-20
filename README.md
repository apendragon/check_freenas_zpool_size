# check_freenas_zpool_size

[check_freenas_zpool_size 0.01](https://github.com/freenas-monitoring-plugins/check_freenas_zpool_size)

This plugin uses FREENAS-MIB to query zpool size with SNMPv2c or SNMPv3

Tested with FreeNAS-11.1-U2, icinga 2.8.2, icingaweb 2.5.1, perl 5.26.1, Monitoring::Plugin 0.39, FreeBSD 11.1, Gentoo 2.4.1

## Usage

    check_freenas_zpool_size -H <host> -C <community> -z <zpool> -w <warning> -c <critical> -t <timeout> [-U <secname> -A <authpassword> -X <privpasswd> -a <authproto> -x <privproto>] -u <unit_of_measurement>

    -?, --usage
      Print usage information
    -h, --help
      Print detailed help screen
    -V, --version
      Print version information
    --extra-opts=[section][@file]
      Read options from an ini file. See [https://www.monitoring-plugins.org/doc/extra-opts.html](https://www.monitoring-plugins.org/doc/extra-opts.html)
      for usage and examples.
    -c, --critical=INTEGER
      Exit with CRITICAL status if usage greater than INTEGER percent
    -C, --community=STRING
      SNMP community
    -H, --hostname=STRING
      Hostname to query - required
    -w, --warning=INTEGER
      Exit with WARNING status if usage greater than INTEGER percent
    -z, --zpool=STRING
      zpool name to query usage
    -u, --uom=STRING
      Unit Of Measurement [KB|MB|GB|TB]
    -U, --secname=STRING
      SNMPv3 username
    -A, --authpassword=STRING
      SNMPv3 authentication password
    -X, --privpasswd=STRING
      SNMPv3 privacy password (passphrase)
    -a, --authproto=STRING
      SNMPv3 authentication proto [MD5|SHA]
    -x, --privproto=STRING
      SNMPv3 privacy protocol [AES|DES]
    -t, --timeout=INTEGER
      Seconds before plugin times out (default: 15)
    -v, --verbose
      Show details for command-line debugging (can repeat up to 3 times)

## Notes:
  To use 'AES' SNMPv3 privacy protocol Crypt/Rijndae perlmod installation is
  on the running host.
  
  Use '-vvv' debugging to troubleshoot any SNMPv3 encountered communication
  problems.

## Examples:
  CHECK ZPOOL WITH SNMPv2: check_freenas_zpool_size -H myfreenas.example.com -z raid -w 70 -c 80 -C public

  Check the zpool named 'raid' from myfreenas.example.com by using 'public'
  community and raise warnings at 70% of used space and critical at 80%.

  CHECK ZPOOL WITH SNMPv3: check_freenas_zpool_size -H myfreenas.example.com -z raid -w 70 -c 80 -U myuser -A mqlkdqfmLIHMOyçè67sdf -X yYOOJMohimoç96e283 -a SHA -x AES -u TB 

  Check the zpool named 'raid' from myfreenas.example.com by using 'myuser'
  user, 'mqlkdqfmLIHMOyçè67sdf' authentication password, 'yYOOJMohimoç96e283'
  private password, 'SHA' authentication protocol, 'AES' privacy protocol,
  'TB' unit of measurement and raise warnings at 70% of used space and 
  critical at 80%.

## Debugging:
  -vv option will display the executed method while running the plugin

  -vvv option will also display all the SNMP dialog managed by Net::SNMP

## LICENSE AND COPYRIGHT

Copyright (C) 2018 Thomas Cazali

This program is distributed under the (Simplified) BSD License:
[http://www.opensource.org/licenses/BSD-2-Clause](http://www.opensource.org/licenses/BSD-2-Clause)

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

* Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

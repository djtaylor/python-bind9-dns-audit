[![Build Status](https://api.travis-ci.org/djtaylor/python-rancher2.png)](https://api.travis-ci.org/djtaylor/python-rancher2)

# BIND9 DNS Audit

This module deploys a command line script to audit a BIND9 server to look for DNS records that don't have any backing infrastructure and be deleted. This script takes a BIND9 configuration path, and parses this for any zone definitions, then parses each zone configuration for A records to audit for connectivity.

### Installation
The prefix option may vary depending on the system you are running.

```
$ git clone https://github.com/djtaylor/python-bind9-dns-audit
$ cd python-bind9-dns-audit
$ python setup.py install --prefix /usr/local
```

### Usage
The following is an example of basic usage to audit a BIND9 DNS server.

```
# This will dump a JSON report to stdout
$ bind9_dns_audit 10.1.1.36 --ssh-user myuser --ssh-passwd my_password --zones-config /etc/bind/named.conf.local
# Generate a no ping response report and write to file
$ bind9_dns_audit 10.1.1.36 --ssh-user myuser --ssh-passwd my_password --zones-config /etc/bind/named.conf.local --report-nopoing --report-file /tmp/my_report.txt
```

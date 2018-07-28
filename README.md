[![Build Status](https://api.travis-ci.org/djtaylor/python-bind9-dns-audit.png)](https://api.travis-ci.org/djtaylor/python-bind9-dns-audit)

# BIND9 DNS Audit

This module deploys a command line script to audit a BIND9 server to look for DNS records that don't have any backing infrastructure and be deleted. This script takes a BIND9 configuration path, and parses this for any zone definitions, then parses each zone configuration for A records to audit for connectivity.

### Installation
The prefix option may vary depending on the system you are running.

```
$ git clone https://github.com/djtaylor/python-bind9-dns-audit
$ cd python-bind9-dns-audit
$ python setup.py install --prefix /usr/local
```

### Testing
Testing is done with `unittest` and `nose` for test collection in both Python 2 and 3.

```
$ python setup.py test
```

### Usage
The following is an example of basic usage to audit a BIND9 DNS server.

```
# This will dump a JSON report to stdout and use system SSH host keys to connect
$ bind9_dns_audit  --ssh-user myuser --zones-config /etc/bind/named.conf.local
$
# Prompt for SSH password if keys not available
$ bind9_dns_audit 192.168.3.10 --ssh-user myuser --ssh-passwd --zones-config /etc/bind/named.conf.local
```

##### Pretty Print
Use the `--pretty-print` parameter to format a report for the CLI. Default is the dump the JSON generated on `stdout`.

```
$ bind9_dns_audit 192.168.3.10 --ssh-user myuser --zones-config /etc/bind/named.conf.local --pretty-print
$ .....
Audit Complete: 192.168.3.10
----------------------------------------
> time elapsed: 15.7087161541

Forward Zone Report: firstdomain.com, 5 total records
> 5 records responded to ICMP/ping
> 0 records DID NOT response to ICMP/ping

Forward Zone Report: seconddomain.com, 13 total records
> 10 records responded to ICMP/ping
> 3 records DID NOT response to ICMP/ping

  deadserver1.seconddomain.com [192.168.3.50]
  deadserver2.seconddomain.com [192.168.3.55]
  deadserver3.seconddomain.com [192.168.3.76]

```

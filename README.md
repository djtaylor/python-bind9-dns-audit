[![Build Status](https://api.travis-ci.org/djtaylor/python-rancher2.png)](https://api.travis-ci.org/djtaylor/python-rancher2)

# BIND9 DNS Audit

This module deploys a command line script to audit a BIND9 server to look for DNS records that don't have any backing infrastructure and be deleted.

### Installation
The prefix option may vary depending on the system you are running.

```
$ git clone https://github.com/djtaylor/python-bind9-dns-audit
$ cd python-bind9-dns-audit
$ python setup.py install --prefix /usr/local
```
